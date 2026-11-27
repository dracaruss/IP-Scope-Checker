#!/usr/bin/env python3
"""
scopecheck.py : external pentest scope recon.

Feed it a file of IPs, CIDRs, IP ranges, hostnames and URLs (mixed is fine).
For every entry it works out who owns it, whether it is live, what is
listening, what the web service is, whether there is a login portal, and
whether the asset is really the client's or a third party (Microsoft, AWS,
Cloudflare, a SaaS vendor...). Third party assets are flagged red with a
short rules of engagement note.

Passive checks run first for every target (DNS, RDAP ownership, PTR,
optional Shodan InternetDB). Active checks (ping, TCP ports, HTTP, TLS)
run second, so --passive or --skip-red-probe can hold them back.

Uses ProjectDiscovery httpx/dnsx and gowitness when installed, and falls
back to built in checks when they are not.
"""

import argparse
import concurrent.futures as cf
import csv
import glob
import html
import ipaddress
import json
import os
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlparse

try:
    from rich import box
    from rich.console import Console
    from rich.panel import Panel
    from rich.progress import BarColumn, MofNCompleteColumn, Progress, TextColumn, TimeElapsedColumn
    from rich.table import Table
    from rich.text import Text
except ImportError:
    sys.exit("Missing dependency: pip install rich requests ipwhois dnspython cryptography")

try:
    import requests
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    requests = None

try:
    from ipwhois import IPWhois
except ImportError:
    IPWhois = None

try:
    import dns.resolver
    import dns.reversename
    import dns.exception
except ImportError:
    dns = None

try:
    from cryptography import x509
    from cryptography.x509.oid import ExtensionOID, NameOID
except ImportError:
    x509 = None

VERSION = "1.0"
console = Console(highlight=False)

DEFAULT_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
                 1433, 1723, 3306, 3389, 4443, 5060, 5432, 5900, 8000, 8080, 8443, 10443]
WEB_PORTS = {80, 443, 4443, 8000, 8008, 8080, 8443, 8888, 9443, 10443}
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/124.0 Safari/537.36")

# --------------------------------------------------------------------------
# Rules of engagement notes. Kept short on purpose. Always confirm against
# the provider's current policy and the client's written authorisation.
# --------------------------------------------------------------------------
NOTE_MS365 = ("Microsoft 365 portal shared by every Microsoft customer. Test only the client's tenant and "
              "accounts, never the service itself. No DoS.")
NOTE_AZURE = ("Microsoft Azure. No approval needed for the client's own resources. Scanning, fuzzing and brute forcing "
              "are fine at a sensible rate. Just no DoS.")
NOTE_MICROSOFT = "Microsoft address. Test only the client's own resources or tenant, not Microsoft's services. No DoS."
NOTE_AWS = ("AWS. No approval needed for common services like EC2, load balancers and CloudFront. Brute forcing is "
            "fine at a sensible rate, but no DoS or request flooding.")
NOTE_GCP = "Google Cloud. No approval needed for the client's own projects. Normal testing is fine, just no DoS."
NOTE_ORACLE = "Oracle Cloud. Oracle must be notified before testing, and Oracle SaaS cannot be tested at all."
NOTE_CDN = ("{name} CDN, shared with other customers. Test the client's site only, no DoS or heavy scanning. "
            "The client's real server sits behind it.")
NOTE_AKAMAI = "Akamai CDN. Akamai requires its own written permission before any testing."
NOTE_HOSTING = "{name} hosting. Normal testing is fine, just no DoS. If the IP is shared hosting, test only the client's site."
NOTE_SAAS = "{name} platform, owned by the vendor, not the client. Only test it if the vendor's testing policy allows it."
NOTE_MAIL = ("{name} email gateway, a shared vendor service. Do not attack it. Only check the client's mail settings, "
             "such as SPF and DMARC.")
NOTE_PRIVATE = "Private IP, not reachable from the internet. Probably a scoping error."
NOTE_NXDOMAIN = "Hostname does not resolve, so there is nothing to reach."
NOTE_TAKEOVER = ("Points at {target}, which no longer exists. Possible subdomain takeover: report it, but do not "
                 "claim it without approval.")

# Verdict per provider: blue means testable with caveats, red means do not test.
TIER_BY_KIND = {"cloud": "blue", "hosting": "blue", "cdn": "blue", "saas": "red", "mail": "red"}
TIER_OVERRIDE = {"m365": "blue", "akamai": "red"}


def P(key, name, kind, note, asns=(), org=None, suffixes=()):
    return dict(key=key, name=name, kind=kind, note=note, asns=set(asns),
                org=re.compile(org, re.I) if org else None, suffixes=tuple(suffixes))


# Order matters: specific SaaS suffixes first, then clouds, then CDNs, then hosting.
PROVIDERS = [
    P("m365", "Microsoft 365", "saas", NOTE_MS365, suffixes=(
        "microsoftonline.com", "office365.com", "outlook.com", "office.com", "office.net", "sharepoint.com",
        "onmicrosoft.com", "lync.com", "teams.microsoft.com", "protection.outlook.com", "mail.protection.outlook.com",
        "microsoftonline-p.com", "msauth.net", "msftauth.net", "live.com", "msappproxy.net")),
    P("azure", "Microsoft Azure", "cloud", NOTE_AZURE, suffixes=(
        "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "azurefd.net",
        "azureedge.net", "azure-api.net", "azurecontainer.io", "azurecontainerapps.io", "azurestaticapps.net",
        "blob.core.windows.net", "web.core.windows.net", "core.windows.net", "database.windows.net",
        "azure.com", "azurehdinsight.net", "servicebus.windows.net", "vault.azure.net")),
    P("aws", "Amazon Web Services", "cloud", NOTE_AWS,
      asns=(16509, 14618, 8987, 7224, 38895, 39111, 10124, 9059, 17493),
      org=r"\bamazon\b|\baws\b|amazon technologies|amazon\.com",
      suffixes=("amazonaws.com", "cloudfront.net", "awsglobalaccelerator.com", "elasticbeanstalk.com",
                "awsapps.com", "amplifyapp.com", "aws.amazon.com", "awsdns")),
    P("okta", "Okta", "saas", NOTE_SAAS, suffixes=("okta.com", "oktapreview.com", "okta-emea.com", "oktacdn.com")),
    P("salesforce", "Salesforce", "saas", NOTE_SAAS, asns=(14340,), org=r"salesforce",
      suffixes=("force.com", "salesforce.com", "salesforce-sites.com", "sfdc.net", "exacttarget.com", "my.site.com")),
    P("zscaler", "Zscaler", "saas", NOTE_SAAS, asns=(22616, 53813, 62044), org=r"zscaler",
      suffixes=("zscaler.net", "zscalertwo.net", "zscalerthree.net", "zscloud.net", "zscaler.com", "zpath.net")),
    P("shopify", "Shopify", "saas", NOTE_SAAS, org=r"shopify",
      suffixes=("myshopify.com", "shopify.com", "shopifycloud.com", "shopifycdn.com")),
    P("github", "GitHub", "saas", NOTE_SAAS, asns=(36459,), org=r"github",
      suffixes=("github.io", "githubusercontent.com", "github.com")),
    P("heroku", "Heroku", "saas", NOTE_SAAS, suffixes=("herokuapp.com", "herokudns.com", "herokussl.com")),
    P("netlify", "Netlify", "saas", NOTE_SAAS, suffixes=("netlify.app", "netlify.com", "netlifyglobalcdn.com")),
    P("vercel", "Vercel", "saas", NOTE_SAAS, org=r"vercel", suffixes=("vercel.app", "vercel-dns.com", "now.sh")),
    P("wpengine", "WP Engine", "saas", NOTE_SAAS, suffixes=("wpengine.com", "wpenginepowered.com")),
    P("zendesk", "Zendesk", "saas", NOTE_SAAS, suffixes=("zendesk.com", "zdassets.com")),
    P("hubspot", "HubSpot", "saas", NOTE_SAAS, suffixes=("hubspot.net", "hs-sites.com", "hubspot.com", "hscoscdn10.net")),
    P("squarespace", "Squarespace", "saas", NOTE_SAAS, asns=(53831,), org=r"squarespace",
      suffixes=("squarespace.com", "sqsp.net")),
    P("wix", "Wix", "saas", NOTE_SAAS, asns=(58182,), org=r"\bwix\b", suffixes=("wixdns.net", "wixsite.com", "wix.com")),
    P("atlassian", "Atlassian Cloud", "saas", NOTE_SAAS, suffixes=("atlassian.net", "atlassian.com", "statuspage.io")),
    P("mimecast", "Mimecast", "mail", NOTE_MAIL, asns=(30031,), org=r"mimecast", suffixes=("mimecast.com", "mimecast.co.za")),
    P("proofpoint", "Proofpoint", "mail", NOTE_MAIL, asns=(22843, 26211, 52129), org=r"proofpoint",
      suffixes=("pphosted.com", "ppe-hosted.com", "proofpoint.com")),
    P("barracuda", "Barracuda", "mail", NOTE_MAIL, asns=(15324,), org=r"barracuda",
      suffixes=("barracudanetworks.com", "cudasvc.com")),
    P("gcp", "Google Cloud", "cloud", NOTE_GCP, asns=(15169, 396982, 19527, 36040, 43515, 139070, 139190),
      org=r"\bgoogle\b", suffixes=("googleusercontent.com", "appspot.com", "googlehosted.com", "run.app", "web.app",
                                   "firebaseapp.com", "1e100.net", "googleapis.com", "cloudfunctions.net")),
    P("oracle", "Oracle Cloud", "cloud", NOTE_ORACLE, asns=(31898, 792, 793, 794, 7160, 43898, 20054),
      org=r"\boracle\b", suffixes=("oraclecloud.com", "oraclecloudapps.com", "oraclevcn.com")),
    P("cloudflare", "Cloudflare", "cdn", NOTE_CDN, asns=(13335, 209242), org=r"cloudflare",
      suffixes=("cloudflare.net", "cloudflare.com", "pages.dev", "workers.dev", "cloudflaressl.com")),
    P("linode", "Akamai Cloud (Linode)", "hosting", NOTE_HOSTING, asns=(63949,), org=r"linode",
      suffixes=("linode.com", "linodeusercontent.com", "ip.linodeusercontent.com")),
    P("akamai", "Akamai", "cdn", NOTE_AKAMAI,
      asns=(20940, 16625, 16702, 17204, 18680, 18717, 20189, 21342, 21357, 21399, 23454, 23455, 24319, 26008,
            30675, 31107, 31108, 31109, 31110, 31377, 33047, 33905, 34164, 34850, 35204, 35993, 35994, 36183,
            39836, 43639, 55409, 55770),
      org=r"akamai", suffixes=("akamaiedge.net", "akamai.net", "akamaitechnologies.com", "edgekey.net",
                               "edgesuite.net", "akamaized.net", "akamaihd.net")),
    P("fastly", "Fastly", "cdn", NOTE_CDN, asns=(54113,), org=r"fastly", suffixes=("fastly.net", "fastlylb.net")),
    P("imperva", "Imperva (Incapsula)", "cdn", NOTE_CDN, asns=(19551,), org=r"incapsula|imperva",
      suffixes=("incapdns.net", "impervadns.net", "incapsula.com")),
    P("sucuri", "Sucuri", "cdn", NOTE_CDN, asns=(30148,), org=r"sucuri", suffixes=("sucuri.net",)),
    # Microsoft by ASN/org only, when we cannot tell Azure from M365.
    P("microsoft", "Microsoft", "cloud", NOTE_MICROSOFT,
      asns=(8075, 8068, 8069, 8070, 8071, 8072, 8073, 8074, 12076, 3598, 6584, 23468, 35106, 45139, 58862,
            59067, 200517), org=r"\bmicrosoft\b", suffixes=("msft.net", "msedge.net", "microsoft.com")),
    P("digitalocean", "DigitalOcean", "hosting", NOTE_HOSTING, asns=(14061,), org=r"digitalocean",
      suffixes=("digitaloceanspaces.com", "ondigitalocean.app")),
    P("alibaba", "Alibaba Cloud", "hosting", NOTE_HOSTING, asns=(37963, 45102, 24429, 45103, 45104),
      org=r"alibaba|aliyun", suffixes=("aliyuncs.com", "alibabacloud.com")),
    P("liquidweb", "Liquid Web", "hosting", NOTE_HOSTING, asns=(32244, 53824, 59253), org=r"liquid ?web"),
    P("plusserver", "PlusServer", "hosting", NOTE_HOSTING, asns=(61157,), org=r"plusserver|plus ?server"),
    P("ovh", "OVHcloud", "hosting", NOTE_HOSTING, asns=(16276, 35540), org=r"\bovh\b"),
    P("hetzner", "Hetzner", "hosting", NOTE_HOSTING, asns=(24940, 213230), org=r"hetzner"),
    P("vultr", "Vultr", "hosting", NOTE_HOSTING, asns=(20473,), org=r"vultr|choopa", suffixes=("vultrusercontent.com",)),
    P("godaddy", "GoDaddy", "hosting", NOTE_HOSTING, asns=(26496, 398101, 44273), org=r"godaddy",
      suffixes=("secureserver.net", "godaddysites.com")),
    P("rackspace", "Rackspace", "hosting", NOTE_HOSTING, asns=(19994, 27357, 33070, 15395), org=r"rackspace"),
    P("ionos", "IONOS", "hosting", NOTE_HOSTING, asns=(8560,), org=r"ionos|1&1"),
    P("hostinger", "Hostinger", "hosting", NOTE_HOSTING, asns=(47583,), org=r"hostinger"),
]

TAKEOVER_SUFFIXES = (
    "azurewebsites.net", "cloudapp.net", "cloudapp.azure.com", "trafficmanager.net", "blob.core.windows.net",
    "azureedge.net", "azurefd.net", "azurestaticapps.net", "s3.amazonaws.com", "s3-website", "elasticbeanstalk.com",
    "cloudfront.net", "herokuapp.com", "herokudns.com", "github.io", "netlify.app", "myshopify.com", "zendesk.com",
    "wpengine.com", "pantheonsite.io", "surge.sh", "ghost.io", "fastly.net", "readme.io", "helpscoutdocs.com",
    "unbouncepages.com", "statuspage.io", "bitbucket.io", "webflow.io", "agilecrm.com", "teamwork.com",
)

# --------------------------------------------------------------------------
# Login portal signatures: (label, regex over body/headers/final URL)
# --------------------------------------------------------------------------
LOGIN_SIGS = [
    ("Outlook Web App", r"outlook web app|/owa/auth|owa/auth/logon\.aspx|x-owa-version"),
    ("Exchange ECP", r"/ecp/|exchange admin center"),
    ("ADFS", r"/adfs/ls|/adfs/portal|adfs/services"),
    ("Microsoft Entra SSO", r"login\.microsoftonline\.com|login\.windows\.net"),
    ("RD Web Access", r"/rdweb/|rd web access|ts web access|remote desktop web"),
    ("Citrix Gateway", r"citrix gateway|netscaler|/vpn/index\.html|/logon/logonpoint|citrix receiver|storefront"),
    ("FortiGate SSL VPN", r"/remote/login|fgt_lang|fortigate|ftnt-fortinet|fortinet"),
    ("GlobalProtect", r"global-protect|globalprotect"),
    ("Ivanti/Pulse Connect", r"/dana-na/|pulse secure|ivanti connect secure"),
    ("Cisco AnyConnect", r"/\+cscoe\+/|webvpn|anyconnect"),
    ("SonicWall", r"sonicwall|/sslvpn|sonicui"),
    ("F5 BIG-IP", r"/my\.policy|f5 networks|big-ip|/tmui/"),
    ("Check Point VPN", r"check point ssl network extender|/sslvpn/login|checkpoint"),
    ("WatchGuard", r"watchguard"),
    ("VMware Horizon", r"vmware horizon|/portal/webclient"),
    ("VMware vSphere", r"vsphere|id_vc_welcome|vmware esxi"),
    ("Okta SSO", r"\.okta\.com|okta-signin"),
    ("WordPress login", r"wp-login\.php|/wp-admin"),
    ("Jenkins", r"jenkins.*(j_acegi|login)|x-jenkins"),
    ("Grafana", r"grafana"),
    ("GitLab", r"gitlab.*sign_in|users/sign_in"),
    ("Atlassian login", r"login\.jsp|atlassian"),
    ("Tomcat Manager", r"/manager/html|apache tomcat"),
    ("phpMyAdmin", r"phpmyadmin"),
    ("cPanel/WHM", r"cpanel|whm login|cpsess"),
    ("Plesk", r"plesk"),
    ("Webmin", r"webmin"),
    ("SharePoint", r"sharepoint|_layouts/15"),
    ("Zimbra", r"zimbra"),
    ("Roundcube", r"roundcube"),
    ("Kibana", r"kbn-name|kibana"),
]
LOGIN_SIGS = [(n, re.compile(r, re.I)) for n, r in LOGIN_SIGS]
PASSWORD_RE = re.compile(r"<input[^>]+type\s*=\s*[\"']?password", re.I)
TITLE_RE = re.compile(r"<title[^>]*>(.*?)</title>", re.I | re.S)
HOST_RE = re.compile(r"^(?=.{1,253}$)([a-z0-9_]([a-z0-9_-]{0,61}[a-z0-9_])?\.)+[a-z]{2,63}$", re.I)


# --------------------------------------------------------------------------
# Data model
# --------------------------------------------------------------------------
@dataclass
class Target:
    raw: str
    kind: str                     # ip | host | url
    host: str
    url: str = ""
    extra_ports: list = field(default_factory=list)
    ips: list = field(default_factory=list)
    cnames: list = field(default_factory=list)
    resolves: bool = True
    ptr: dict = field(default_factory=dict)
    fcrdns: dict = field(default_factory=dict)
    owners: dict = field(default_factory=dict)
    private: bool = False
    tier: str = "green"           # green testable | blue caveats | red leave alone | grey unreachable
    provider: str = ""
    provider_kind: str = ""
    note: str = ""
    client_domain_hit: str = ""
    ping: bool = False
    rst_seen: bool = False
    live: str = "not checked"
    open_ports: list = field(default_factory=list)
    web: list = field(default_factory=list)
    tls: list = field(default_factory=list)
    logins: list = field(default_factory=list)
    shodan: dict = field(default_factory=dict)
    takeover: str = ""
    expected_ip: str = ""
    base_note: str = ""
    errors: list = field(default_factory=list)

    @property
    def primary_ip(self):
        return self.ips[0] if self.ips else ""

    @property
    def is_name(self):
        return not is_ip(self.host)

    def owner_label(self):
        o = self.owners.get(self.primary_ip) or {}
        org = o.get("org") or ("" if (self.private or not self.ips) else "lookup failed")
        if self.provider and (org in ("", "lookup failed") or is_handle(org) or (org.isupper() and " " not in org)):
            org = self.provider
        asn = f"AS{o['asn']}" if o.get("asn") else ""
        return org, asn, o.get("country", "")

    def tls_names(self):
        names = []
        for c in self.tls:
            for n in [c.get("cn")] + c.get("sans", []):
                if n and n not in names:
                    names.append(n)
        return names


# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------
def is_ip(s):
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def is_private(ip):
    a = ipaddress.ip_address(ip)
    return not a.is_global


def norm(s):
    return re.sub(r"[^a-z0-9]", "", (s or "").lower())


def under(name, suffixes):
    name = (name or "").lower().rstrip(".").lstrip("*.")
    for s in suffixes:
        s = s.lower()
        if name == s or name.endswith("." + s):
            return s
        if s in ("s3-website", "awsdns") and s in name:
            return s
    return None


def find_tool(names, must_contain=None):
    for n in names:
        p = shutil.which(n) or (os.path.expanduser(f"~/go/bin/{n}") if os.path.exists(os.path.expanduser(f"~/go/bin/{n}")) else None)
        if not p:
            continue
        if must_contain:
            try:
                out = subprocess.run([p, "-version"], capture_output=True, text=True, timeout=10)
                if must_contain not in (out.stdout + out.stderr).lower():
                    continue
            except Exception:
                continue
        return p
    return None


# --------------------------------------------------------------------------
# Input parsing
# --------------------------------------------------------------------------
def parse_targets(path, max_hosts):
    targets, seen, bad = [], {}, []
    with open(path, encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.split("#", 1)[0].strip()
            if not line:
                continue
            parent = None      # last hostname or URL on this line
            for raw in re.split(r"[\s,;]+", line):
                bracketed = raw[:1] in "([{<" and raw[-1:] in ")]}>"
                tok = raw.strip("()[]{}<>\"'")
                if not tok:
                    continue
                # "host.example.com (1.2.3.4)" : the bracketed IP is what the scope expects the host to resolve to
                if bracketed and parent is not None and is_ip(tok):
                    parent.expected_ip = tok
                    continue
                try:
                    new = parse_token(tok, max_hosts)
                except ValueError as e:
                    bad.append(f"{raw}: {e}")
                    continue
                kept = []
                for t in new:
                    key = (t.kind, t.host, t.url, tuple(t.extra_ports))
                    if key not in seen:
                        seen[key] = t
                        targets.append(t)
                    kept.append(seen[key])
                parent = kept[0] if len(kept) == 1 and not is_ip(kept[0].host) else None
    return targets, bad


def parse_token(tok, max_hosts):
    if "://" in tok:
        u = urlparse(tok)
        if not u.hostname:
            raise ValueError("URL has no host")
        h = u.hostname.lower()
        return [Target(raw=tok, kind="url", host=h, url=tok, ips=[h] if is_ip(h) else [])]
    if is_ip(tok):
        return [Target(raw=tok, kind="ip", host=str(ipaddress.ip_address(tok)), ips=[str(ipaddress.ip_address(tok))])]
    if "/" in tok:
        net = ipaddress.ip_network(tok, strict=False)
        hosts = list(net.hosts()) if net.num_addresses > 2 else list(net)
        if len(hosts) > max_hosts:
            raise ValueError(f"{len(hosts)} hosts exceeds --max-hosts {max_hosts}")
        return [Target(raw=tok, kind="ip", host=str(h), ips=[str(h)]) for h in hosts]
    m = re.match(r"^(\d+\.\d+\.\d+\.\d+)-(\d+(?:\.\d+\.\d+\.\d+)?)$", tok)
    if m:
        start = ipaddress.ip_address(m.group(1))
        end_s = m.group(2)
        end = ipaddress.ip_address(end_s if "." in end_s else ".".join(m.group(1).split(".")[:3] + [end_s]))
        n = int(end) - int(start) + 1
        if n <= 0 or n > max_hosts:
            raise ValueError("bad or oversized range")
        return [Target(raw=tok, kind="ip", host=str(start + i), ips=[str(start + i)]) for i in range(n)]
    if tok.count(":") == 1:
        h, p = tok.rsplit(":", 1)
        if p.isdigit():
            t = parse_token(h, max_hosts)[0]
            t.raw, t.extra_ports = tok, [int(p)]
            return [t]
    if HOST_RE.match(tok.rstrip(".")):
        return [Target(raw=tok, kind="host", host=tok.rstrip(".").lower())]
    raise ValueError("not an IP, range, hostname or URL")


# --------------------------------------------------------------------------
# DNS
# --------------------------------------------------------------------------
class DNS:
    def __init__(self, timeout):
        self.r = None
        if dns:
            self.r = dns.resolver.Resolver()
            self.r.lifetime = timeout
            self.r.timeout = timeout

    def resolve(self, host):
        """Return (ips, cnames, nxdomain)."""
        cnames, ips, nx = [], [], False
        if self.r:
            name = host
            for _ in range(10):
                try:
                    ans = self.r.resolve(name, "CNAME")
                    nxt = str(ans[0].target).rstrip(".").lower()
                    cnames.append(nxt)
                    name = nxt
                except Exception:
                    break
            for rtype in ("A", "AAAA"):
                try:
                    ips += [r.to_text() for r in self.r.resolve(host, rtype)]
                except dns.resolver.NXDOMAIN:
                    nx = True
                except Exception:
                    pass
        else:
            try:
                ips = sorted({i[4][0] for i in socket.getaddrinfo(host, None)})
            except socket.gaierror:
                nx = True
        return ips, cnames, nx and not ips

    def name_exists(self, name):
        if not self.r:
            try:
                socket.getaddrinfo(name, None)
                return True
            except socket.gaierror:
                return False
        for rtype in ("A", "AAAA", "CNAME"):
            try:
                self.r.resolve(name, rtype)
                return True
            except dns.resolver.NXDOMAIN:
                return False
            except Exception:
                continue
        return False

    def ptr(self, ip):
        try:
            if self.r:
                return str(self.r.resolve_address(ip)[0]).rstrip(".").lower()
            return socket.gethostbyaddr(ip)[0].lower()
        except Exception:
            return ""

    def forward_has(self, name, ip):
        ips, _, _ = self.resolve(name)
        return ip in ips


def dnsx_prefetch(dnsx, hosts, threads):
    out = {}
    if not dnsx or not hosts:
        return out
    with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
        f.write("\n".join(hosts))
        fn = f.name
    try:
        p = subprocess.run([dnsx, "-l", fn, "-a", "-aaaa", "-cname", "-json", "-silent", "-t", str(threads)],
                           capture_output=True, text=True, timeout=600)
        for line in p.stdout.splitlines():
            try:
                j = json.loads(line)
            except ValueError:
                continue
            h = (j.get("host") or "").lower()
            out[h] = ((j.get("a") or []) + (j.get("aaaa") or []), [c.lower().rstrip(".") for c in j.get("cname") or []])
    except Exception:
        pass
    finally:
        os.unlink(fn)
    return out


# --------------------------------------------------------------------------
# Ownership (RDAP + ASN)
# --------------------------------------------------------------------------
class Owners:
    def __init__(self, timeout):
        self.cache, self.nets = {}, []
        self.lock = threading.Lock()
        self.sem = threading.Semaphore(4)       # be polite to RIRs
        self.timeout = timeout

    def lookup(self, ip):
        with self.lock:
            if ip in self.cache:
                return self.cache[ip]
            a = ipaddress.ip_address(ip)
            for net, res in self.nets:
                if a.version == net.version and a in net:
                    return res
        with self.sem:
            res = self._ipwhois(ip) if IPWhois else None
            if not res:
                res = self._rdap(ip)
        with self.lock:
            self.cache[ip] = res
            for c in (res.get("cidr") or "").split(","):
                try:
                    self.nets.append((ipaddress.ip_network(c.strip(), strict=False), res))
                except ValueError:
                    pass
        return res

    def _ipwhois(self, ip):
        try:
            r = IPWhois(ip, timeout=self.timeout).lookup_rdap(depth=1, retry_count=2)
        except Exception:
            return None
        net = r.get("network") or {}
        names, reg = [], []
        for obj in (r.get("objects") or {}).values():
            c = (obj or {}).get("contact") or {}
            if c.get("name") and c["name"] not in names:
                names.append(c["name"])
                if "registrant" in (obj.get("roles") or []):
                    reg.append(c["name"])
        org = pick_org(reg, r.get("asn_description") or "", names, net.get("name") or "")
        return dict(org=org, netname=net.get("name") or "", entities=names, cidr=net.get("cidr") or r.get("asn_cidr") or "",
                    asn=(r.get("asn") or "").split(" ")[0], asn_name=r.get("asn_description") or "",
                    country=net.get("country") or r.get("asn_country_code") or "")

    def _rdap(self, ip):
        res = dict(org="", netname="", entities=[], cidr="", asn="", asn_name="", country="")
        reg = []
        if requests:
            try:
                j = requests.get(f"https://rdap.org/ip/{ip}", timeout=self.timeout,
                                 headers={"Accept": "application/rdap+json"}).json()
                res["netname"] = j.get("name") or ""
                res["country"] = j.get("country") or ""
                cidrs = [f"{c.get('v4prefix') or c.get('v6prefix')}/{c.get('length')}" for c in j.get("cidr0_cidrs") or []]
                res["cidr"] = ",".join(cidrs)

                def walk(ents):
                    for e in ents or []:
                        for item in (e.get("vcardArray") or [None, []])[1]:
                            if item and item[0] == "fn" and item[3] not in res["entities"]:
                                res["entities"].append(item[3])
                                if "registrant" in (e.get("roles") or []):
                                    reg.append(item[3])
                        walk(e.get("entities"))
                walk(j.get("entities"))
            except Exception:
                pass
        if dns:
            try:
                a = ipaddress.ip_address(ip)
                q = ".".join(reversed(ip.split("."))) + ".origin.asn.cymru.com" if a.version == 4 else \
                    ".".join(reversed(a.exploded.replace(":", ""))) + ".origin6.asn.cymru.com"
                txt = str(dns.resolver.resolve(q, "TXT")[0]).strip('"').split("|")
                res["asn"] = txt[0].strip().split()[0]
                res["cidr"] = res["cidr"] or txt[1].strip()
                res["country"] = res["country"] or txt[2].strip()
                txt2 = str(dns.resolver.resolve(f"AS{res['asn']}.asn.cymru.com", "TXT")[0]).strip('"').split("|")
                res["asn_name"] = txt2[-1].strip()
            except Exception:
                pass
        res["org"] = pick_org(reg, res["asn_name"], res["entities"], res["netname"])
        return res


HANDLE_RE = re.compile(r"-MNT\b|^MNT-|^RIPE-NCC|^APNIC|^AFRINIC|^LACNIC|^ARIN\b", re.I)


def is_handle(n):
    """Registry handles such as HOS-GUN, MNT-PlusServer or RIPE-NCC-HM-MNT, not real organisation names."""
    n = (n or "").strip()
    return bool(HANDLE_RE.search(n) or re.fullmatch(r"[A-Za-z0-9]+(?:[-_][A-Za-z0-9]+)+", n))


def clean_asn_name(s):
    """'SKYNET-AS Proximus NV, BE' -> 'Proximus NV'; 'VTX - VTX Services SA, CH' -> 'VTX Services SA'."""
    s = re.sub(r",\s*[A-Z]{2}$", "", (s or "").strip())
    parts = s.split(" ", 1)
    if len(parts) == 2 and re.fullmatch(r"[A-Z0-9_.-]+", parts[0]):
        s = parts[1]
    s = s.strip().lstrip("-:| ").strip()
    if " " not in s:
        s = re.sub(r"[-_]AS\d*$", "", s, flags=re.I)     # HETZNER-AS -> HETZNER
    return s


def pick_org(registrant, asn_name, entities, netname):
    """Prefer a real organisation name over registry handles and personal contacts."""
    for n in registrant:
        if not is_handle(n):
            return n
    if asn_name and clean_asn_name(asn_name):
        return clean_asn_name(asn_name)
    for n in entities:
        if not is_handle(n):
            return n
    return netname


def shodan_internetdb(ip, timeout):
    if not requests:
        return {}
    try:
        r = requests.get(f"https://internetdb.shodan.io/{ip}", timeout=timeout)
        if r.status_code == 200:
            j = r.json()
            return dict(ports=j.get("ports", []), vulns=j.get("vulns", []), tags=j.get("tags", []),
                        hostnames=j.get("hostnames", []))
    except Exception:
        pass
    return {}


# --------------------------------------------------------------------------
# Classification
# --------------------------------------------------------------------------
def match_provider(t, use_tls=False):
    names = [t.host] + t.cnames + list(t.ptr.values())
    if use_tls:
        names += [c.get("cn") for c in t.tls if c.get("cn")]
    for prov in PROVIDERS:
        for n in names:
            if is_ip(n or ""):
                continue
            if prov["suffixes"] and under(n, prov["suffixes"]):
                return prov
    for prov in PROVIDERS:
        for o in t.owners.values():
            try:
                asn = int(o.get("asn") or 0)
            except ValueError:
                asn = 0
            if asn and asn in prov["asns"]:
                return prov
    for prov in PROVIDERS:
        if not prov["org"]:
            continue
        for o in t.owners.values():
            blob = " ".join([o.get("org", ""), o.get("netname", ""), o.get("asn_name", "")] + o.get("entities", []))
            if prov["org"].search(blob):
                return prov
    return None


def classify(t, clients, domains, final=False):
    """
    green = testable (client owned, or a leased static IP)
    blue  = testable with caveats (cloud, hosting, CDN, Microsoft 365)
    red   = live but leave alone (vendor SaaS, email gateways, Akamai)
    grey  = not reachable (no DNS, private IP)
    A matched provider always decides the verdict, even when the block is registered to the client,
    because the provider's rules still apply.
    """
    evidence = [t.host] + t.cnames + list(t.ptr.values()) + t.tls_names()
    t.client_domain_hit = ""
    for n in evidence:
        if n and not is_ip(n) and domains and under(n, domains):
            t.client_domain_hit = n
            break
    t.provider, t.provider_kind = "", ""

    if not t.resolves:
        t.tier = "grey"
        t.base_note = NOTE_TAKEOVER.format(target=t.cnames[-1]) if t.takeover else NOTE_NXDOMAIN
        t.note = t.base_note + (f" Your scope lists it as {t.expected_ip}." if t.expected_ip else "")
        return
    if t.ips and all(is_private(i) for i in t.ips):
        t.private, t.tier = True, "grey"
        t.base_note = t.note = NOTE_PRIVATE
        return

    client_reg = False
    if clients:
        for o in t.owners.values():
            blob = norm(" ".join([o.get("org", ""), o.get("netname", ""), o.get("asn_name", "")] + o.get("entities", [])))
            if any(c and c in blob for c in clients):
                client_reg = True
                break

    prov = match_provider(t, use_tls=final)
    extra = []
    if prov:
        t.tier = TIER_OVERRIDE.get(prov["key"]) or TIER_BY_KIND[prov["kind"]]
        t.provider, t.provider_kind = prov["name"], prov["kind"]
        t.base_note = prov["note"].format(name=prov["name"])
        if client_reg:
            extra.append("The IP block is registered to the client.")
        if t.client_domain_hit and t.tier == "blue":
            extra.append(f"Serves {t.client_domain_hit}, so it is the client's own resource.")
    else:
        org = t.owner_label()[0]
        t.tier = "green"
        if client_reg:
            t.base_note = "Registered to the client."
        elif not t.owners or not org or org == "lookup failed":
            t.base_note = "Owner lookup failed, but nothing points to a third party."
        else:
            t.base_note = f"IP leased from {org}."
        if t.client_domain_hit:
            extra.append(f"Serves {t.client_domain_hit}.")
        elif t.is_name and domains:
            extra.append("Not under the client domains you listed.")
    if t.expected_ip and t.ips and t.expected_ip not in t.ips:
        extra.append(f"WARNING: your scope lists {t.expected_ip}, but it resolves to {', '.join(t.ips[:3])}.")
    t.note = " ".join([t.base_note] + extra)


# --------------------------------------------------------------------------
# Active checks
# --------------------------------------------------------------------------
def do_ping(ip, timeout):
    exe = shutil.which("ping")
    if not exe:
        return False
    cmd = [exe, "-c", "1", "-W", str(max(1, int(timeout)))]
    if ipaddress.ip_address(ip).version == 6:
        cmd.insert(1, "-6")
    try:
        return subprocess.run(cmd + [ip], capture_output=True, timeout=timeout + 2).returncode == 0
    except Exception:
        return False


def scan_ports(ip, ports, timeout):
    opened, rst = [], False

    def one(p):
        try:
            with socket.create_connection((ip, p), timeout=timeout):
                return p, "open"
        except ConnectionRefusedError:
            return p, "rst"
        except Exception:
            return p, "none"
    with cf.ThreadPoolExecutor(max_workers=min(32, len(ports))) as ex:
        for p, st in ex.map(one, ports):
            if st == "open":
                opened.append(p)
            elif st == "rst":
                rst = True
    return sorted(opened), rst


def tls_ok(host, ip, port, timeout):
    ctx = ssl.create_default_context()
    ctx.check_hostname, ctx.verify_mode = False, ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=None if is_ip(host) else host) as ss:
                return ss.getpeercert(binary_form=True)
    except Exception:
        return None


def parse_cert(der, port):
    info = dict(port=port, cn="", sans=[], issuer="", not_after="", expired=False, self_signed=False)
    if not der or not x509:
        return info
    try:
        c = x509.load_der_x509_certificate(der)
        cn = c.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
        info["cn"] = cn[0].value.lower() if cn else ""
        try:
            san = c.extensions.get_extension_for_oid(ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
            info["sans"] = [n.lower() for n in san.get_values_for_type(x509.DNSName)][:50]
        except Exception:
            pass
        io = c.issuer.get_attributes_for_oid(NameOID.ORGANIZATION_NAME) or c.issuer.get_attributes_for_oid(NameOID.COMMON_NAME)
        info["issuer"] = io[0].value if io else ""
        na = getattr(c, "not_valid_after_utc", None) or c.not_valid_after.replace(tzinfo=timezone.utc)
        info["not_after"] = na.strftime("%Y-%m-%d")
        info["expired"] = na < datetime.now(timezone.utc)
        info["self_signed"] = c.issuer == c.subject
    except Exception:
        pass
    return info


def fetch(url, timeout):
    res = dict(url=url, status=None, title="", server="", final_url="", length=0, logins=[], auth="", tech=[], error="")
    if not requests:
        res["error"] = "requests not installed"
        return res
    try:
        r = requests.get(url, timeout=timeout, verify=False, allow_redirects=True, stream=True,
                         headers={"User-Agent": UA, "Accept": "text/html,*/*"})
        body = r.raw.read(512 * 1024, decode_content=True) or b""
        r.close()
        text = body.decode(r.encoding or "utf-8", errors="ignore")
        res["status"], res["final_url"] = r.status_code, r.url
        res["server"] = r.headers.get("Server", "")
        res["length"] = len(body)
        m = TITLE_RE.search(text)
        if m:
            res["title"] = re.sub(r"\s+", " ", html.unescape(m.group(1))).strip()[:120]
        hdrs = " ".join(f"{k}: {v}" for k, v in r.headers.items())
        chain = " ".join([h.headers.get("Location", "") for h in r.history] + [r.url])
        blob = f"{text}\n{hdrs}\n{chain}"
        hits = [name for name, rx in LOGIN_SIGS if rx.search(blob)]
        if PASSWORD_RE.search(text) and not hits:
            hits.append("Login form")
        wa = r.headers.get("WWW-Authenticate", "")
        if r.status_code == 401 and wa:
            scheme = wa.split()[0]
            res["auth"] = scheme
            hits.append(f"HTTP {scheme} auth" + (" (NTLM exposed)" if "ntlm" in wa.lower() or "negotiate" in wa.lower() else ""))
        res["logins"] = hits
    except requests.exceptions.SSLError as e:
        res["error"] = "TLS error"
    except requests.exceptions.ConnectionError:
        res["error"] = "connection failed"
    except requests.exceptions.Timeout:
        res["error"] = "timeout"
    except Exception as e:
        res["error"] = type(e).__name__
    return res


# --------------------------------------------------------------------------
# Pipeline
# --------------------------------------------------------------------------
class Runner:
    def __init__(self, args):
        self.a = args
        self.clients = [norm(c) for c in args.client if norm(c)]
        self.domains = [d.lower().strip(".") for d in args.domain]
        self.dns = DNS(args.timeout)
        self.owners = Owners(max(5, args.timeout * 2))
        self.ports = sorted(set(args.ports))
        self.ext = not args.no_external_tools
        self.httpx = find_tool(["httpx-toolkit", "httpx"], must_contain="projectdiscovery") if self.ext else None
        self.dnsx = find_tool(["dnsx"]) if self.ext else None
        self.prefetched = {}

    # phase 1: passive
    def passive(self, t):
        if t.is_name:
            if t.host in self.prefetched and self.prefetched[t.host][0]:
                t.ips, t.cnames = self.prefetched[t.host]
            else:
                t.ips, t.cnames, _ = self.dns.resolve(t.host)
            if not t.ips:
                t.resolves = False
                if t.cnames and under(t.cnames[-1], TAKEOVER_SUFFIXES) and not self.dns.name_exists(t.cnames[-1]):
                    t.takeover = t.cnames[-1]
        for ip in t.ips[:4]:
            if is_private(ip):
                continue
            t.owners[ip] = self.owners.lookup(ip)
            p = self.dns.ptr(ip)
            if p:
                t.ptr[ip] = p
                t.fcrdns[ip] = self.dns.forward_has(p, ip)
        if self.a.shodan and t.primary_ip and not is_private(t.primary_ip):
            t.shodan = shodan_internetdb(t.primary_ip, self.a.timeout * 2)
        classify(t, self.clients, self.domains)

    # phase 2: active
    def active(self, t):
        if not t.ips:
            return
        ip = t.primary_ip
        t.ping = do_ping(ip, self.a.timeout)
        ports = sorted(set(self.ports + t.extra_ports))
        if t.kind == "url":
            u = urlparse(t.url)
            ports = sorted(set(ports + [u.port or (443 if u.scheme == "https" else 80)]))
        t.open_ports, t.rst_seen = scan_ports(ip, ports, self.a.timeout)
        t.live = "live" if (t.open_ports or t.ping or t.rst_seen) else "no response"

        urls = []
        if t.kind == "url":
            urls.append(t.url)
        for p in t.open_ports:
            if p in WEB_PORTS or p in t.extra_ports:
                der = tls_ok(t.host, ip, p, self.a.timeout)
                scheme = "https" if der else "http"
                if der:
                    t.tls.append(parse_cert(der, p))
                default = (scheme == "https" and p == 443) or (scheme == "http" and p == 80)
                u = f"{scheme}://{t.host if not ':' in t.host else '[' + t.host + ']'}" + ("" if default else f":{p}") + "/"
                if not any(x.rstrip("/") == u.rstrip("/") for x in urls):
                    urls.append(u)
        if t.kind == "url" and not t.tls and t.url.startswith("https"):
            u = urlparse(t.url)
            der = tls_ok(t.host, ip, u.port or 443, self.a.timeout)
            if der:
                t.tls.append(parse_cert(der, u.port or 443))
        for u in urls:
            w = fetch(u, self.a.timeout * 3)
            t.web.append(w)
            for l in w["logins"]:
                if l not in t.logins:
                    t.logins.append(l)
        classify(t, self.clients, self.domains, final=True)

    def httpx_enrich(self, targets):
        if not self.httpx:
            return
        idx = {}
        for t in targets:
            for w in t.web:
                if w["status"] is not None:
                    idx[w["url"].rstrip("/")] = w
        if not idx:
            return
        with tempfile.NamedTemporaryFile("w", delete=False, suffix=".txt") as f:
            f.write("\n".join(idx))
            fn = f.name
        try:
            p = subprocess.run([self.httpx, "-l", fn, "-json", "-silent", "-title", "-status-code", "-web-server",
                                "-tech-detect", "-follow-redirects", "-no-color", "-timeout", str(self.a.timeout * 3),
                                "-threads", str(self.a.threads)], capture_output=True, text=True, timeout=1800)
            for line in p.stdout.splitlines():
                try:
                    j = json.loads(line)
                except ValueError:
                    continue
                key = (j.get("input") or j.get("url") or "").rstrip("/")
                w = idx.get(key) or idx.get((j.get("url") or "").rstrip("/"))
                if w is not None:
                    w["tech"] = j.get("tech") or []
                    w["title"] = w["title"] or j.get("title", "")
                    w["server"] = w["server"] or j.get("webserver", "")
        except Exception:
            pass
        finally:
            os.unlink(fn)

    def screenshots(self, targets, outdir, progress):
        shot_dir = os.path.join(outdir, "screenshots")
        os.makedirs(shot_dir, exist_ok=True)
        gw = find_tool(["gowitness"]) if self.ext else None
        gw_v3 = False
        if gw:
            try:
                v = subprocess.run([gw, "version"], capture_output=True, text=True, timeout=10)
                gw_v3 = bool(re.search(r"\b3\.\d", v.stdout + v.stderr))
            except Exception:
                pass
        chrome = None
        for c in ("chromium", "chromium-browser", "google-chrome", "google-chrome-stable"):
            chrome = shutil.which(c)
            if chrome:
                break
        if not gw and not chrome:
            console.print("[yellow]Screenshots skipped: neither gowitness nor Chrome/Chromium was found.[/]")
            return
        jobs = [w for t in targets for w in t.web if w["status"] is not None]
        task = progress.add_task("Screenshots", total=len(jobs))

        def shoot(w):
            name = re.sub(r"[^A-Za-z0-9]+", "_", w["url"]).strip("_")[:120] + ".png"
            dest = os.path.join(shot_dir, name)
            if gw:
                tmp = tempfile.mkdtemp()
                cmd = ([gw, "scan", "single", "-u", w["url"], "-s", tmp] if gw_v3 else
                       [gw, "single", "-P", tmp, w["url"]])
                try:
                    subprocess.run(cmd, capture_output=True, timeout=60)
                    imgs = [f for f in glob.glob(os.path.join(tmp, "**", "*"), recursive=True)
                            if f.lower().endswith((".png", ".jpg", ".jpeg"))]
                    if imgs:
                        ext = os.path.splitext(imgs[0])[1]
                        dest = dest[:-4] + ext
                        shutil.move(imgs[0], dest)
                finally:
                    shutil.rmtree(tmp, ignore_errors=True)
            if not os.path.exists(dest) and chrome:
                cmd = [chrome, "--headless=new", "--disable-gpu", "--hide-scrollbars", "--ignore-certificate-errors",
                       "--window-size=1366,768", f"--screenshot={dest}", w["url"]]
                if hasattr(os, "geteuid") and os.geteuid() == 0:
                    cmd.insert(1, "--no-sandbox")
                try:
                    subprocess.run(cmd, capture_output=True, timeout=45)
                except Exception:
                    pass
            if os.path.exists(dest):
                w["screenshot"] = os.path.relpath(dest, outdir)
            progress.advance(task)
        with cf.ThreadPoolExecutor(max_workers=4) as ex:
            list(ex.map(shoot, jobs))

    def run(self, targets, outdir):
        cols = [TextColumn("[bold cyan]{task.description}"), BarColumn(), MofNCompleteColumn(), TimeElapsedColumn()]
        with Progress(*cols, console=console, transient=True) as prog:
            if self.dnsx:
                self.prefetched = dnsx_prefetch(self.dnsx, [t.host for t in targets if t.is_name], self.a.threads)
            t1 = prog.add_task("Passive: DNS, ownership, PTR", total=len(targets))
            with cf.ThreadPoolExecutor(max_workers=self.a.threads) as ex:
                for f in cf.as_completed([ex.submit(self._safe, self.passive, t) for t in targets]):
                    prog.advance(t1)
            if not self.a.passive:
                todo = [t for t in targets if not t.private and t.resolves and not (self.a.skip_red_probe and t.tier == "red")]
                t2 = prog.add_task("Active: ping, ports, web, TLS", total=len(todo))
                with cf.ThreadPoolExecutor(max_workers=self.a.threads) as ex:
                    for f in cf.as_completed([ex.submit(self._safe, self.active, t) for t in todo]):
                        prog.advance(t2)
                if self.httpx:
                    t3 = prog.add_task("httpx tech detection", total=1)
                    self.httpx_enrich(targets)
                    prog.advance(t3)
                if self.a.screenshots:
                    self.screenshots(targets, outdir, prog)

    @staticmethod
    def _safe(fn, t):
        try:
            fn(t)
        except Exception as e:
            t.errors.append(f"{fn.__name__}: {type(e).__name__}: {e}")


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
TIER_STYLE = {"green": "bold green", "blue": "bold dodger_blue1", "red": "bold red", "grey": "bold bright_black"}
TIER_LABEL = {"green": "TESTABLE", "blue": "CAVEATS", "red": "DO NOT TEST", "grey": "NOT REACHABLE"}
TIER_HEX = {"green": "#22c55e", "blue": "#3b82f6", "red": "#ef4444", "grey": "#6b7280"}
TIER_ORDER = {"green": 0, "blue": 1, "red": 2, "grey": 3}


def sort_targets(targets):
    """Group by verdict, then by provider or owner so similar targets sit together, keeping input order inside."""
    def group(t):
        if t.tier == "green":
            return "" if t.base_note.startswith("Registered to the client") else t.owner_label()[0].lower()
        return (t.provider or "").lower()
    return sorted(targets, key=lambda t: (TIER_ORDER[t.tier], group(t)))


def known_names(t):
    """Every hostname tied to the target: input name, certificate names, PTR, Shodan."""
    names = []
    for n in ([t.host] if t.is_name else []) + t.tls_names() + list(t.ptr.values()) + t.shodan.get("hostnames", []):
        n = (n or "").lower()
        if n and n not in names:
            names.append(n)
    return names


def print_table(targets, args):
    def grid():
        g = Table.grid(expand=True, padding=(0, 1))
        g.add_column(justify="right", width=3)
        g.add_column(ratio=3, overflow="fold")
        g.add_column(ratio=6, overflow="fold")
        g.add_column(ratio=3, overflow="fold")
        g.add_column(ratio=5, overflow="fold")
        g.add_column(ratio=2)
        g.add_column(ratio=2, overflow="fold")
        g.add_column(ratio=2, overflow="fold")
        return g
    head = grid()
    head.add_row(*[Text(h, style="bold white") for h in
                   ("#", "Target", "What it is", "Owner", "Verdict", "Status", "Ports", "Logins")])
    console.print(Panel(head, box=box.HEAVY, border_style="grey50", padding=(0, 1)))
    for i, t in enumerate(targets, 1):
        org, asn, cc = t.owner_label()
        # what it is: URLs first, then names
        what = Text()
        for w in t.web[:4]:
            if w["status"] is None:
                continue
            sc = w["status"]
            what.append(f"[{sc}] ", style="green" if sc < 300 else "yellow" if sc < 400 else "red")
            what.append(w["url"], style="bold blue")
            if w["title"]:
                what.append(f"  {w['title'][:60]}", style="white")
            if w["final_url"] and w["final_url"].rstrip("/") != w["url"].rstrip("/"):
                what.append(f"\n  > {w['final_url'][:80]}", style="dim")
            what.append("\n")
        names = [n for n in known_names(t) if n != t.host]
        if names:
            what.append(", ".join(names[:5]) + (" ..." if len(names) > 5 else ""), style="cyan")
        if t.cnames:
            what.append(("\n" if names else "") + "CNAME " + " > ".join(t.cnames[-2:]), style="magenta")
        if not what.plain.strip():
            what.append("no web service or hostname found", style="dim")
        for c in t.tls[:1]:
            if c["expired"]:
                what.append("  cert EXPIRED", style="bold red")
            if c["self_signed"]:
                what.append("  self signed cert", style="yellow")

        own = Text()
        if t.ips:
            if t.is_name:
                own.append(", ".join(t.ips[:2]) + (" ..." if len(t.ips) > 2 else "") + "\n", style="cyan")
            own.append(org, style="white")
            if asn or cc:
                own.append("\n" + f"{asn} {cc}".strip(), style="dim")

        verdict = Text(TIER_LABEL[t.tier], style=TIER_STYLE[t.tier])
        if t.takeover:
            verdict.append("  TAKEOVER?", style="bold white on red")
        if t.provider:
            verdict.append(f"  {t.provider}", style=TIER_STYLE[t.tier].replace("bold ", ""))
        main, _, warn = t.note.partition(" WARNING: ")
        verdict.append("\n" + main, style="white" if t.tier != "green" else "dim")
        if warn:
            verdict.append("\nWARNING: " + warn, style="bold yellow")

        if t.live == "live":
            st = Text("LIVE", style="bold green")
        elif t.live == "no response":
            st = Text("no response", style="dim")
        else:
            st = Text("not probed", style="dim")
        ports = Text(", ".join(map(str, t.open_ports)), style="green")
        if t.shodan.get("vulns"):
            ports.append(f"\n{len(t.shodan['vulns'])} CVEs", style="bold red")
        logins = Text("\n".join(t.logins), style="bold magenta")
        row = grid()
        row.add_row(Text(str(i), style="dim"), Text(t.raw, style="bold"), what, own, verdict, st, ports, logins)
        console.print(Panel(row, box=box.ROUNDED, border_style=TIER_STYLE[t.tier].replace("bold ", ""), padding=(0, 1)))


def print_notes(targets):
    """Recap of the non-green rows above, one box per provider rule, so IP lists can be copied in one go."""
    groups = {}
    for i, t in enumerate(targets, 1):
        if t.tier != "green":
            groups.setdefault((t.tier, t.provider, t.base_note), []).append((i, t))
    if not groups:
        return
    console.print()
    console.rule("[bold]Recap by provider: the blue, red and grey rows above, grouped")
    for (tier, prov, note), items in sorted(groups.items(), key=lambda kv: (TIER_ORDER[kv[0][0]], kv[0][1].lower())):
        title = TIER_LABEL[tier] + (f": {prov}" if prov else "")
        body = Text(note + "\n", style="white")
        body.append(", ".join(t.raw for _, t in items), style=TIER_STYLE[tier].replace("bold ", ""))
        body.append(f"\nrows {', '.join(str(i) for i, _ in items)}", style="dim")
        console.print(Panel(body, title=f"[{TIER_STYLE[tier]}]{title}[/]", border_style=TIER_STYLE[tier].replace("bold ", ""),
                            title_align="left"))


def portal_rows(targets):
    """One row per web URL that showed a login portal."""
    rows = []
    for i, t in enumerate(targets, 1):
        for w in t.web:
            if w.get("logins"):
                rows.append((i, t, w))
    return rows


def print_portals(targets):
    rows = portal_rows(targets)
    if not rows:
        return
    console.print()
    tb = Table(box=box.SIMPLE, header_style="bold magenta", expand=True, show_edge=False)
    tb.add_column("#", justify="right", style="dim", width=3)
    tb.add_column("Portal type", style="bold magenta", ratio=3)
    tb.add_column("URL", style="bold blue", overflow="fold", ratio=5)
    tb.add_column("Title", overflow="fold", ratio=3)
    tb.add_column("Target", overflow="fold", ratio=3)
    tb.add_column("Verdict", ratio=2)
    for i, t, w in rows:
        final = w["final_url"] if w["final_url"] and w["final_url"].rstrip("/") != w["url"].rstrip("/") else ""
        url = Text(w["url"])
        if final:
            url.append(f"\n> {final}", style="dim")
        tb.add_row(str(i), ", ".join(w["logins"]), url, w["title"][:60], t.raw,
                   Text(TIER_LABEL[t.tier] + (f"\n{t.provider}" if t.provider else ""), style=TIER_STYLE[t.tier]))
    console.print(Panel(tb, title=f"[bold magenta]Login portals ({len(rows)})[/]", border_style="magenta",
                        title_align="left"))


def print_summary(targets, outdir):
    c = {k: sum(1 for t in targets if t.tier == k) for k in TIER_LABEL}
    live = sum(1 for t in targets if t.live == "live")
    logins = sum(1 for t in targets if t.logins)
    take = sum(1 for t in targets if t.takeover)
    s = Text()
    s.append(f"{len(targets)} targets   ", style="bold")
    s.append(f"{c['green']} testable   ", style="bold green")
    s.append(f"{c['blue']} with caveats   ", style="bold dodger_blue1")
    s.append(f"{c['red']} do not test   ", style="bold red")
    s.append(f"{c['grey']} not reachable   ", style="bold bright_black")
    s.append(f"{live} live   ", style="bold green")
    s.append(f"{len(portal_rows(targets))} login portals on {logins} targets", style="bold magenta")
    if take:
        s.append(f"   {take} possible takeovers", style="bold white on red")
    console.print(Panel(s, title="Summary", border_style="cyan", title_align="left"))
    console.print(f"[dim]Reports written to[/] [bold]{outdir}/[/] [dim](report.html, results.csv, results.json)[/]")


def write_csv(targets, path):
    fields = ["target", "kind", "ips", "cnames", "ptr", "owner", "asn", "asn_name", "country", "verdict", "provider", "names",
              "status", "open_ports", "web", "logins", "tls_names", "cert_issues", "shodan_ports", "shodan_vulns",
              "takeover", "note"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader()
        for t in targets:
            org, asn, cc = t.owner_label()
            o = t.owners.get(t.primary_ip) or {}
            issues = []
            for c in t.tls:
                if c["expired"]:
                    issues.append(f"{c['port']} expired")
                if c["self_signed"]:
                    issues.append(f"{c['port']} self signed")
            w.writerow(dict(
                target=t.raw, kind=t.kind, ips=" ".join(t.ips), cnames=" > ".join(t.cnames),
                ptr=" ".join(t.ptr.values()), owner=org, asn=asn, asn_name=o.get("asn_name", ""), country=cc,
                verdict=TIER_LABEL[t.tier], provider=t.provider, names=" ".join(known_names(t)), status=t.live,
                open_ports=" ".join(map(str, t.open_ports)),
                web=" | ".join(f"{x['status']} {x['url']} {x['title']}" for x in t.web if x["status"]),
                logins="; ".join(t.logins), tls_names=" ".join(t.tls_names()[:20]), cert_issues="; ".join(issues),
                shodan_ports=" ".join(map(str, t.shodan.get("ports", []))),
                shodan_vulns=" ".join(t.shodan.get("vulns", [])), takeover=t.takeover, note=t.note))


def write_html(targets, path, args, started):
    e = html.escape
    rows = []
    for i, t in enumerate(targets, 1):
        org, asn, cc = t.owner_label()
        col = TIER_HEX[t.tier]
        own = f"{e(org)}<br><span class=dim>{e(asn)} {e(cc)}</span>" if t.ips else ""
        if t.is_name and t.ips:
            own = f"<span class=ip>{e(', '.join(t.ips))}</span><br>" + own
        verdict = f"<span class=badge style='background:{col}'>{TIER_LABEL[t.tier]}</span>"
        if t.provider:
            verdict += f" <b style='color:{col}'>{e(t.provider)}</b>"
        if t.takeover:
            verdict += " <span class=badge style='background:#ef4444;color:#fff'>TAKEOVER?</span>"
        main, _, warn = t.note.partition(" WARNING: ")
        verdict += f"<div class=why>{e(main)}</div>"
        if warn:
            verdict += f"<div class=why style='color:#eab308;font-weight:700'>WARNING: {e(warn)}</div>"
        status = {"live": "<span class=live>LIVE</span>", "no response": "<span class=dim>no response</span>"}.get(
            t.live, "<span class=dim>not probed</span>")
        what = ""
        for w in t.web:
            if w["status"] is None:
                continue
            sc = w["status"]
            scc = "#22c55e" if sc < 300 else "#eab308" if sc < 400 else "#ef4444"
            what += (f"<div class=web><span style='color:{scc}'>[{sc}]</span> <a href='{e(w['url'])}' target=_blank>"
                     f"<b>{e(w['url'])}</b></a> {e(w['title'])}")
            if w["final_url"] and w["final_url"].rstrip("/") != w["url"].rstrip("/"):
                what += f"<br><span class=dim>&rarr; {e(w['final_url'])}</span>"
            if w["server"] or w.get("tech"):
                what += f"<br><span class=dim>{e(w['server'])} {e(', '.join(w.get('tech', [])))}</span>"
            if w.get("screenshot"):
                what += f"<br><a href='{e(w['screenshot'])}' target=_blank><img src='{e(w['screenshot'])}'></a>"
            what += "</div>"
        names = [n for n in known_names(t) if n != t.host]
        if names:
            what += f"<div class=ip>{e(', '.join(names[:10]))}</div>"
        if t.cnames:
            what += "<div class=mag>CNAME " + e(" > ".join(t.cnames)) + "</div>"
        for c in t.tls:
            if c["expired"] or c["self_signed"]:
                what += (f"<div class=dim>Cert on :{c['port']}" + (" <b style='color:#ef4444'>EXPIRED</b>" if c["expired"] else "")
                         + (" <b style='color:#eab308'>self signed</b>" if c["self_signed"] else "") + "</div>")
        if not what:
            what = "<span class=dim>no web service or hostname found</span>"
        ports = e(", ".join(map(str, t.open_ports)))
        if t.shodan.get("vulns"):
            ports += f"<br><span style='color:#ef4444'>{e(', '.join(t.shodan['vulns'][:10]))}</span>"
        logins = "<br>".join(f"<span class=login>{e(l)}</span>" for l in t.logins)
        rows.append(f"<tr style='border-left:6px solid {col}' data-tier='{t.tier}'><td>{i}</td><td><b>{e(t.raw)}</b></td>"
                    f"<td>{what}</td><td>{own}</td><td>{verdict}</td><td>{status}</td><td>{ports}</td><td>{logins}</td></tr>")
    c = {k: sum(1 for t in targets if t.tier == k) for k in TIER_LABEL}
    prow = ""
    for i, t, w in portal_rows(targets):
        col = TIER_HEX[t.tier]
        final = w["final_url"] if w["final_url"] and w["final_url"].rstrip("/") != w["url"].rstrip("/") else ""
        prow += (f"<tr><td>{i}</td><td class=login>{e(', '.join(w['logins']))}</td>"
                 f"<td><a href='{e(w['url'])}' target=_blank><b>{e(w['url'])}</b></a>"
                 + (f"<br><span class=dim>&rarr; {e(final)}</span>" if final else "") +
                 f"</td><td>{e(w['title'])}</td><td>{e(t.raw)}</td>"
                 f"<td><span class=badge style='background:{col}'>{TIER_LABEL[t.tier]}</span> {e(t.provider)}</td></tr>")
    portals = (f"<h2 class=ph>Login portals ({len(portal_rows(targets))})</h2><table class=portals><thead><tr><th>#</th>"
               f"<th>Portal type</th><th>URL</th><th>Title</th><th>Target</th><th>Verdict</th></tr></thead>"
               f"<tbody>{prow}</tbody></table>") if prow else ""
    clients = e(", ".join(args.client)) or "not set"
    domains = e(", ".join(args.domain)) or "not set"
    doc = f"""<!DOCTYPE html><html><head><meta charset=utf-8><title>Scope check report</title><style>
body{{background:#0b1020;color:#e5e7eb;font:14px/1.45 system-ui,Segoe UI,Arial,sans-serif;margin:24px}}
h1{{margin:0 0 4px}} .meta{{color:#9ca3af;margin-bottom:16px}}
.cards{{display:flex;gap:12px;margin:12px 0 18px;flex-wrap:wrap}}
.card{{padding:10px 16px;border-radius:8px;background:#111827;border-top:4px solid;cursor:pointer;min-width:110px}}
.card b{{font-size:22px;display:block}}
table{{border-collapse:collapse;width:100%}} th{{background:#1f2937;text-align:left;padding:8px;position:sticky;top:0}}
td{{padding:8px;vertical-align:top;border-bottom:1px solid #1f2937}} tr.note td{{color:#cbd5e1;font-size:13px;padding-top:0}}
.badge{{display:inline-block;padding:2px 8px;border-radius:4px;color:#000;font-weight:700;font-size:12px}}
.ph{{color:#e879f9;margin:8px 0 8px}} .mh{{margin:28px 0 8px}} table.portals{{border:1px solid #6b21a8}}
.why{{margin-top:4px;font-size:13px;color:#cbd5e1;max-width:360px}} .dim{{color:#9ca3af;font-size:12px}} .ip{{color:#67e8f9}}
.mag{{color:#e879f9;font-size:12px}} .live{{color:#22c55e;font-weight:700}} .login{{color:#e879f9;font-weight:700}}
a{{color:#93c5fd}} img{{max-width:260px;margin-top:6px;border:1px solid #374151;border-radius:4px}} .web{{margin-bottom:8px}}
</style></head><body>
<h1>Scope check report</h1>
<div class=meta>Generated {e(started)} &middot; client names: {clients} &middot; client domains: {domains} &middot; {len(targets)} targets</div>
<div class=cards>
<div class=card style='border-color:#22c55e' onclick="f('green')"><b>{c['green']}</b>Testable</div>
<div class=card style='border-color:#3b82f6' onclick="f('blue')"><b>{c['blue']}</b>Testable with caveats</div>
<div class=card style='border-color:#ef4444' onclick="f('red')"><b>{c['red']}</b>Do not test</div>
<div class=card style='border-color:#6b7280' onclick="f('grey')"><b>{c['grey']}</b>Not reachable</div>
<div class=card style='border-color:#38bdf8' onclick="f('')"><b>{len(targets)}</b>Show all</div>
</div>
{portals}
<h2 class=mh>All targets</h2>
<table><thead><tr><th>#</th><th>Target</th><th>What it is</th><th>Owner</th><th>Verdict</th><th>Status</th><th>Ports</th><th>Logins</th></tr></thead>
<tbody id=main>{''.join(rows)}</tbody></table>
<p class=dim>Notes summarise provider testing policies and are not a substitute for the provider's current policy or the client's written authorisation.</p>
<script>function f(t){{document.querySelectorAll('#main tr').forEach(r=>{{r.style.display=(!t||r.dataset.tier===t)?'':'none'}})}}</script>
</body></html>"""
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(doc)


# --------------------------------------------------------------------------
def main():
    ap = argparse.ArgumentParser(description="External pentest scope recon: ownership, liveness, web and login portals.",
                                 formatter_class=argparse.RawDescriptionHelpFormatter, epilog="""examples:
  scopecheck.py -i scope.txt -c "Acme Corp" -d acme.com -d acme-mail.com
  scopecheck.py -i scope.txt -c Acme --screenshots --shodan
  scopecheck.py -i scope.txt -c Acme --passive          (no packets to targets)
  scopecheck.py -i scope.txt -c Acme --skip-red-probe   (never probe third party assets)""")
    ap.add_argument("-i", "--input", required=True, help="file of IPs, CIDRs, ranges, hostnames and URLs")
    ap.add_argument("-c", "--client", action="append", default=[], help="client name as it may appear in WHOIS (repeatable)")
    ap.add_argument("-d", "--domain", action="append", default=[], help="client domain (repeatable)")
    ap.add_argument("-o", "--outdir", help="output folder (default scopecheck_<timestamp>)")
    ap.add_argument("-p", "--ports", default=",".join(map(str, DEFAULT_PORTS)), help="TCP ports for liveness check")
    ap.add_argument("-t", "--threads", type=int, default=10, help="concurrent targets (default 10)")
    ap.add_argument("--timeout", type=int, default=3, help="network timeout in seconds (default 3)")
    ap.add_argument("--max-hosts", type=int, default=1024, help="max hosts a single CIDR or range may expand to")
    ap.add_argument("--passive", action="store_true", help="passive only: no ping, ports, HTTP or TLS")
    ap.add_argument("--skip-red-probe", action="store_true", help="do not actively probe DO NOT TEST (red) targets")
    ap.add_argument("--screenshots", action="store_true", help="screenshot web services (gowitness, else headless Chrome)")
    ap.add_argument("--shodan", action="store_true", help="query Shodan InternetDB (free, no key) for known ports and CVEs")
    ap.add_argument("--no-external-tools", action="store_true", help="ignore httpx, dnsx and gowitness even if installed")
    args = ap.parse_args()
    for c in list(args.client):
        args.client.remove(c)
        args.client += [x.strip() for x in c.split(",") if x.strip()]
    for d in list(args.domain):
        args.domain.remove(d)
        args.domain += [x.strip() for x in d.split(",") if x.strip()]
    try:
        args.ports = [int(p) for p in args.ports.split(",") if p.strip()]
    except ValueError:
        sys.exit("Ports must be a comma separated list of numbers.")

    started = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    outdir = args.outdir or "scopecheck_" + datetime.now().strftime("%Y%m%d_%H%M%S")
    os.makedirs(outdir, exist_ok=True)

    console.print(Panel.fit(f"[bold cyan]scopecheck[/] v{VERSION}  [dim]external scope recon[/]", border_style="cyan"))
    targets, bad = parse_targets(args.input, args.max_hosts)
    if not targets:
        sys.exit("No valid targets found.")
    if not args.client:
        console.print("[yellow]No --client given, so nothing can be marked as client owned. Everything not "
                      "matched to a provider will show as VERIFY.[/]")
    missing = [n for n, m in (("ipwhois", IPWhois), ("dnspython", dns), ("cryptography", x509), ("requests", requests)) if not m]
    if missing:
        console.print(f"[yellow]Optional modules missing ({', '.join(missing)}); some checks fall back or are skipped.[/]")

    r = Runner(args)
    tools = [f"httpx: {'yes' if r.httpx else 'no'}", f"dnsx: {'yes' if r.dnsx else 'no'}"]
    mode = "passive only" if args.passive else ("active, not probing DO NOT TEST targets" if args.skip_red_probe else "active")
    console.print(f"[dim]{len(targets)} targets | mode: {mode} | {' | '.join(tools)}[/]")

    t0 = time.time()
    r.run(targets, outdir)
    targets = sort_targets(targets)
    print_table(targets, args)
    print_notes(targets)
    print_portals(targets)
    write_csv(targets, os.path.join(outdir, "results.csv"))
    with open(os.path.join(outdir, "results.json"), "w", encoding="utf-8") as fh:
        json.dump([asdict(t) for t in targets], fh, indent=2, default=str)
    write_html(targets, os.path.join(outdir, "report.html"), args, started)
    print_summary(targets, outdir)
    if bad:
        console.print(f"[yellow]Skipped {len(bad)} entries from the input file that are not an IP, range, hostname or URL:[/]")
        for b in bad:
            console.print(f"  [yellow]{b}[/]")
    errs = [(t.raw, e) for t in targets for e in t.errors]
    for raw, err in errs[:10]:
        console.print(f"[red]Error[/] {raw}: {err}")
    console.print(f"[dim]Finished in {time.time() - t0:.1f}s[/]")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        sys.exit("\nInterrupted.")

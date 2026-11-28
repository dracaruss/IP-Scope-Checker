#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
dnstwistturbo.py

Wraps dnstwist for external penetration testing recon and adds the one thing
dnstwist does not do: it infers whether each registered lookalike domain is
owned by the client (a defensive registration) or by someone else (a
typosquatting or phishing threat).

It fingerprints the real domain first to build a baseline, runs dnstwist to
generate and resolve lookalikes, then correlates every registered lookalike
against the baseline using netblock and ASN ownership, nameserver overlap,
HTTP redirects, TLS certificate names, registration data and live mail.

Ownership is ALWAYS inferred, never proven. Confirm every verdict against the
client's own list of registered domains before it goes in a report.

Requirements (Kali):  apt install dnstwist python3-dnspython python3-cryptography
                or:   pip install dnstwist dnspython cryptography
A dnstwist.py sitting beside this script also works.

Quick use:
  python3 dnstwistturbo.py acme.com -c "Acme Corp"
  python3 dnstwistturbo.py acme.com -c "Acme Corp" -d acme-mail.com      (finds ../IP-Scope-Checker results itself)
  python3 dnstwistturbo.py acme.com --known client_domains.txt -o out/
  python3 dnstwistturbo.py acme.com --list > lookalikes.txt
  dnstwist -r -a -m -f json acme.com > dt.json; python3 dnstwistturbo.py acme.com --from-json dt.json

scopecheck integration (one way, scopecheck never needs this tool):
  When scopecheck.py sits beside this script, in the current folder, or at
  $SCOPECHECK_PY, its RDAP ownership lookup, provider list and client name
  matching are used, so both tools reach the same ownership answers.
  The newest scopecheck_*/results.json is found automatically (or pass
  --scopecheck DIR); it adds the client IPs,
  netblocks registered to the client and client domains it verified.
"""

__version__ = '1.0.0'

import argparse
import concurrent.futures as cf
import html
import ipaddress
import json
import os
import re
import socket
import ssl
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))

try:
    import dnstwist
except ImportError:
    sys.path.insert(0, HERE)
    try:
        import dnstwist
    except ImportError:
        dnstwist = None

try:
    import dns.resolver
    import dns.exception
    HAVE_DNSPYTHON = True
except ImportError:
    HAVE_DNSPYTHON = False

try:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    from cryptography.x509.oid import NameOID
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


# --------------------------------------------------------------------------
# Scoring weights. Tune these here. Each category contributes its single
# strongest signal; categories are summed and capped at 100.
# --------------------------------------------------------------------------
W = {
    # ownership evidence
    'ip_scope':            45,   # IP scopecheck marked testable (green) for the client
    'ip_exact':            45,   # same IP as client, client not on shared infra
    'ip_exact_cloud':      30,   # same cloud IP as client (elastic IPs are per customer)
    'ip_exact_hosting':    20,   # same hosting IP as client (may be shared hosting)
    'ip_exact_shared':     10,   # same IP, but it is a shared CDN, SaaS or mail IP
    'ip_netblock':         40,   # inside a client netblock (non shared)
    'ip_org_hint':         40,   # netblock RDAP org matches --org
    'ip_asn':              25,   # same non shared ASN as client
    'ip_hostorg':          25,   # same hosting org as client (non shared)
    'ip_asn_shared':        3,   # both on the same big shared provider
    'ns_client_domain':    50,   # NS hostnames live under a client domain
    'ns_route53_set':      40,   # identical Route53 delegation set
    'ns_cloudflare_pair':  35,   # identical Cloudflare NS pair
    'ns_custom':           30,   # shares a non generic NS host with client
    'ns_bp_same':          25,   # same brand protection DNS as client
    'ns_bp':               15,   # on brand protection DNS at all
    'ns_partial_pair':      5,   # one of the Cloudflare pair matches
    'ns_generic':           5,   # shares a generic registrar or hosting NS
    'http_redirect':       40,   # redirects to a client domain
    'tls_same_cert':       45,   # identical certificate to the client
    'tls_san':             40,   # certificate SAN covers a client domain
    'tls_org':             30,   # certificate subject O matches client org
    'reg_email':           50,   # registrant email on a client domain
    'reg_org':             45,   # registrant org matches client org
    'registrar_bp_same':   35,   # same brand protection registrar as client
    'registrar_bp':        20,   # any brand protection registrar
    'mx_client_domain':    40,   # MX host under a client domain
    'mx_same_tenant':      35,   # same tenant specific MX as client
    'mx_same_shared':       3,   # same shared mail service MX
    'mx_null':             10,   # RFC 7505 null MX, mail disabled
    # threat evidence
    't_mx_spy':            40,   # MX accepts mail for any recipient
    't_mx_live':           15,   # has a working MX not tied to the client
    't_age_30':            30,   # registered in the last 30 days
    't_age_90':            20,
    't_age_365':           10,
    't_login':             20,   # serves a password form
    't_clone':             25,   # serves the client's page title
    't_parked':           -10,   # parked page or parking NS
}

# Short labels for the normal output. Full wording and points show with --debug.
SHORT = {
    'ip_scope': 'IP in client scope', 'ip_exact': 'client IP', 'ip_exact_cloud': 'client cloud IP',
    'ip_exact_hosting': 'client hosting IP', 'ip_exact_shared': 'same CDN IP', 'ip_netblock': 'client netblock',
    'ip_org_hint': 'client netblock', 'ip_asn': 'client ASN', 'ip_hostorg': 'client host', 'ip_asn_shared': 'same provider',
    'ns_client_domain': 'client NS', 'ns_route53_set': 'client Route53 NS', 'ns_cloudflare_pair': 'client Cloudflare NS',
    'ns_custom': 'client NS', 'ns_bp_same': 'brand protection DNS', 'ns_bp': 'brand protection DNS',
    'ns_partial_pair': 'similar NS', 'ns_generic': 'same DNS host', 'http_redirect': 'redirects to client',
    'tls_same_cert': 'client cert', 'tls_san': 'cert names client', 'tls_org': 'cert org is client',
    'reg_email': 'registrant is client', 'reg_org': 'registrant is client', 'registrar_bp_same': 'client registrar',
    'registrar_bp': 'brand protection registrar', 'mx_client_domain': 'client MX', 'mx_same_tenant': 'client MX',
    'mx_same_shared': 'same mail service', 'mx_null': 'mail disabled', 't_mx_spy': 'accepts any mail',
    't_mx_live': 'live MX', 't_login': 'login page', 't_clone': 'clones client site', 't_parked': 'parked or for sale',
}
# Any of these on a domain with no client evidence makes it a THREAT, shown in red.
DANGER_KEYS = {'t_mx_spy', 't_login', 't_clone'}
GENERIC_TITLES = {'home', 'homepage', 'welcome', 'index', 'default', 'untitled', 'coming soon', 'login', 'log in',
                  'sign in', 'loading', 'redirecting', 'just a moment...', '403 forbidden', '404 not found', 'access denied'}

CLIENT_MIN = 35      # owner score needed to call client owned
THREAT_MIN = 40      # threat score needed to call likely malicious

# Shared providers. A match here means "many unrelated customers share this",
# so it is weak ownership evidence on its own.
SHARED_ASNS = {
    13335: 'Cloudflare', 209242: 'Cloudflare', 16625: 'Akamai', 20940: 'Akamai',
    32787: 'Akamai', 21342: 'Akamai', 33905: 'Akamai', 35994: 'Akamai',
    63949: 'Akamai Linode', 54113: 'Fastly', 16509: 'AWS', 14618: 'AWS', 8987: 'AWS',
    8075: 'Microsoft', 8068: 'Microsoft', 15169: 'Google', 396982: 'Google Cloud',
    19527: 'Google', 19551: 'Imperva', 62571: 'Imperva', 30148: 'Sucuri',
    15133: 'Edgio', 14153: 'Edgio', 22822: 'Edgio', 12989: 'StackPath',
    33438: 'StackPath', 20446: 'StackPath', 36459: 'GitHub', 14061: 'DigitalOcean',
    16276: 'OVH', 24940: 'Hetzner', 26496: 'GoDaddy', 398101: 'GoDaddy',
    46606: 'Newfold Bluehost', 53831: 'Squarespace', 58182: 'Wix', 20473: 'Vultr',
    22612: 'Namecheap', 31898: 'Oracle Cloud', 36351: 'IBM Cloud', 45102: 'Alibaba',
    132203: 'Tencent', 47583: 'Hostinger', 8560: 'IONOS', 51167: 'Contabo',
    60781: 'Leaseweb', 32244: 'Liquid Web',
}
SHARED_KW = [
    ('cloudflare', 'Cloudflare'), ('akamai', 'Akamai'), ('fastly', 'Fastly'),
    ('amazon', 'AWS'), ('aws', 'AWS'), ('microsoft', 'Microsoft'), ('azure', 'Azure'),
    ('google', 'Google'), ('incapsula', 'Imperva'), ('imperva', 'Imperva'),
    ('sucuri', 'Sucuri'), ('edgecast', 'Edgio'), ('edgio', 'Edgio'),
    ('limelight', 'Edgio'), ('stackpath', 'StackPath'), ('highwinds', 'StackPath'),
    ('github', 'GitHub'), ('digitalocean', 'DigitalOcean'), ('linode', 'Linode'),
    ('ovh', 'OVH'), ('hetzner', 'Hetzner'), ('godaddy', 'GoDaddy'),
    ('unified layer', 'Bluehost'), ('bluehost', 'Bluehost'), ('hostgator', 'HostGator'),
    ('squarespace', 'Squarespace'), ('wix', 'Wix'), ('shopify', 'Shopify'),
    ('wpengine', 'WP Engine'), ('wp engine', 'WP Engine'), ('vercel', 'Vercel'),
    ('netlify', 'Netlify'), ('heroku', 'Heroku'), ('namecheap', 'Namecheap'),
    ('hostinger', 'Hostinger'), ('ionos', 'IONOS'), ('vultr', 'Vultr'),
    ('choopa', 'Vultr'), ('oracle', 'Oracle Cloud'), ('alibaba', 'Alibaba'),
    ('tencent', 'Tencent'), ('liquid web', 'Liquid Web'), ('rackspace', 'Rackspace'),
    ('softlayer', 'IBM Cloud'), ('newfold', 'Newfold'), ('dreamhost', 'DreamHost'),
    ('siteground', 'SiteGround'), ('contabo', 'Contabo'), ('leaseweb', 'Leaseweb'),
    ('network solutions', 'Network Solutions'), ('team internet', 'Team Internet'),
    ('sedo', 'Sedo'), ('bodis', 'Bodis'),
]

# Provider kind for the built in fallback, matching scopecheck's kinds.
# Anything not listed here counts as hosting.
PROVIDER_KIND = {
    'Cloudflare': 'cdn', 'Akamai': 'cdn', 'Fastly': 'cdn', 'Imperva': 'cdn', 'Sucuri': 'cdn',
    'Edgio': 'cdn', 'StackPath': 'cdn', 'AWS': 'cloud', 'Microsoft': 'cloud', 'Azure': 'cloud',
    'Google': 'cloud', 'Google Cloud': 'cloud', 'Oracle Cloud': 'cloud', 'IBM Cloud': 'cloud',
    'Alibaba': 'cloud', 'Tencent': 'cloud', 'GitHub': 'saas', 'Squarespace': 'saas', 'Wix': 'saas',
    'Shopify': 'saas', 'WP Engine': 'saas', 'Vercel': 'saas', 'Netlify': 'saas', 'Heroku': 'saas',
    'Sedo': 'parking', 'Bodis': 'parking', 'Team Internet': 'parking',
}

# scopecheck.py is imported when found beside this script, in the current
# folder, at $SCOPECHECK_PY, or at --scopecheck-py. Its ownership lookup and
# provider list then replace the built in ones, so both tools agree.
SC = None
SC_PATH = None


def load_scopecheck(path=None):
    global SC, SC_PATH
    import importlib.util
    import glob
    parent = os.path.dirname(HERE)
    # Sibling repo clones: ../IP-Scope-Checker/scopecheck.py first, then any ../*/scopecheck.py
    siblings = [os.path.join(parent, 'IP-Scope-Checker', 'scopecheck.py')] + \
        sorted(glob.glob(os.path.join(parent, '*', 'scopecheck.py')))
    cands = [path] if path else [os.environ.get('SCOPECHECK_PY'), os.path.join(HERE, 'scopecheck.py'),
                                 os.path.join(os.getcwd(), 'scopecheck.py')] + siblings
    for p in cands:
        if not p or not os.path.isfile(p):
            continue
        try:
            spec = importlib.util.spec_from_file_location('scopecheck', p)
            mod = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(mod)
            if hasattr(mod, 'Owners') and hasattr(mod, 'match_provider'):
                SC, SC_PATH = mod, os.path.abspath(p)
                return SC
        except BaseException as e:          # scopecheck calls sys.exit when rich is missing
            log(yel('[!] could not import {} ({}), using built in ownership logic'.format(p, e)))
    return None


def owner_matches_client(i, hints):
    """Client name in the IP owner record. Uses scopecheck's matching when it is loaded."""
    if not hints or not i:
        return None
    if SC is not None:
        blob = SC.norm(' '.join([i.get('net_org') or '', i.get('net_name') or '', i.get('as_name') or '']
                                + list(i.get('entities') or [])))
        return next((h for h in hints if SC.norm(h) and SC.norm(h) in blob), None)
    return org_match(i.get('net_org') or '', hints) or org_match(i.get('as_name') or '', hints)


PARKING_NS = ('sedoparking.com', 'parkingcrew.net', 'bodis.com', 'above.com',
              'dan.com', 'undeveloped.com', 'afternic.com', 'hugedomains.com',
              'parklogic.com', 'ztomy.com', 'cashparking.com', 'parking.namecheap',
              'domainparking', 'parkeddomain', 'expired.uniregistry')
PARKING_HTML = ('this domain is for sale', 'buy this domain', 'domain is for sale',
                'this domain may be for sale', 'domain has expired', 'parked free',
                'parkingcrew', 'sedoparking', 'afternic', 'hugedomains',
                'make an offer on this domain', 'related searches',
                'this domain is parked', 'domain parking')
GENERIC_DNS = ('domaincontrol.com', 'registrar-servers.com', 'name-services.com',
               'hostgator.com', 'bluehost.com', 'websitewelcome.com', 'dreamhost.com',
               'wixdns.net', 'googledomains.com', 'google.com', 'ui-dns.com',
               'ui-dns.de', 'ui-dns.org', 'ui-dns.biz', 'nsone.net', 'dnsmadeeasy.com',
               'ultradns.net', 'ultradns.com', 'ultradns.org', 'ultradns.biz',
               'akam.net', 'dynect.net', 'azure-dns.com', 'azure-dns.net',
               'azure-dns.org', 'azure-dns.info', 'worldnic.com', 'hover.com',
               'gandi.net', 'ovh.net', 'digitalocean.com', 'linode.com', 'cloudns.net',
               'porkbun.com', 'squarespacedns.com', 'name.com', 'dns.com',
               'hostinger.com', 'dns-parking.com', 'siteground.net', 'wpengine.com',
               'register.com', 'networksolutions.com', 'secureserver.net',
               'hetzner.com', 'your-server.de', 'vercel-dns.com', 'netlify.com')
BP_DNS = ('cscdns', 'markmonitor', 'safenames', 'comlaude', 'nom-iq', 'corsearch',
          'brandshelter', 'ebrand', 'lexsynergy', 'abion')
BP_REGISTRARS = ('markmonitor', 'csc corporate', 'corporation service company',
                 'cscglobal', 'safenames', 'com laude', 'nom-iq', 'corsearch',
                 'brandsight', 'godaddy corporate', 'lexsynergy', 'ebrand', 'abion',
                 'brandshelter', 'authentic web', 'gandi corporate')
SHARED_MX = ('google.com', 'googlemail.com', 'mimecast', 'outlook.com', 'messagelabs',
             'secureserver.net', 'registrar-servers.com', 'privateemail.com', 'zoho',
             'mailgun', 'sendgrid', 'emailsrvr.com', 'improvmx', 'forwardemail',
             'mxroute', 'yandex', 'icloud.com', 'protonmail', 'titan.email',
             'hostinger', 'ovh.net', 'mail.protection')
# Hosts a client homepage may redirect to that are not the client's own domain.
NOT_CLIENT_HOSTS = ('microsoftonline.com', 'okta.com', 'google.com', 'wixsite.com',
                    'squarespace.com', 'myshopify.com', 'godaddysites.com',
                    'wordpress.com', 'github.io', 'linkedin.com', 'facebook.com')

REDACT_RE = re.compile(
    r'redact|privacy|private|withheld|not disclosed|data protected|proxy|whoisguard|'
    r'domains by proxy|contact privacy|gdpr|masked|statutory|non-public|not available|'
    r'on behalf of|identity protect|perfect privacy|whois agent|please query|'
    r'select request email form', re.I)
ORG_SUFFIX_RE = re.compile(
    r'\b(inc|incorporated|llc|l l c|ltd|limited|corp|corporation|co|company|gmbh|plc|'
    r'sa|ag|bv|nv|pty|pllc|lp|llp|group|holdings|the)\b')


# --------------------------------------------------------------------------
# Small helpers
# --------------------------------------------------------------------------
class Col:
    on = False
    @classmethod
    def c(cls, code, s):
        return '\x1b[{}m{}\x1b[0m'.format(code, s) if cls.on else s

def red(s): return Col.c('1;31', s)
def yel(s): return Col.c('1;33', s)
def grn(s): return Col.c('1;32', s)
def cya(s): return Col.c('36', s)
def blu(s): return Col.c('1;94', s)
def dim(s): return Col.c('2', s)
def bold(s): return Col.c('1', s)

def log(msg, end='\n'):
    print(msg, file=sys.stderr, end=end, flush=True)


def reg_domain(host):
    """Registrable domain for a hostname (acme.co.uk from www.acme.co.uk)."""
    host = (host or '').lower().strip('.')
    if dnstwist is not None:
        try:
            _, dom, tld = dnstwist.domain_tld(host)
            if dom and tld:
                return '{}.{}'.format(dom, tld)
        except Exception:
            pass
    parts = host.split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else host


def host_in(host, bases):
    host = (host or '').lower().strip('.')
    if not host:
        return False
    return any(host == b or host.endswith('.' + b) for b in bases)


def norm_org(s):
    s = re.sub(r'[^a-z0-9 ]', ' ', (s or '').lower())
    s = ORG_SUFFIX_RE.sub(' ', s)
    return ' '.join(s.split())


def org_match(value, orgs):
    """Return the matching client org string, or None."""
    nv = norm_org(value)
    if len(nv) < 3:
        return None
    for o in orgs:
        no = norm_org(o)
        if len(no) < 3:
            continue
        if nv == no or (len(no) >= 5 and no in nv) or (len(nv) >= 5 and nv in no):
            return o
    return None


def detect_provider(asn, *names):
    if asn in SHARED_ASNS:
        return SHARED_ASNS[asn]
    blob = ' '.join(n for n in names if n).lower()
    for kw, name in SHARED_KW:
        if re.search(r'\b' + re.escape(kw) + r'\b', blob):
            return name
    return None


def is_bp_registrar(name):
    n = (name or '').lower()
    return next((b for b in BP_REGISTRARS if b in n), None)


def parse_date(s):
    if not s:
        return None
    if isinstance(s, datetime):
        dt = s
    else:
        s = str(s).strip().split(' (')[0]
        dt = None
        try:
            dt = datetime.fromisoformat(s.replace('Z', '+00:00'))
        except ValueError:
            for f in ('%Y-%m-%d %H:%M:%S%z', '%Y-%m-%d %H:%M:%S', '%Y-%m-%d',
                      '%d-%b-%Y', '%d.%m.%Y', '%Y.%m.%d', '%Y/%m/%d', '%d/%m/%Y',
                      '%a %b %d %Y', '%Y.%m.%d %H:%M:%S', '%d-%b-%Y %H:%M:%S'):
                for cand in (s, s[:10], s.split('T')[0]):
                    try:
                        dt = datetime.strptime(cand, f)
                        break
                    except ValueError:
                        pass
                if dt:
                    break
    if dt is None:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def ns_class(h):
    h = h.lower()
    if h.endswith('.ns.cloudflare.com'):
        return 'cloudflare'
    if re.search(r'awsdns-\d+\.', h):
        return 'route53'
    if any(p in h for p in BP_DNS):
        return 'bp'
    if any(h == p or h.endswith('.' + p) for p in GENERIC_DNS):
        return 'generic'
    return 'custom'


def clean(values):
    """Drop dnstwist error markers like !ServFail."""
    return [v for v in (values or []) if isinstance(v, str) and not v.startswith('!')]


# --------------------------------------------------------------------------
# Network layer. Every outbound lookup lives here so it can be mocked.
# --------------------------------------------------------------------------
class _RedirectRecorder(urllib.request.HTTPRedirectHandler):
    max_redirections = 8

    def __init__(self):
        super().__init__()
        self.chain = []

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        self.chain.append(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class Net:
    def __init__(self, timeout=6.0, nameservers=None, useragent=None):
        self.timeout = timeout
        self.ua = useragent or ('Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 '
                                '(KHTML, like Gecko) Chrome/131.0 Safari/537.36')
        self._cache, self._locks = {}, {}
        self._glock = threading.Lock()
        self._rdap_nets = []
        self.reg_sem = threading.Semaphore(4)
        self.rdap_sem = threading.Semaphore(6)
        self.res = None
        self.sc_owners = SC.Owners(max(5, int(timeout * 2))) if SC is not None else None
        if HAVE_DNSPYTHON:
            ips = [n for n in (nameservers or []) if re.match(r'^[0-9a-fA-F:.]+$', n)]
            self.res = dns.resolver.Resolver(configure=not ips)
            if ips:
                self.res.nameservers = ips
            self.res.lifetime = timeout
            self.res.timeout = max(1.0, timeout / 2)

    def cached(self, key, fn):
        with self._glock:
            if key in self._cache:
                return self._cache[key]
            lock = self._locks.setdefault(key, threading.Lock())
        with lock:
            with self._glock:
                if key in self._cache:
                    return self._cache[key]
            try:
                val = fn()
            except Exception:
                val = None
            with self._glock:
                self._cache[key] = val
            return val

    # ---- DNS ----
    def resolve(self, name, rtype):
        return self.cached(('dns', name.lower(), rtype), lambda: self._resolve(name, rtype)) or []

    def _resolve(self, name, rtype):
        if self.res is None:
            if rtype in ('A', 'AAAA'):
                fam = socket.AF_INET if rtype == 'A' else socket.AF_INET6
                try:
                    return sorted({a[4][0] for a in socket.getaddrinfo(name, None, fam, socket.SOCK_STREAM)})
                except Exception:
                    return []
            return []
        try:
            ans = self.res.resolve(name, rtype)
        except Exception:
            return []
        out = set()
        for r in ans:
            if rtype in ('A', 'AAAA'):
                out.add(r.address)
            elif rtype == 'NS':
                out.add(str(r.target).rstrip('.').lower())
            elif rtype == 'MX':
                out.add(str(r.exchange).rstrip('.').lower())
            elif rtype == 'TXT':
                out.add(b''.join(r.strings).decode('utf-8', 'ignore'))
        return sorted(out)

    # ---- ASN via Team Cymru DNS ----
    def cymru(self, ip):
        addr = ipaddress.ip_address(ip)
        if addr.version == 4:
            q = '.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com'
        else:
            q = '.'.join(reversed(addr.exploded.replace(':', ''))) + '.origin6.asn.cymru.com'
        txt = self.resolve(q, 'TXT')
        if not txt:
            return None, None
        parts = [p.strip() for p in txt[0].split('|')]
        try:
            return int(parts[0].split()[0]), parts[1]
        except (ValueError, IndexError):
            return None, None

    def cymru_asname(self, asn):
        txt = self.resolve('AS{}.asn.cymru.com'.format(asn), 'TXT')
        if not txt:
            return None
        return txt[0].split('|')[-1].strip()

    # ---- HTTP JSON (RDAP) ----
    def get_json(self, url):
        req = urllib.request.Request(url, headers={'User-Agent': self.ua,
                                                   'Accept': 'application/rdap+json, application/json'})
        for attempt in range(3):
            try:
                with self.rdap_sem:
                    with urllib.request.urlopen(req, timeout=self.timeout + 4) as r:
                        return json.loads(r.read().decode('utf-8', 'ignore'))
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < 2:
                    time.sleep(2 + attempt * 3)
                    continue
                return None
            except Exception:
                return None
        return None

    # ---- RDAP IP ----
    def rdap_ip(self, ip):
        addr = ipaddress.ip_address(ip)
        with self._glock:
            for net, data in self._rdap_nets:
                if addr.version == net.version and addr in net:
                    return data
        data = self.cached(('rdapip', ip), lambda: self._rdap_ip(ip))
        if data and data.get('nets'):
            with self._glock:
                for n in data['nets']:
                    self._rdap_nets.append((ipaddress.ip_network(n, strict=False), data))
        return data

    def _rdap_ip(self, ip):
        j = self.get_json('https://rdap.org/ip/{}'.format(ip))
        return parse_rdap_ip(j) if j else None

    def ip_info(self, ip):
        return self.cached(('ipinfo', ip), lambda: self._ip_info(ip))

    def _ip_info(self, ip):
        info = {'ip': ip, 'asn': None, 'prefix': None, 'as_name': None, 'net_handle': None,
                'net_name': None, 'net_org': None, 'nets': [], 'entities': [], 'provider': None,
                'kind': None, 'shared': False, 'source': 'built in'}
        if self.sc_owners is not None:
            o = self.sc_owners.lookup(ip) or {}
            t = SC.Target(raw=ip, kind='ip', host=ip, ips=[ip])
            t.owners = {ip: o}
            prov = SC.match_provider(t)
            nets = [c.strip() for c in (o.get('cidr') or '').split(',') if c.strip()]
            asn = str(o.get('asn') or '')
            info.update(asn=int(asn) if asn.isdigit() else None, prefix=nets[0] if nets else None,
                        as_name=o.get('asn_name') or None, net_handle=o.get('netname') or None,
                        net_name=o.get('netname') or None, net_org=o.get('org') or None, nets=nets,
                        entities=list(o.get('entities') or []), source='scopecheck')
            if prov:
                info.update(provider=prov['name'], kind=prov['kind'], shared=True)
            return info
        asn, prefix = self.cymru(ip)
        if asn:
            info['asn'], info['prefix'] = asn, prefix
            info['as_name'] = self.cached(('asname', asn), lambda: self.cymru_asname(asn))
        rd = self.rdap_ip(ip)
        if rd:
            info['net_handle'], info['net_name'] = rd.get('handle'), rd.get('name')
            info['net_org'], info['nets'] = rd.get('org'), rd.get('nets', [])
        if prefix and prefix not in info['nets']:
            info['nets'] = info['nets'] + [prefix]
        prov = detect_provider(asn, info['as_name'], info['net_name'], info['net_org'])
        info['provider'], info['shared'] = prov, bool(prov)
        info['kind'] = PROVIDER_KIND.get(prov, 'hosting') if prov else None
        return info

    # ---- HTTP probe ----
    def fetch(self, url):
        rec = _RedirectRecorder()
        ctx = ssl._create_unverified_context()
        opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx), rec)
        req = urllib.request.Request(url, headers={'User-Agent': self.ua,
                                                   'Accept': 'text/html,*/*;q=0.8',
                                                   'Accept-Encoding': 'identity'})
        out = {'url': url, 'chain': rec.chain, 'status': None, 'final_url': url, 'body': ''}
        try:
            with opener.open(req, timeout=self.timeout) as r:
                out['status'], out['final_url'] = r.status, r.geturl()
                out['body'] = r.read(262144).decode('utf-8', 'ignore')
        except urllib.error.HTTPError as e:
            out['status'], out['final_url'] = e.code, (e.geturl() or url)
            try:
                out['body'] = e.read(65536).decode('utf-8', 'ignore')
            except Exception:
                pass
        except Exception as e:
            out['error'] = type(e).__name__
        return out

    def http_probe(self, domain, bases):
        return self.cached(('http', domain), lambda: analyse_http(
            [self.fetch('https://{}/'.format(domain)), self.fetch('http://{}/'.format(domain))],
            domain, bases))

    # ---- TLS ----
    def tls_probe(self, host, port=443, ip=None):
        return self.cached(('tls', host, port), lambda: self._tls_probe(host, port, ip))

    def _tls_probe(self, host, port, ip):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        try:
            with socket.create_connection((ip or host, port), timeout=self.timeout) as s:
                with ctx.wrap_socket(s, server_hostname=host) as ss:
                    der = ss.getpeercert(binary_form=True)
        except Exception:
            return None
        return parse_cert(der) if der else None

    # ---- Registration data: RDAP first, port 43 WHOIS fallback ----
    def domain_reg(self, domain):
        d = reg_domain(domain)
        return self.cached(('reg', d), lambda: self._domain_reg(d))

    def _domain_reg(self, d):
        with self.reg_sem:
            info, src = {}, None
            j = self.get_json('https://rdap.org/domain/{}'.format(d))
            if j:
                info, src = parse_rdap_domain(j), 'rdap'
                if not any(info.get(k) for k in ('registrant_org', 'registrant_name', 'registrant_email')):
                    for link in j.get('links', []) or []:
                        href = link.get('href', '')
                        if link.get('rel') == 'related' and '/domain/' in href:
                            j2 = self.get_json(href)
                            if j2:
                                extra = parse_rdap_domain(j2)
                                for k, v in extra.items():
                                    if v and not info.get(k):
                                        info[k] = v
                            break
            if not (info.get('registrar') or info.get('created')):
                text = self.whois43(d)
                if text:
                    w = parse_whois(text)
                    for k, v in w.items():
                        if v and not info.get(k):
                            info[k] = v
                    src = src or 'whois'
        if not info:
            return None
        info['source'] = src
        return finalize_reg(info)

    def _whois_query(self, server, q):
        try:
            with socket.create_connection((server, 43), timeout=self.timeout) as s:
                s.sendall(q.encode('idna') + b'\r\n')
                buf = b''
                while len(buf) < 131072:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    buf += chunk
            return buf.decode('utf-8', 'ignore')
        except Exception:
            return ''

    def whois43(self, d):
        tld = d.rsplit('.', 1)[-1]
        server = self.cached(('whoissrv', tld), lambda: (re.search(
            r'^whois:\s*(\S+)', self._whois_query('whois.iana.org', tld), re.M | re.I) or [None, None])[1])
        if not server:
            return ''
        text = self._whois_query(server, d)
        m = re.search(r'Registrar WHOIS Server:\s*(\S+)', text, re.I)
        if m:
            srv2 = re.sub(r'^https?://', '', m.group(1).lower()).strip('/')
            if srv2 and srv2 != server:
                text += '\n' + self._whois_query(srv2, d)
        return text


# --------------------------------------------------------------------------
# Parsers (pure functions, unit testable)
# --------------------------------------------------------------------------
def _vcard(ent):
    out = {}
    va = ent.get('vcardArray')
    if isinstance(va, list) and len(va) > 1 and isinstance(va[1], list):
        for item in va[1]:
            if isinstance(item, list) and len(item) >= 4:
                k, v = item[0], item[3]
                if isinstance(v, list):
                    v = ' '.join(str(x) for x in v if x)
                if k in ('fn', 'org', 'email', 'kind') and v and k not in out:
                    out[k] = str(v).strip()
    return out


def _walk(ents):
    for e in ents or []:
        if isinstance(e, dict):
            yield e
            yield from _walk(e.get('entities'))


def parse_rdap_ip(j):
    nets = []
    for c in j.get('cidr0_cidrs', []) or []:
        pre = c.get('v4prefix') or c.get('v6prefix')
        if pre and c.get('length') is not None:
            nets.append(str(ipaddress.ip_network('{}/{}'.format(pre, c['length']), strict=False)))
    if not nets and j.get('startAddress') and j.get('endAddress'):
        try:
            nets = [str(n) for n in ipaddress.summarize_address_range(
                ipaddress.ip_address(j['startAddress']), ipaddress.ip_address(j['endAddress']))]
        except Exception:
            pass
    org = None
    ents = list(_walk(j.get('entities')))
    for e in ents:
        if 'registrant' in (e.get('roles') or []):
            v = _vcard(e)
            org = v.get('org') or v.get('fn')
            if org:
                break
    if not org:
        for e in ents:
            v = _vcard(e)
            if v.get('fn'):
                org = v.get('org') or v['fn']
                break
    return {'handle': j.get('handle'), 'name': j.get('name'), 'org': org, 'nets': nets}


def parse_rdap_domain(j):
    out = {}
    for ev in j.get('events', []) or []:
        if ev.get('eventAction') == 'registration':
            out['created'] = parse_date(ev.get('eventDate'))
    for e in _walk(j.get('entities')):
        roles = e.get('roles') or []
        v = _vcard(e)
        if 'registrar' in roles and not out.get('registrar'):
            out['registrar'] = v.get('fn') or v.get('org') or e.get('handle')
        if 'registrant' in roles:
            org = v.get('org') or (v.get('fn') if v.get('kind') == 'org' else None)
            out.setdefault('registrant_org', org)
            out.setdefault('registrant_name', v.get('fn'))
            out.setdefault('registrant_email', v.get('email'))
    if j.get('redacted'):
        out['redacted_flag'] = True
    return out


def parse_whois(text):
    def g(*pats):
        for p in pats:
            m = re.search(p, text, re.I | re.M)
            if m and m.group(1).strip():
                return m.group(1).strip()
        return None
    return {
        'registrar': g(r'^\s*Registrar(?: Name)?:[ \t]*(\S.*)$', r'^\s*Registrar:\s*\n\s*(\S.*)$',
                       r'^\s*Sponsoring Registrar:\s*(\S.*)$'),
        'created': parse_date(g(r'^\s*(?:Creation Date|Created(?: On)?|Registered(?: On)?|'
                                r'Registration Time|Domain Registration Date|created)\s*:\s*(\S.*)$',
                                r'^\s*Registered on:\s*(\S.*)$')),
        'registrant_org': g(r'^\s*Registrant Organi[sz]ation\s*:\s*(\S.*)$',
                            r'^\s*Registrant:\s*\n\s*(\S.*)$'),
        'registrant_name': g(r'^\s*Registrant Name\s*:\s*(\S.*)$'),
        'registrant_email': g(r'^\s*Registrant (?:Contact )?Email\s*:\s*(\S.*)$'),
    }


def finalize_reg(info):
    redacted = bool(info.pop('redacted_flag', False))
    for k in ('registrant_org', 'registrant_name', 'registrant_email'):
        v = info.get(k)
        if v and REDACT_RE.search(v):
            info[k] = None
            redacted = True
    if not any(info.get(k) for k in ('registrant_org', 'registrant_name', 'registrant_email')):
        redacted = True
    info['redacted'] = redacted
    return info


def parse_cert(der):
    out = {'san': [], 'subject_o': None, 'subject_cn': None, 'issuer_o': None,
           'not_before': None, 'fingerprint': None}
    if HAVE_CRYPTO:
        try:
            c = x509.load_der_x509_certificate(der)
        except Exception:
            return None
        out['fingerprint'] = c.fingerprint(hashes.SHA256()).hex()
        def attr(name, oid):
            a = name.get_attributes_for_oid(oid)
            return a[0].value if a else None
        out['subject_o'] = attr(c.subject, NameOID.ORGANIZATION_NAME)
        out['subject_cn'] = attr(c.subject, NameOID.COMMON_NAME)
        out['issuer_o'] = attr(c.issuer, NameOID.ORGANIZATION_NAME)
        try:
            out['not_before'] = c.not_valid_before_utc
        except AttributeError:
            out['not_before'] = c.not_valid_before.replace(tzinfo=timezone.utc)
        try:
            ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            out['san'] = [n.lower() for n in ext.value.get_values_for_type(x509.DNSName)]
        except x509.ExtensionNotFound:
            pass
        return out
    # Fallback without the cryptography package
    import hashlib
    import tempfile
    out['fingerprint'] = hashlib.sha256(der).hexdigest()
    try:
        with tempfile.NamedTemporaryFile('w', suffix='.pem', delete=False) as f:
            f.write(ssl.DER_cert_to_PEM_cert(der))
            path = f.name
        d = ssl._ssl._test_decode_cert(path)
        os.unlink(path)
    except Exception:
        return out
    for rdn in d.get('subject', ()):
        for k, v in rdn:
            if k == 'organizationName':
                out['subject_o'] = v
            if k == 'commonName':
                out['subject_cn'] = v
    for rdn in d.get('issuer', ()):
        for k, v in rdn:
            if k == 'organizationName':
                out['issuer_o'] = v
    out['san'] = [v.lower() for k, v in d.get('subjectAltName', ()) if k == 'DNS']
    out['not_before'] = parse_date(d.get('notBefore'))
    return out


TITLE_RE = re.compile(r'<title[^>]*>(.*?)</title>', re.I | re.S)
LOGIN_RE = re.compile(r'<input[^>]+type\s*=\s*["\']?password', re.I)
META_RE = re.compile(r'''(?:http-equiv\s*=\s*["']?refresh[^>]*url\s*=\s*['"]?|'''
                     r'''location(?:\.href)?\s*=\s*['"]|location\.replace\(\s*['"])'''
                     r'''https?://([^/'"\s>:]+)''', re.I)


def analyse_http(fetches, domain, bases):
    res = {'to_client': False, 'status': None, 'final_url': None, 'redirect_host': None,
           'title': None, 'login': False, 'parked': False}
    for f in fetches:
        if f.get('status') is None and f.get('error') and not f.get('chain'):
            continue
        body = f.get('body') or ''
        m = TITLE_RE.search(body)
        title = ' '.join(html.unescape(m.group(1)).split())[:80] if m else None
        low = body.lower()
        final_host = (urllib.parse.urlparse(f['final_url']).hostname or '').lower()
        page = dict(status=f['status'], final_url=f['final_url'], title=title,
                    login=bool(LOGIN_RE.search(body)),
                    parked=any(p in low for p in PARKING_HTML) or any(p in final_host for p in PARKING_NS))
        # Hosts the request was sent to, excluding the starting host itself
        hosts = [urllib.parse.urlparse(u).hostname or '' for u in f['chain'] + [f['final_url']]]
        hosts += META_RE.findall(body[:65536])
        hosts = [h.lower() for h in hosts if h and h.lower() != domain]
        hit = [h for h in hosts if host_in(h, bases)]
        if hit:
            res.update(page, to_client=True, redirect_host=hit[-1])
            return res
        if res['status'] is None:
            res.update(page)
            if final_host and reg_domain(final_host) != reg_domain(domain):
                res['redirect_host'] = final_host
    return res


# --------------------------------------------------------------------------
# Baseline
# --------------------------------------------------------------------------
def load_scopecheck_results(path):
    """
    Read a scopecheck output folder (or its results.json). Returns the client
    assets scopecheck already verified: in scope IPs with their tier, netblocks
    registered to the client, owner org names and client domains.
    """
    p = path if os.path.isfile(path) else os.path.join(path, 'results.json')
    with open(p, encoding='utf-8') as f:
        rows = json.load(f)
    s = {'path': p, 'ips': {}, 'nets': set(), 'orgs': set(), 'domains': set()}
    for t in rows:
        tier = t.get('tier')
        if tier not in ('green', 'blue'):
            continue
        for ip in t.get('ips') or []:
            try:
                if not ipaddress.ip_address(ip).is_global:
                    continue
            except ValueError:
                continue
            if s['ips'].get(ip) != 'green':
                s['ips'][ip] = tier
        if tier == 'green' and (t.get('base_note') or '').startswith('Registered to the client'):
            for o in (t.get('owners') or {}).values():
                for c in (o.get('cidr') or '').split(','):
                    try:
                        s['nets'].add(str(ipaddress.ip_network(c.strip(), strict=False)))
                    except ValueError:
                        pass
                if o.get('org'):
                    s['orgs'].add(o['org'])
        if t.get('client_domain_hit'):
            s['domains'].add(reg_domain(t['client_domain_hit']))
    md = os.path.join(os.path.dirname(p), 'mail_domains.txt')
    if os.path.isfile(md):
        with open(md, encoding='utf-8') as f:
            s['domains'] |= {x.strip().lower() for x in f if x.strip()}
    s['domains'].discard('')
    return s


def find_scopecheck_results():
    """
    Newest scopecheck_*/results.json, searched in the scopecheck.py folder,
    the sibling ../IP-Scope-Checker repo, this folder, the current folder and
    every other sibling folder. Returns the path or None.
    """
    import glob
    parent = os.path.dirname(HERE)
    roots = ([os.path.dirname(SC_PATH)] if SC_PATH else []) + \
        [os.path.join(parent, 'IP-Scope-Checker'), HERE, os.getcwd()] + sorted(glob.glob(os.path.join(parent, '*')))
    found, seen = set(), set()
    for r in roots:
        r = os.path.abspath(r)
        if r in seen or not os.path.isdir(r):
            continue
        seen.add(r)
        found |= set(glob.glob(os.path.join(r, 'scopecheck_*', 'results.json')))
    return max(found, key=os.path.getmtime) if found else None


def build_baseline(net, domain, org_hints, known, extra_domains=(), scope=None):
    b = {'domain': domain, 'base': reg_domain(domain)}
    scope = scope or {'ips': {}, 'nets': set(), 'orgs': set(), 'domains': set()}
    org_hints = list(org_hints) + sorted(o for o in scope['orgs'] if o not in org_hints)
    bases = {b['base'], domain} | {reg_domain(k) for k in known} | set(known)
    bases |= {d.lower().strip('.') for d in extra_domains} | scope['domains']
    ips = set(net.resolve(domain, 'A')) | set(net.resolve(domain, 'AAAA'))
    www = 'www.' + b['base']
    ips |= set(net.resolve(www, 'A')) | set(net.resolve(www, 'AAAA'))
    http = net.http_probe(domain, bases)
    canon = None
    if http and http.get('redirect_host') and not http.get('to_client'):
        h = http['redirect_host']
        if not any(h == x or h.endswith('.' + x) for x in NOT_CLIENT_HOSTS):
            canon = reg_domain(h)
            bases.add(canon)
            ips |= set(net.resolve(h, 'A')) | set(net.resolve(h, 'AAAA'))
    b['canonical'] = canon
    b['bases'] = sorted(bases)
    b['http'] = http
    b['ns'] = sorted(set(net.resolve(b['base'], 'NS')) | set(net.resolve(domain, 'NS')))
    b['mx'] = sorted(set(clean(net.resolve(domain, 'MX'))) - {''})
    b['cert'] = net.tls_probe(domain) or net.tls_probe(www)
    b['reg'] = net.domain_reg(b['base'])
    b['ip_info'] = [net.ip_info(ip) for ip in sorted(ips)]
    b['ip_info'] = [i for i in b['ip_info'] if i]
    b['ips'] = sorted(ips | set(scope['ips']))
    b['scope_ips'] = dict(scope['ips'])
    b['asns'] = sorted({i['asn'] for i in b['ip_info'] if i['asn'] and not i['shared']})
    b['all_asns'] = sorted({i['asn'] for i in b['ip_info'] if i['asn']})
    b['nets'] = sorted({n for i in b['ip_info'] if not i['shared'] for n in i['nets']} | scope['nets'])
    b['scope_file'] = scope.get('path')
    b['scope_nets'] = len(scope['nets'])
    b['host_orgs'] = sorted({i['net_org'] for i in b['ip_info'] if i['net_org'] and not i['shared']})
    orgs = list(org_hints)
    reg = b['reg'] or {}
    if reg.get('registrant_org') and not detect_provider(None, reg['registrant_org']):
        orgs.append(reg['registrant_org'])
    cert = b['cert'] or {}
    if cert.get('subject_o') and not detect_provider(None, cert['subject_o']):
        orgs.append(cert['subject_o'])
    b['orgs'] = sorted(set(orgs))
    b['org_hints'] = list(org_hints)
    b['title'] = (http or {}).get('title')
    return b


def print_baseline(b):
    log(bold('[baseline] {}'.format(b['domain'])))
    log('  ownership {}'.format('scopecheck.py ({})'.format(SC_PATH) if SC is not None else 'built in (scopecheck.py not found)'))
    if b.get('scope_file'):
        n_green = sum(1 for v in b['scope_ips'].values() if v == 'green')
        try:
            hours = (time.time() - os.path.getmtime(b['scope_file'])) / 3600
            age = '{:.0f}h old'.format(hours) if hours < 48 else '{:.0f} days old'.format(hours / 24)
        except OSError:
            age = 'age unknown'
        log('  scope     {} IPs from scopecheck ({} testable, {} with caveats), {} client netblocks'.format(
            len(b['scope_ips']), n_green, len(b['scope_ips']) - n_green, b.get('scope_nets', 0)))
        log('  scope run {} ({})'.format(os.path.dirname(b['scope_file']), age))
    else:
        log('  scope run ' + dim('none found (run scopecheck first, or pass --scopecheck DIR)'))
    extra = [d for d in b['bases'] if d not in (b['domain'], b['base'])]
    if extra:
        log('  domains   {}'.format(', '.join(extra[:8]) + (' ...' if len(extra) > 8 else '')))
    for i in b['ip_info']:
        tag = '{} AS{} {}'.format(i['ip'], i['asn'] or '?', i['provider'] or i['as_name'] or i['net_org'] or '')
        log('  ip        {}{}'.format(tag.strip(), dim('  shared') if i['shared'] else ''))
    if not b['ip_info']:
        log('  ip        ' + yel('none resolved'))
    log('  ns        {}'.format(', '.join(b['ns']) or '-'))
    log('  mx        {}'.format(', '.join(b['mx']) or '-'))
    h = b['http'] or {}
    if h.get('status'):
        log('  web       {} [{}] {}'.format(h.get('final_url'), h.get('status'), h.get('title') or ''))
    if b['canonical']:
        log('  canonical {} (added as a client domain)'.format(b['canonical']))
    c = b['cert'] or {}
    if c:
        log('  cert      O={} CN={} SANs={}'.format(c.get('subject_o') or '-', c.get('subject_cn') or '-', len(c.get('san', []))))
    r = b['reg'] or {}
    if r:
        who = r.get('registrant_org') or r.get('registrant_name') or 'redacted'
        log('  registrar {}   registrant {}'.format(r.get('registrar') or '-', who))
    log('  orgs      {}'.format(', '.join(b['orgs']) or dim('none (pass --org to strengthen matching)')))


# --------------------------------------------------------------------------
# Correlation
# --------------------------------------------------------------------------
def correlate(net, b, entry, opts):
    d = entry['domain'].lower()
    bases = b['bases']
    own, thr, info = {}, {}, []

    def O(cat, key, tag):
        pts = W[key]
        if pts > own.get(cat, (0, '', ''))[0]:
            own[cat] = (pts, tag, key)

    def T(cat, key, tag):
        pts = W[key]
        if cat not in thr or abs(pts) > abs(thr[cat][0]):
            thr[cat] = (pts, tag, key)

    a = clean(entry.get('dns_a')) + clean(entry.get('dns_aaaa'))
    ns = sorted(set(clean(entry.get('dns_ns'))))
    raw_mx = [m for m in (entry.get('dns_mx') or []) if isinstance(m, str) and not m.startswith('!')]
    mx = sorted(set(raw_mx) - {''})
    r = {'domain': d, 'fuzzer': entry.get('fuzzer', ''), 'ips': a, 'ns': ns, 'mx': mx,
         'mx_spy': bool(entry.get('mx_spy')), 'hosting': None}
    parked = False

    # 1. IP by netblock and ASN, not exact address
    best_host = None
    for ip in a[:6]:
        i = net.ip_info(ip)
        if not i:
            continue
        best_host = best_host or i
        prov = i['provider']
        if b.get('scope_ips', {}).get(ip) == 'green':
            O('ip', 'ip_scope', 'IP is in client scope per scopecheck ({})'.format(ip))
        elif ip in b['ips']:
            kind = i.get('kind')
            if not i['shared']:
                O('ip', 'ip_exact', 'same IP as client ({})'.format(ip))
            elif kind == 'cloud':
                O('ip', 'ip_exact_cloud', 'same {} IP as client ({})'.format(prov, ip))
            elif kind == 'hosting':
                O('ip', 'ip_exact_hosting', 'same {} hosting IP as client, may be shared'.format(prov))
            else:
                O('ip', 'ip_exact_shared', 'same IP as client on shared {}'.format(prov))
        if not i['shared']:
            addr = ipaddress.ip_address(ip)
            for n in b['nets']:
                nn = ipaddress.ip_network(n, strict=False)
                if addr.version == nn.version and addr in nn:
                    O('ip', 'ip_netblock', 'IP in client netblock {}'.format(i['net_handle'] or n))
                    break
            if i['asn'] and i['asn'] in b['asns']:
                O('ip', 'ip_asn', 'same ASN as client AS{}'.format(i['asn']))
            if i['net_org'] and org_match(i['net_org'], b['host_orgs']):
                O('ip', 'ip_hostorg', 'same hosting org as client ({})'.format(i['net_org']))
        elif i['asn'] and i['asn'] in b['all_asns']:
            O('ip', 'ip_asn_shared', 'same shared provider as client ({})'.format(prov))
        if owner_matches_client(i, b['org_hints']):
            O('ip', 'ip_org_hint', 'netblock registered to {}'.format(i['net_org'] or i['as_name']))
    if best_host:
        r['hosting'] = '{} AS{} {}'.format(best_host['ip'], best_host['asn'] or '?',
                                           best_host['provider'] or best_host['as_name'] or best_host['net_org'] or '').strip()
        r['ip_info'] = best_host

    # 2. Nameserver overlap
    overlap = set(ns) & set(b['ns'])
    if any(host_in(n, bases) for n in ns):
        O('ns', 'ns_client_domain', 'NS on client domain')
    elif overlap:
        kinds = {ns_class(n) for n in overlap}
        if 'route53' in kinds:
            if set(ns) == set(b['ns']):
                O('ns', 'ns_route53_set', 'same Route53 delegation set as client')
        elif 'cloudflare' in kinds:
            if set(ns) == set(b['ns']):
                O('ns', 'ns_cloudflare_pair', 'same Cloudflare NS pair as client')
            else:
                O('ns', 'ns_partial_pair', 'one Cloudflare NS shared with client')
        elif 'custom' in kinds:
            O('ns', 'ns_custom', 'shares client NS {}'.format(sorted(overlap)[0]))
        elif 'bp' in kinds:
            O('ns', 'ns_bp_same', 'same brand protection DNS as client')
        else:
            O('ns', 'ns_generic', 'shares generic DNS host')
    if 'ns' not in own and any(ns_class(n) == 'bp' for n in ns):
        O('ns', 'ns_bp', 'brand protection DNS')
    if any(p in n for n in ns for p in PARKING_NS):
        parked = True

    # 3. MX
    if '' in raw_mx and not mx:
        O('mx', 'mx_null', 'null MX, mail disabled')
    client_mx = False
    for m in mx:
        if host_in(m, bases):
            O('mx', 'mx_client_domain', 'MX on client domain')
            client_mx = True
        elif m in b['mx']:
            if any(s in m for s in SHARED_MX):
                O('mx', 'mx_same_shared', 'same shared mail service as client')
            else:
                O('mx', 'mx_same_tenant', 'same MX as client ({})'.format(m))
                client_mx = True
    if mx and not client_mx:
        T('mx', 't_mx_live', 'live MX {}'.format(mx[0]))
    if r['mx_spy'] and not client_mx:
        T('mxspy', 't_mx_spy', 'MX accepts mail for any recipient')

    # 4. HTTP redirect, login, clone, parking
    if a and not opts.no_http:
        h = net.http_probe(d, bases) or {}
        r['http'] = {k: h.get(k) for k in ('status', 'final_url', 'title', 'login', 'parked', 'redirect_host', 'to_client')}
        if h.get('to_client'):
            O('http', 'http_redirect', 'redirects to client ({})'.format(h.get('redirect_host')))
        else:
            if h.get('login'):
                T('login', 't_login', 'serves a login form')
            t_l, b_l = (h.get('title') or '').strip().lower(), (b.get('title') or '').strip().lower()
            if t_l and t_l == b_l and len(t_l) >= 6 and t_l not in GENERIC_TITLES:
                T('clone', 't_clone', 'serves the client page title "{}"'.format(h['title'][:40]))
            if h.get('parked'):
                parked = True
            if h.get('redirect_host'):
                info.append('redirects to {}'.format(h['redirect_host']))

    # 5. TLS certificate
    if a and not opts.no_tls:
        t = net.tls_probe(d, ip=a[0] if ':' not in a[0] else None)
        if t:
            r['cert'] = {'subject_o': t.get('subject_o'), 'issuer_o': t.get('issuer_o'),
                         'san_count': len(t.get('san', [])), 'not_before': t.get('not_before')}
            bc = b.get('cert') or {}
            if bc.get('fingerprint') and t.get('fingerprint') == bc['fingerprint']:
                O('tls', 'tls_same_cert', 'same certificate as client')
            else:
                hit = next((s for s in t.get('san', []) if host_in(s.lstrip('*.'), bases)), None)
                if hit:
                    O('tls', 'tls_san', 'cert SAN covers {}'.format(hit))
                elif t.get('subject_o') and org_match(t['subject_o'], b['orgs']):
                    O('tls', 'tls_org', 'cert org matches ({})'.format(t['subject_o']))

    # 6. Registration data
    if not opts.no_whois:
        g = net.domain_reg(d)
        if g:
            r['reg'] = {k: g.get(k) for k in ('registrar', 'created', 'registrant_org', 'registrant_email', 'redacted', 'source')}
            em = g.get('registrant_email') or ''
            if '@' in em and host_in(em.split('@')[-1], bases):
                O('reg', 'reg_email', 'registrant email on client domain')
            else:
                hit = org_match(g.get('registrant_org') or '', b['orgs']) or \
                      org_match(g.get('registrant_name') or '', b['orgs'])
                if hit:
                    O('reg', 'reg_org', 'registrant matches {}'.format(hit))
            bp = is_bp_registrar(g.get('registrar'))
            if bp:
                base_bp = is_bp_registrar((b.get('reg') or {}).get('registrar'))
                if base_bp == bp:
                    O('registrar', 'registrar_bp_same', 'same brand protection registrar as client ({})'.format(g['registrar']))
                else:
                    O('registrar', 'registrar_bp', 'brand protection registrar ({})'.format(g['registrar']))
            created = parse_date(g.get('created'))
            if created:
                age = (datetime.now(timezone.utc) - created).days
                r['age_days'] = age
                if age <= 30:
                    T('age', 't_age_30', 'registered {}d ago'.format(age))
                elif age <= 90:
                    T('age', 't_age_90', 'registered {}d ago'.format(age))
                elif age <= 365:
                    T('age', 't_age_365', 'registered {}d ago'.format(age))
            if g.get('redacted'):
                info.append('registrant redacted')

    if parked:
        T('parked', 't_parked', 'parked')

    owner = min(100, sum(v[0] for v in own.values()))
    threat = max(0, min(100, sum(v[0] for v in thr.values())))
    if owner >= CLIENT_MIN and owner >= threat:
        verdict = 'CLIENT-OWNED'
        conf = 'high' if owner >= 70 else 'med' if owner >= 50 else 'low'
    elif owner < CLIENT_MIN and (threat >= THREAT_MIN or any(v[2] in DANGER_KEYS for v in thr.values())):
        verdict = 'LIKELY MALICIOUS'
        conf = 'high' if threat >= 70 else 'med' if threat >= 55 else 'low'
    else:
        verdict, conf = 'UNKNOWN', '-'
        if owner >= CLIENT_MIN:
            info.append('conflicting signals')
        elif owner >= 20:
            info.append('weak client signals')

    known = opts.known_set
    if d in known or reg_domain(d) in known:
        if verdict != 'CLIENT-OWNED':
            info.append('tool inferred {} but client list says owned'.format(verdict.lower()))
        verdict, conf = 'CLIENT-OWNED', 'confirmed'

    o_sorted = sorted(own.values(), reverse=True)
    t_sorted = sorted(thr.values(), reverse=True)
    ev = ['+{} {}'.format(p, t) for p, t, _ in o_sorted]
    ev += ['{}{} {}'.format('+' if p >= 0 else '', p, t) for p, t, _ in t_sorted]

    # one short reason for the normal (non debug) output
    def short(key):
        if key.startswith('t_age_'):
            return 'registered {}d ago'.format(r.get('age_days', '?'))
        return SHORT.get(key, key)
    if verdict == 'CLIENT-OWNED' and conf == 'confirmed':
        reason = [('on client list', False)]
    elif verdict == 'CLIENT-OWNED':
        reason = [(short(k), False) for p, _, k in o_sorted if p >= 10][:2]
    else:
        reason = [(short(k), k in DANGER_KEYS) for p, _, k in t_sorted if p > 0][:3]
        if not reason and parked:
            reason = [('parked or for sale', False)]
        if not reason:
            parent = reg_domain(d)
            label = d[:-(len(parent) + 1)] if d.endswith('.' + parent) else ''
            if label and r['fuzzer'] == 'subdomain':
                reason.append(('sits under {}'.format(parent), False))
            if not (a or ns or mx):
                reason.append(('DNS lookup failed', False))
            elif not reason:
                reason.append(('no link to client found', False))
    r.update(owner=owner, threat=threat, verdict=verdict, confidence=conf,
             owner_evidence=[v[1] for v in o_sorted], threat_evidence=[v[1] for v in t_sorted],
             evidence=ev, notes=info, parked=parked, reason=reason)
    return r


# --------------------------------------------------------------------------
# dnstwist driver
# --------------------------------------------------------------------------
def run_dnstwist(args):
    if dnstwist is None:
        log(red('[!] dnstwist not found. apt install dnstwist, pip install dnstwist, or drop dnstwist.py beside this script.'))
        sys.exit(2)
    if not HAVE_DNSPYTHON:
        log(yel('[!] dnspython missing: dnstwist cannot pull NS or MX, and the MX honeypot check is disabled.'))
    kw = dict(domain=args.domain, registered=True, format='null', all=True, threads=args.threads)
    if not args.no_mxcheck:
        kw['mxcheck'] = True
    for k in ('fuzzers', 'dictionary', 'tld', 'nameservers'):
        if getattr(args, k):
            kw[k] = getattr(args, k)
    done = threading.Event()

    def ticker():
        t0 = time.time()
        while not done.wait(1):
            if sys.stderr.isatty():
                log('\r[*] dnstwist generating and resolving lookalikes {:>4}s'.format(int(time.time() - t0)), end='')
    th = threading.Thread(target=ticker, daemon=True)
    th.start()
    try:
        rows = dnstwist.run(**kw) or []
    except Exception as e:
        done.set()
        log(red('\n[!] dnstwist error: {}'.format(e)))
        sys.exit(2)
    finally:
        done.set()
        if sys.stderr.isatty():
            log('')
    return rows


# --------------------------------------------------------------------------
# Output
# --------------------------------------------------------------------------
ORDER = {'LIKELY MALICIOUS': 0, 'UNKNOWN': 1, 'CLIENT-OWNED': 2}


def tag_of(r):
    """Display tag and colour: red THREAT, yellow UNKNOWN, blue LIKELY CLIENT, green CLIENT."""
    v, c = r['verdict'], r['confidence']
    if v == 'LIKELY MALICIOUS':
        return 'Threat', red
    if v == 'UNKNOWN':
        return 'Unknown', yel
    if c == 'confirmed':
        return 'Confirmed', grn
    if c == 'low':
        return 'Likely client', blu
    return 'Client', grn


def reason_text(r, colour=True):
    """Reasons joined into one phrase that starts with a capital letter."""
    parts = []
    for i, (t, is_red) in enumerate(r['reason']):
        if i == 0:
            t = t[:1].upper() + t[1:]
        parts.append(red(t) if (is_red and colour) else t)
    return ', '.join(parts)


def sort_key(r):
    rank = {'Threat': 0, 'Unknown': 1, 'Likely client': 2, 'Client': 3, 'Confirmed': 4}[tag_of(r)[0]]
    return (rank, -r['threat'], -r['owner'], r['fuzzer'], r['domain'])


def _cut(s, n):
    return s if len(s) <= n else s[:n - 1] + '~'


def print_table(results, debug=False):
    """dnstwist style lines with the ownership tag at the end."""
    if not results:
        print('No registered lookalikes found.')
        return
    rows = []
    for r in results:
        ip = (r['ips'] or ['-'])[0]
        ns = 'NS:' + _cut(r['ns'][0], 32) if r['ns'] else ''
        mx = 'MX:' + _cut(r['mx'][0], 32) if r['mx'] else ''
        rows.append((r, ip, ns, mx))
    wd = max(len(r['domain']) for r in results) + 1
    wi = max(len(x[1]) for x in rows) + 1
    wn = max(len(x[2]) for x in rows) + 1
    wm = max(len(x[3]) for x in rows) + 1
    for r, ip, ns, mx in rows:
        tag, col = tag_of(r)
        reason = col(reason_text(r, colour=False)) if r['reason'] else ''
        print('{} {:<{wi}} {:<{wn}} {:<{wm}} {} {}'.format(
            Col.c('94', r['domain'].ljust(wd)), ip, ns, mx, col(tag.ljust(13)), reason,
            wi=wi, wn=wn, wm=wm).rstrip())
        if debug:
            print(dim('    {}  owner {} threat {}  {}  {}'.format(
                r['fuzzer'], r['owner'], r['threat'], r['hosting'] or 'no A record',
                '; '.join(r['evidence'] + r['notes']) or 'no signals')))


def print_brief_baseline(b):
    own = 'scopecheck' if SC is not None else 'built in'
    scope = 'none'
    if b.get('scope_file'):
        try:
            hours = (time.time() - os.path.getmtime(b['scope_file'])) / 3600
            age = '{:.0f}h old'.format(hours) if hours < 48 else '{:.0f} days old'.format(hours / 24)
        except OSError:
            age = '?'
        scope = '{} ({})'.format(os.path.basename(os.path.dirname(b['scope_file'])), age)
    log('{}  ownership: {}  scopecheck run: {}'.format(bold(b['domain']), own, scope))
    if not b['ip_info'] and not b['ns']:
        log(red('[!] {} did not resolve. Check the domain or your DNS before trusting the ownership tags.'.format(b['domain'])))


CAVEAT_SHORT = 'Ownership tags are inferred. Confirm them against the client\'s own list of registered domains.'
CAVEAT = ('Ownership is inferred, not proven. Registrant data is often redacted, so these verdicts '
          'rest on infrastructure, certificate, redirect and mail signals. Confirm every verdict '
          'against the client\'s own list of registered domains before reporting.')


def main(argv=None):
    p = argparse.ArgumentParser(
        prog='dnstwistturbo.py',
        description='dnstwist plus ownership correlation: separates client defensive registrations from real lookalike threats.')
    p.add_argument('domain', help='client real domain, for example acme.com')
    p.add_argument('-c', '--client', '--org', dest='org', action='append', default=[], metavar='NAME',
                   help='client name as it may appear in WHOIS or RDAP, repeatable (same as scopecheck -c)')
    p.add_argument('-d', '--domain', dest='extra_domains', action='append', default=[], metavar='DOMAIN',
                   help='other client domain, repeatable (same as scopecheck -d)')
    p.add_argument('--scopecheck', metavar='DIR', nargs='?', const='auto',
                   help='scopecheck output folder or results.json (default, or with no value: newest scopecheck_* folder found automatically)')
    p.add_argument('--no-scopecheck-results', action='store_true',
                   help='do not look for or use scopecheck results')
    p.add_argument('--scopecheck-py', metavar='FILE', help='path to scopecheck.py if it is not beside this script')
    p.add_argument('--known', metavar='FILE', help='client supplied list of their registered domains, one per line')
    p.add_argument('--from-json', metavar='FILE', help='use existing dnstwist JSON instead of running dnstwist')
    p.add_argument('-o', '--outdir', default='.', help='directory for output files (default: current)')
    p.add_argument('--list', action='store_true', help='print only unknown and malicious domains to stdout, for piping')
    p.add_argument('--json', action='store_true', help='print full JSON results to stdout')
    p.add_argument('--no-files', action='store_true', help='do not write output files')
    p.add_argument('-t', '--threads', type=int, default=32, help='dnstwist resolver threads (default 32)')
    p.add_argument('-w', '--workers', type=int, default=20, help='correlation workers (default 20)')
    p.add_argument('--timeout', type=float, default=6.0, help='per request timeout in seconds (default 6)')
    p.add_argument('--fuzzers', help='dnstwist fuzzers, comma separated')
    p.add_argument('--dictionary', metavar='FILE', help='dnstwist dictionary file')
    p.add_argument('--tld', metavar='FILE', help='dnstwist TLD swap file')
    p.add_argument('--nameservers', help='DNS servers, comma separated (passed to dnstwist too)')
    p.add_argument('--no-http', action='store_true', help='skip HTTP redirect and content checks')
    p.add_argument('--no-tls', action='store_true', help='skip TLS certificate checks')
    p.add_argument('--no-whois', action='store_true', help='skip RDAP and WHOIS registration lookups')
    p.add_argument('--no-mxcheck', action='store_true', help='skip the dnstwist MX honeypot check (port 25)')
    p.add_argument('--available', action='store_true',
                   help='also list unregistered lookalikes the client could register defensively')
    p.add_argument('--debug', action='store_true', help='show the baseline, scores and full evidence for every domain')
    p.add_argument('--no-color', action='store_true')
    p.add_argument('--version', action='version', version=__version__)
    args = p.parse_args(argv)

    Col.on = sys.stdout.isatty() and not args.no_color and not args.list and not args.json

    dom = args.domain.strip().lower()
    if '://' in dom:
        dom = urllib.parse.urlparse(dom).hostname or dom
    dom = dom.split('/')[0].strip('.')
    try:
        dom = dom.encode('idna').decode()
    except Exception:
        pass
    args.domain = dom

    known = set()
    if args.known:
        with open(args.known, encoding='utf-8') as f:
            for line in f:
                line = line.strip().lower().split('#')[0].strip()
                if line:
                    known.add(line)
    args.known_set = known

    # comma separated values work the same way they do in scopecheck
    args.org = [x.strip() for c in args.org for x in c.split(',') if x.strip()]
    args.extra_domains = [x.strip().lower() for c in args.extra_domains for x in c.split(',') if x.strip()]

    load_scopecheck(args.scopecheck_py)
    scope = None
    if args.scopecheck in (None, 'auto') and not args.no_scopecheck_results:
        args.scopecheck = find_scopecheck_results()
    elif args.scopecheck == 'auto':
        args.scopecheck = None
    if args.scopecheck:
        try:
            scope = load_scopecheck_results(args.scopecheck)
        except (OSError, ValueError) as e:
            log(red('[!] cannot read scopecheck results from {}: {}'.format(args.scopecheck, e)))
            sys.exit(2)

    net = Net(timeout=args.timeout, nameservers=(args.nameservers or '').split(',') if args.nameservers else None)

    dbg = (lambda m: log(m)) if args.debug else (lambda m: None)
    t0 = time.time()
    base = build_baseline(net, dom, args.org, known, args.extra_domains, scope)
    if args.debug:
        log(bold('dnstwistturbo {}'.format(__version__)))
        print_baseline(base)
    else:
        log('')
        print_brief_baseline(base)

    if args.from_json:
        with open(args.from_json, encoding='utf-8') as f:
            rows = json.load(f)
        dbg('[*] loaded {} rows from {}'.format(len(rows), args.from_json))
    else:
        rows = run_dnstwist(args)

    look, available = [], []
    for row in rows:
        d = (row.get('domain') or '').lower()
        if not d or row.get('fuzzer') == '*original' or d == dom:
            continue
        if not any(clean(row.get(k)) or row.get(k) for k in ('dns_a', 'dns_aaaa', 'dns_ns', 'dns_mx')):
            available.append(row)
            continue
        look.append(row)
    dbg('[*] {} registered lookalikes, correlating with {} workers'.format(len(look), args.workers))

    results, n = [], 0
    with cf.ThreadPoolExecutor(max_workers=max(1, args.workers)) as ex:
        futs = {ex.submit(correlate, net, base, row, args): row for row in look}
        try:
            for fut in cf.as_completed(futs):
                n += 1
                try:
                    results.append(fut.result())
                except Exception as e:
                    row = futs[fut]
                    log(yel('\n[!] {} failed: {}'.format(row.get('domain'), e)))
                if sys.stderr.isatty():
                    log('\r\x1b[2Kchecking ownership {}/{}'.format(n, len(look)), end='')
        except KeyboardInterrupt:
            ex.shutdown(wait=False, cancel_futures=True)
            log(yel('\n[!] interrupted, reporting partial results'))
    if sys.stderr.isatty() and look:
        log('\r\x1b[2K', end='')

    results.sort(key=sort_key)
    threats = [r['domain'] for r in results if r['verdict'] != 'CLIENT-OWNED']
    malicious = [r['domain'] for r in results if r['verdict'] == 'LIKELY MALICIOUS']
    client = [r['domain'] for r in results if r['verdict'] == 'CLIENT-OWNED']

    if args.list:
        if threats:
            print('\n'.join(threats))
    elif args.json:
        print(json.dumps({'baseline': base, 'results': results}, indent=2, default=str))
    else:
        print()
        print_table(results, args.debug)
        if args.available and available:
            print()
            print('unregistered, available to register ({}):'.format(len(available)))
            for a in sorted(available, key=lambda x: x['domain']):
                print(Col.c('94', a['domain']))

    if not args.no_files:
        import csv
        os.makedirs(args.outdir, exist_ok=True)
        out_csv = os.path.join(args.outdir, dom + '_lookalikes.csv')
        with open(out_csv, 'w', newline='') as f:
            w = csv.writer(f)
            w.writerow(['domain', 'ip', 'ns', 'mx', 'ownership', 'reason'])
            for r in results:
                w.writerow([r['domain'], ' '.join(r['ips']), ' '.join(r['ns']), ' '.join(r['mx']),
                            tag_of(r)[0], reason_text(r, colour=False)])
            if args.available:
                for a in sorted(available, key=lambda x: x['domain']):
                    w.writerow([a['domain'], '', '', '', 'Available', 'Not registered'])
        if args.debug:
            with open(os.path.join(args.outdir, dom + '_debug.json'), 'w') as f:
                json.dump({'baseline': base, 'results': results, 'generated': datetime.now(timezone.utc),
                           'version': __version__, 'caveat': CAVEAT}, f, indent=2, default=str)

    counts = {}
    for r in results:
        counts[tag_of(r)[0]] = counts.get(tag_of(r)[0], 0) + 1
    parts = [red('{} threat'.format(counts.get('Threat', 0))), yel('{} unknown'.format(counts.get('Unknown', 0))),
             blu('{} likely client'.format(counts.get('Likely client', 0))),
             grn('{} client'.format(counts.get('Client', 0) + counts.get('Confirmed', 0)))]
    log('')
    log('{} registered lookalikes: {}  ({:.0f}s)'.format(len(results), ', '.join(parts), time.time() - t0))
    log('')
    if not args.no_files:
        log('Saved to {}'.format(out_csv) + ('  (and {}_debug.json)'.format(dom) if args.debug else ''))
    if known and args.debug:
        missed = sorted(k for k in known if k not in {r['domain'] for r in results} and k != dom)
        if missed:
            log('[*] {} domains on the client list did not show up as lookalikes'.format(len(missed)))
    log(grn(CAVEAT_SHORT) if not args.debug else grn(CAVEAT))
    return results


if __name__ == '__main__':
    try:
        main()
    except BrokenPipeError:
        pass
    except KeyboardInterrupt:
        log('\n[!] aborted')
        sys.exit(130)

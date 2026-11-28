#!/usr/bin/env python3
"""Offline tests for dnstwistturbo.py. Network is mocked except local HTTP/TLS servers."""
import datetime as dt
import http.server
import io
import ipaddress
import json
import os
import ssl
import sys
import tempfile
import threading
import time
import contextlib

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import dnstwistturbo as T

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NOW = dt.datetime.now(dt.timezone.utc)
FAILS = []


def check(name, cond, extra=''):
    print(('PASS ' if cond else 'FAIL ') + name + (('  ' + str(extra)) if extra and not cond else ''))
    if not cond:
        FAILS.append(name)


def make_cert(sans, org=None):
    key = ec.generate_private_key(ec.SECP256R1())
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, sans[0])]
    if org:
        attrs.append(x509.NameAttribute(NameOID.ORGANIZATION_NAME, org))
    name = x509.Name(attrs)
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
            .public_key(key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=30))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), critical=False)
            .sign(key, hashes.SHA256()))
    return cert, key


def der(cert):
    return cert.public_bytes(serialization.Encoding.DER)


def rdap_ip(handle, name, org, cidr):
    net = ipaddress.ip_network(cidr)
    return {'handle': handle, 'name': name,
            'cidr0_cidrs': [{'v4prefix': str(net.network_address), 'length': net.prefixlen}],
            'entities': [{'roles': ['registrant'], 'vcardArray': ['vcard', [['fn', {}, 'text', org]]]}]}


def rdap_dom(registrar, created_days, org=None, email=None):
    ents = [{'roles': ['registrar'], 'vcardArray': ['vcard', [['fn', {}, 'text', registrar]]]}]
    vc = [['fn', {}, 'text', org or 'REDACTED FOR PRIVACY']]
    if org:
        vc += [['org', {}, 'text', org]]
    if email:
        vc += [['email', {}, 'text', email]]
    ents.append({'roles': ['registrant'], 'vcardArray': ['vcard', vc]})
    return {'events': [{'eventAction': 'registration',
                        'eventDate': (NOW - dt.timedelta(days=created_days)).strftime('%Y-%m-%dT%H:%M:%SZ')}],
            'entities': ents}


# IP -> (asn, prefix, asname, rdap)
IPS = {
    '104.16.1.1': (13335, '104.16.0.0/13', 'CLOUDFLARENET - Cloudflare, Inc., US', rdap_ip('NET-104-16', 'CLOUDFLARENET', 'Cloudflare, Inc.', '104.16.0.0/12')),
    '104.16.2.2': (13335, '104.16.0.0/13', 'CLOUDFLARENET - Cloudflare, Inc., US', None),
    '104.16.9.9': (13335, '104.16.0.0/13', 'CLOUDFLARENET - Cloudflare, Inc., US', None),
    '198.51.100.10': (64500, '198.51.100.0/24', 'ACME-NET - Acme Corporation, US', rdap_ip('NET-ACME-1', 'ACME-NET', 'Acme Corporation', '198.51.100.0/24')),
    '198.51.100.20': (64500, '198.51.100.0/24', 'ACME-NET - Acme Corporation, US', None),
    '203.0.113.5': (14061, '203.0.113.0/24', 'DIGITALOCEAN-ASN, US', rdap_ip('NET-DO', 'DO-13', 'DigitalOcean, LLC', '203.0.113.0/24')),
    '192.0.2.50': (47846, '192.0.2.0/24', 'SEDO-AS SEDO GmbH, DE', rdap_ip('NET-SEDO', 'SEDO', 'Sedo GmbH', '192.0.2.0/24')),
    '145.0.0.1': (47583, '145.0.0.0/16', 'AS-HOSTINGER, CY', rdap_ip('NET-HST', 'HOSTINGER', 'Hostinger International', '145.0.0.0/16')),
    '66.77.0.9': (64600, '66.77.0.0/16', 'SMALLHOST - Peak Hosting, US', rdap_ip('NET-PEAK', 'PEAK', 'Peak Hosting LLC', '66.77.0.0/16')),
}

DNS = {
    ('acme-corp.com', 'A'): ['104.16.1.1'], ('www.acme-corp.com', 'A'): ['198.51.100.10'],
    ('acme-corp.com', 'NS'): ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com'],
    ('acme-corp.com', 'MX'): ['mx0a-00abc123.pphosted.com'],
}
for ip, (asn, pre, name, _) in IPS.items():
    DNS[('.'.join(reversed(ip.split('.'))) + '.origin.asn.cymru.com', 'TXT')] = ['{} | {} | US | arin | 2010-01-01'.format(asn, pre)]
    DNS[('AS{}.asn.cymru.com'.format(asn), 'TXT')] = ['{} | US | arin | 2001-01-01 | {}'.format(asn, name)]

CLIENT_CERT, CLIENT_KEY = make_cert(['acme-corp.com', 'www.acme-corp.com'], 'Acme Corporation')
NET_CERT, _ = make_cert(['acme-corp.net', 'acme-corp.com'])
LE_CERT, _ = make_cert(['acmee-corp.com'])
TLS = {'acme-corp.com': der(CLIENT_CERT), 'acme-corp.net': der(NET_CERT), 'acmee-corp.com': der(LE_CERT)}

HTTP = {
    'https://acme-corp.com/': {'chain': ['https://www.acme-corp.com/'], 'status': 200, 'final_url': 'https://www.acme-corp.com/',
                               'body': '<title>Acme Corp | Home</title>'},
    'https://acmecorp.com/': {'chain': ['https://www.acme-corp.com/'], 'status': None, 'final_url': 'https://acmecorp.com/', 'body': '', 'error': 'URLError'},
    'https://acme-c0rp.com/': {'chain': [], 'status': 200, 'final_url': 'https://acme-c0rp.com/',
                               'body': '<title>Sign in</title><form><input type="password" name=p></form>'},
    'https://acne-corp.com/': {'chain': [], 'status': 200, 'final_url': 'https://acne-corp.com/', 'body': '<title>acne-corp.com</title>This domain is for sale!'},
    'https://acme-corp.co/': {'chain': [], 'status': 200, 'final_url': 'https://acme-corp.co/', 'body': '<title>Welcome</title>'},
    'http://acmee-corp.com/': {'chain': [], 'status': 200, 'final_url': 'http://acmee-corp.com/', 'body': '<title>Acme Corp | Home</title>'},
    'https://acmecorp.biz/': {'chain': [], 'status': 200, 'final_url': 'https://acmecorp.biz/', 'body': '<title>Acme Corp | Home</title>'},
    'http://metarefresh.com/': {'chain': [], 'status': 200, 'final_url': 'http://metarefresh.com/',
                                'body': '<meta http-equiv="refresh" content="0;url=https://www.acme-corp.com/x">'},
}

RDAPDOM = {
    'acme-corp.com': rdap_dom('MarkMonitor Inc.', 9000, 'Acme Corporation', 'hostmaster@acme-corp.com'),
    'acmecorp.com': rdap_dom('MarkMonitor Inc.', 4000),
    'acme-c0rp.com': rdap_dom('NameCheap, Inc.', 10),
    'acne-corp.com': rdap_dom('GoDaddy.com, LLC', 3650),
    'acme-corp.co': rdap_dom('GoDaddy.com, LLC', 700),
    'acmee-corp.com': rdap_dom('Hostinger Operations, UAB', 40),
    'acme-corpp.com': rdap_dom('CSC Corporate Domains, Inc.', 2000),
    'acme-corp.org': rdap_dom('GoDaddy.com, LLC', 3000),
    'acmecorp.biz': rdap_dom('Hostinger Operations, UAB', 2000),
    'acmecorp.io': rdap_dom('Gandi SAS', 500, 'ACME CORP', 'it@acme-corp.com'),
}


class FakeNet(T.Net):
    def _resolve(self, name, rtype):
        return DNS.get((name.lower(), rtype), [])

    def get_json(self, url):
        if '/ip/' in url:
            ip = url.rsplit('/', 1)[-1]
            return IPS.get(ip, (0, 0, 0, None))[3]
        if '/domain/' in url:
            return RDAPDOM.get(url.rsplit('/', 1)[-1])
        return None

    def fetch(self, url):
        f = dict(HTTP.get(url, {'chain': [], 'status': None, 'final_url': url, 'body': '', 'error': 'URLError'}))
        f['chain'] = list(f['chain'])
        f['url'] = url
        return f

    def _tls_probe(self, host, port, ip):
        return T.parse_cert(TLS[host]) if host in TLS else None

    def whois43(self, d):
        return ''


LOOKALIKES = [
    {'fuzzer': '*original', 'domain': 'acme-corp.com', 'dns_a': ['104.16.1.1']},
    {'fuzzer': 'omission', 'domain': 'acmecorp.com', 'dns_a': ['104.16.2.2'], 'dns_ns': ['ada.ns.cloudflare.com', 'bob.ns.cloudflare.com']},
    {'fuzzer': 'homoglyph', 'domain': 'acme-c0rp.com', 'dns_a': ['203.0.113.5'], 'dns_ns': ['ns1.digitalocean.com'],
     'dns_mx': ['mail.acme-c0rp.com'], 'mx_spy': True},
    {'fuzzer': 'tld-swap', 'domain': 'acme-corp.net', 'dns_a': ['198.51.100.20'], 'dns_ns': ['ns1.acme-corp.com']},
    {'fuzzer': 'replacement', 'domain': 'acne-corp.com', 'dns_a': ['192.0.2.50'], 'dns_ns': ['ns1.sedoparking.com', 'ns2.sedoparking.com']},
    {'fuzzer': 'tld-swap', 'domain': 'acme-corp.co', 'dns_a': ['104.16.9.9'], 'dns_ns': ['kim.ns.cloudflare.com', 'lee.ns.cloudflare.com']},
    {'fuzzer': 'repetition', 'domain': 'acmee-corp.com', 'dns_a': ['145.0.0.1'], 'dns_ns': ['ns1.dns-parking.com'], 'dns_mx': ['mx1.hostinger.com']},
    {'fuzzer': 'tld-swap', 'domain': 'acme-corp.org', 'dns_ns': ['ns01.domaincontrol.com']},
    {'fuzzer': 'repetition', 'domain': 'acme-corpp.com', 'dns_ns': ['ns1.cscdns.net'], 'dns_mx': ['']},
    {'fuzzer': 'tld-swap', 'domain': 'acmecorp.io', 'dns_ns': ['ns1.gandi.net']},
    {'fuzzer': 'subdomain', 'domain': 'ac.me-corp.com', 'dns_ns': ['!ServFail']},
    {'fuzzer': 'bitsquatting', 'domain': 'acme-cosp.com'},
    {'fuzzer': 'tld-swap', 'domain': 'acmecorp.biz', 'dns_a': ['145.0.0.1'], 'dns_ns': ['ns1.dns-parking.com']},
    {'fuzzer': 'insertion', 'domain': 'acme-coro.com', 'dns_a': ['66.77.0.9'], 'dns_mx': ['mx0a-00abc123.pphosted.com']},
]


def run_scenario(extra=()):
    tmp = tempfile.mkdtemp()
    js = os.path.join(tmp, 'dt.json')
    with open(js, 'w') as f:
        json.dump(LOOKALIKES, f)
    known = os.path.join(tmp, 'known.txt')
    with open(known, 'w') as f:
        f.write('acme-corp.com\nacme-corp.org  # parked at GoDaddy\n')
    T.Net = FakeNet
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        args = ['acme-corp.com', '--from-json', js, '--known', known, '-o', tmp, '-c', 'Acme Corp'] + list(extra)
        if '--plain' in args:
            args.remove('--plain')
        else:
            args.append('--debug')
        res = T.main(args)
    return {r['domain']: r for r in res}, out.getvalue(), err.getvalue(), tmp


def scenario_tests(extra=(), quiet=False):
    R, out, err, tmp = run_scenario(extra)
    if quiet:
        return R, out, err, tmp
    print(err)
    print(out)
    v = lambda d: (R[d]['verdict'], R[d]['confidence'])
    check('original excluded', 'acme-corp.com' not in R)
    check('unregistered row excluded', 'acme-cosp.com' not in R)
    check('acmecorp.com client high (CF pair + redirect + MarkMonitor)', v('acmecorp.com') == ('CLIENT-OWNED', 'high'), R['acmecorp.com']['evidence'])
    check('acme-c0rp.com malicious high', v('acme-c0rp.com') == ('LIKELY MALICIOUS', 'high'), R['acme-c0rp.com']['evidence'])
    check('acme-corp.net client high (netblock + NS + SAN)', v('acme-corp.net') == ('CLIENT-OWNED', 'high'), R['acme-corp.net']['evidence'])
    check('acne-corp.com unknown and parked', R['acne-corp.com']['verdict'] == 'UNKNOWN' and R['acne-corp.com']['parked'], R['acne-corp.com']['evidence'])
    check('acme-corp.co unknown (shared CF, other NS pair)', R['acme-corp.co']['verdict'] == 'UNKNOWN' and R['acme-corp.co']['owner'] <= 5, R['acme-corp.co']['evidence'])
    check('acmee-corp.com malicious (clone + young + live MX)', R['acmee-corp.com']['verdict'] == 'LIKELY MALICIOUS', R['acmee-corp.com']['evidence'])
    check('acme-corp.org confirmed from client list with disagreement note',
          v('acme-corp.org') == ('CLIENT-OWNED', 'confirmed') and any('client list says owned' in n for n in R['acme-corp.org']['notes']))
    check('acme-corpp.com client low (CSC DNS + CSC registrar + null MX)', v('acme-corpp.com') == ('CLIENT-OWNED', 'low'), R['acme-corpp.com']['evidence'])
    check('acmecorp.io client via registrant email', R['acmecorp.io']['verdict'] == 'CLIENT-OWNED' and any('email' in e for e in R['acmecorp.io']['evidence']), R['acmecorp.io']['evidence'])
    check('acme-coro.com client via same Proofpoint tenant MX', any('same MX as client' in e for e in R['acme-coro.com']['evidence']), R['acme-coro.com']['evidence'])
    check('ServFail row kept as unknown', R['ac.me-corp.com']['verdict'] == 'UNKNOWN')
    import csv
    rows = list(csv.DictReader(open(os.path.join(tmp, 'acme-corp.com_lookalikes.csv'))))
    th = [x['domain'] for x in rows if x['ownership'] in ('Threat', 'Unknown')]
    mal = [x['domain'] for x in rows if x['ownership'] == 'Threat']
    cl = [x['domain'] for x in rows if x['ownership'] in ('Client', 'Likely client', 'Confirmed')]
    check('only one file written (plus debug json in debug mode)', sorted(os.listdir(tmp)) ==
          ['acme-corp.com_debug.json', 'acme-corp.com_lookalikes.csv', 'dt.json', 'known.txt'], os.listdir(tmp))
    check('clone on its own makes a THREAT', R['acmecorp.biz']['verdict'] == 'LIKELY MALICIOUS', R['acmecorp.biz']['evidence'])
    check('red reasons only on THREAT lines', all(r['verdict'] == 'LIKELY MALICIOUS' for r in R.values() if any(x[1] for x in r['reason'])))
    check('empty subdomain row explains itself', [t for t, _ in R['ac.me-corp.com']['reason']] ==
          ['sits under me-corp.com', 'DNS lookup failed'], R['ac.me-corp.com']['reason'])
    check('threats list has unknown + malicious only', set(th) == {d for d, r in R.items() if r['verdict'] != 'CLIENT-OWNED'}, th)
    check('malicious list first entry', mal[0] == 'acme-c0rp.com', mal)
    check('client list excludes threats', not set(cl) & set(th))
    check('debug json valid', json.load(open(os.path.join(tmp, 'acme-corp.com_debug.json')))['caveat'])
    check('caveat printed', 'Confirm every verdict' in err)
    check('no ANSI in non tty output', '\x1b[' not in out)
    return R, out, err, tmp


def unit_tests():
    check('reg_domain co.uk', T.reg_domain('www.acme.co.uk') == 'acme.co.uk', T.reg_domain('www.acme.co.uk'))
    check('host_in suffix not substring', T.host_in('evilacme.com', ['acme.com']) is False and T.host_in('a.acme.com', ['acme.com']))
    check('org match suffix strip', T.org_match('ACME CORPORATION', ['Acme Corp']) == 'Acme Corp')
    check('org no false match', T.org_match('Acmetric Labs', ['Acme Corp']) is None)
    check('provider by keyword', T.detect_provider(None, 'AMAZON-02') == 'AWS')
    check('provider none for client', T.detect_provider(64500, 'ACME-NET') is None)
    check('ns_class cloudflare', T.ns_class('ada.ns.cloudflare.com') == 'cloudflare')
    check('ns_class route53', T.ns_class('ns-12.awsdns-01.com') == 'route53')
    check('ns_class generic', T.ns_class('ns51.domaincontrol.com') == 'generic')
    w = T.parse_whois('Domain Name: X.COM\nRegistrar: MarkMonitor Inc.\nCreation Date: 1997-03-12T05:00:00Z\n'
                      'Registrant Organization: REDACTED FOR PRIVACY\nRegistrant Email: Select Request Email Form\n')
    f = T.finalize_reg(dict(w))
    check('whois registrar', w['registrar'] == 'MarkMonitor Inc.')
    check('whois created', w['created'].year == 1997)
    check('whois redaction detected', f['redacted'] and f['registrant_org'] is None)
    uk = T.parse_whois('    Registrant:\n        Acme Ltd\n\n    Registrar:\n        Markmonitor Inc. [Tag = MARKMONITOR]\n    Registered on: 12-Mar-1998\n')
    check('whois .uk multi line', uk['registrant_org'] == 'Acme Ltd' and 'Markmonitor' in uk['registrar'] and uk['created'].year == 1998, uk)
    r = T.parse_rdap_ip(rdap_ip('NET-X', 'X', 'Acme Corporation', '198.51.100.0/24'))
    check('rdap ip parse', r['nets'] == ['198.51.100.0/24'] and r['org'] == 'Acme Corporation')
    r2 = T.parse_rdap_ip({'handle': 'H', 'startAddress': '10.0.0.0', 'endAddress': '10.0.1.255', 'entities': []})
    check('rdap ip range summarise', r2['nets'] == ['10.0.0.0/23'], r2)
    c = T.parse_cert(der(CLIENT_CERT))
    check('cert parse', c['subject_o'] == 'Acme Corporation' and 'www.acme-corp.com' in c['san'])
    h = T.analyse_http([HTTP['http://metarefresh.com/']], 'metarefresh.com', ['acme-corp.com'])
    check('meta refresh to client detected', h['to_client'] and h['redirect_host'] == 'www.acme-corp.com', h)


class Redir(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(301)
        self.send_header('Location', 'https://www.acme-corp.invalid/landing')
        self.end_headers()

    def log_message(self, *a):
        pass


def live_local_tests():
    os.environ['no_proxy'] = os.environ['NO_PROXY'] = '*'
    for k in ('http_proxy', 'https_proxy', 'HTTP_PROXY', 'HTTPS_PROXY'):
        os.environ.pop(k, None)
    real = T.Net.__mro__[-2] if T.Net.__name__ == 'FakeNet' else T.Net
    real = [c for c in T.Net.__mro__ if c.__name__ == 'Net'][0]
    net = real(timeout=3)
    srv = http.server.HTTPServer(('127.0.0.1', 0), Redir)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    f = net.fetch('http://127.0.0.1:{}/'.format(srv.server_address[1]))
    h = T.analyse_http([f], '127.0.0.1', ['acme-corp.invalid'])
    check('real redirect chain recorded even when target unreachable', h['to_client'] and h['redirect_host'] == 'www.acme-corp.invalid', (f, h))
    srv.shutdown()

    cert, key = make_cert(['localhost', 'acme-corp.com'], 'Acme Corporation')
    d = tempfile.mkdtemp()
    cp, kp = os.path.join(d, 'c.pem'), os.path.join(d, 'k.pem')
    open(cp, 'wb').write(cert.public_bytes(serialization.Encoding.PEM))
    open(kp, 'wb').write(key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    hs = http.server.HTTPServer(('127.0.0.1', 0), Redir)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cp, kp)
    hs.socket = ctx.wrap_socket(hs.socket, server_side=True)
    hs.handle_error = lambda *a: None
    threading.Thread(target=hs.serve_forever, daemon=True).start()
    t = net._tls_probe('localhost', hs.server_address[1], '127.0.0.1')
    check('real TLS probe reads SAN and O from self signed cert', t and 'acme-corp.com' in t['san'] and t['subject_o'] == 'Acme Corporation', t)
    f2 = net.fetch('https://127.0.0.1:{}/'.format(hs.server_address[1]))
    check('https fetch with bad cert still follows redirect', f2['chain'] == ['https://www.acme-corp.invalid/landing'], f2)
    hs.shutdown()


SC_FILE = os.environ.get('SC_FILE') or os.path.join(os.path.dirname(os.path.abspath(__file__)), 'scopecheck.py')


def sc_owner(ip):
    asn, pre, asname, rd = IPS.get(ip, (0, '', '', None))
    org = (rd or {}).get('entities', [{}])[0].get('vcardArray', [0, [[0, 0, 0, '']]])[1][0][3] if rd else asname.split(' - ')[-1].split(',')[0]
    cidr = '{}/{}'.format(rd['cidr0_cidrs'][0]['v4prefix'], rd['cidr0_cidrs'][0]['length']) if rd else pre
    return dict(org=org, netname=(rd or {}).get('name', ''), entities=[org], cidr=cidr, asn=str(asn) if asn else '',
                asn_name=asname, country='US')


def scopecheck_tests(baseline_results):
    real_loader = T.load_scopecheck

    def loader(path=None):
        mod = real_loader(SC_FILE)
        if mod:
            mod.Owners.lookup = lambda self, ip: sc_owner(ip)
        return mod
    T.load_scopecheck = loader
    R, out, err, tmp = scenario_tests(quiet=True)
    check('scopecheck module imported', 'ownership scopecheck.py' in err, err[:400])
    same = {d: r['verdict'] for d, r in R.items()} == {d: r['verdict'] for d, r in baseline_results.items()}
    check('scopecheck ownership gives the same verdicts as built in', same,
          {d: (r['verdict'], baseline_results[d]['verdict']) for d, r in R.items() if r['verdict'] != baseline_results[d]['verdict']})
    check('scopecheck provider kind used (Cloudflare is cdn)', R['acme-corp.co']['ip_info']['kind'] == 'cdn' and R['acme-corp.co']['ip_info']['source'] == 'scopecheck')
    check('scopecheck client name match on netblock', T.owner_matches_client(R['acme-corp.net']['ip_info'], ['Acme Corp']) == 'Acme Corp'
          and T.owner_matches_client(R['acme-c0rp.com']['ip_info'], ['Acme Corp']) is None)

    # seed the baseline from a scopecheck results folder
    d = tempfile.mkdtemp()
    rows = [
        {'tier': 'green', 'base_note': 'IP leased from Peak Hosting LLC.', 'ips': ['66.77.0.9'], 'owners': {}, 'client_domain_hit': 'vpn.acmeholdings.com'},
        {'tier': 'green', 'base_note': 'Registered to the client.', 'ips': ['64.1.2.200'],
         'owners': {'64.1.2.200': {'cidr': '64.1.2.192/26', 'org': 'Acme Holdings Inc', 'asn': '7922'}}, 'client_domain_hit': ''},
        {'tier': 'blue', 'base_note': 'AWS.', 'ips': ['52.1.1.1'], 'owners': {}, 'client_domain_hit': ''},
        {'tier': 'red', 'base_note': 'Mimecast', 'ips': ['40.0.0.1'], 'owners': {}, 'client_domain_hit': ''},
        {'tier': 'grey', 'base_note': 'Private IP', 'ips': ['10.0.0.5'], 'owners': {}, 'client_domain_hit': ''},
    ]
    json.dump(rows, open(os.path.join(d, 'results.json'), 'w'))
    open(os.path.join(d, 'mail_domains.txt'), 'w').write('acme-mail.com\n')
    R2, out2, err2, tmp2 = scenario_tests(extra=['--scopecheck', d, '-d', 'acme-intl.com,acme.de'], quiet=True)
    base = json.load(open(os.path.join(tmp2, 'acme-corp.com_debug.json')))['baseline']
    check('scope IPs loaded, red and grey ignored', base['scope_ips'] == {'66.77.0.9': 'green', '64.1.2.200': 'green', '52.1.1.1': 'blue'}, base['scope_ips'])
    check('client netblock from scopecheck', '64.1.2.192/26' in base['nets'])
    check('scopecheck owner org becomes a client name', 'Acme Holdings Inc' in base['org_hints'])
    check('scopecheck ASN not trusted (could be the ISP)', 7922 not in base['asns'])
    check('client domains from scopecheck, mail_domains.txt and -d',
          {'acmeholdings.com', 'acme-mail.com', 'acme-intl.com', 'acme.de'} <= set(base['bases']), base['bases'])
    check('lookalike on an in scope IP is client high', R2['acme-coro.com']['verdict'] == 'CLIENT-OWNED' and R2['acme-coro.com']['confidence'] == 'high'
          and any('in client scope' in e for e in R2['acme-coro.com']['evidence']), R2['acme-coro.com']['evidence'])
    check('scope summary printed', 'IPs from scopecheck (2 testable, 1 with caveats), 1 client netblocks' in err2, err2[:600])
    T.load_scopecheck = real_loader
    T.SC = None

    # a broken scopecheck.py must not kill the run
    bad = os.path.join(tempfile.mkdtemp(), 'scopecheck.py')
    open(bad, 'w').write('import sys\nsys.exit("Missing dependency: pip install rich")\n')
    e = io.StringIO()
    with contextlib.redirect_stderr(e):
        m = real_loader(bad)
    check('broken scopecheck import falls back cleanly', m is None and T.SC is None and 'built in' in e.getvalue())


def simple_output_tests():
    R, out, err, tmp = scenario_tests(extra=['--plain'], quiet=True)
    print(err)
    print(out)
    lines = [l for l in out.splitlines() if l.strip()]
    first = lines[0].split()
    check('plain output starts with the biggest threat, no fuzzer column', first[:2] == ['acme-c0rp.com', '203.0.113.5'], lines[0])
    check('no all caps tags or reasons', not any(w in out for w in ('THREAT', 'UNKNOWN', 'CLIENT SITE', 'ACCEPTS')))
    check('reasons start with a capital', all(l.rstrip().split('  ')[-1].strip()[:1].isupper() for l in lines if 'Unknown' in l or 'Threat' in l), lines)
    check('saved line', 'Saved to ' in err)
    T.Col.on = True
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        T.print_table([R['ac.me-corp.com'], R['acme-corpp.com'], R['acmecorp.com'], R['acmecorp.biz']])
    T.Col.on = False
    cl = buf.getvalue().splitlines()
    check('reason colour matches tag colour', cl[0].endswith('\x1b[1;33mSits under me-corp.com, DNS lookup failed\x1b[0m')
          and cl[1].endswith('\x1b[1;94mBrand protection registrar, brand protection DNS\x1b[0m')
          and cl[2].endswith('\x1b[1;32mRedirects to client, client registrar\x1b[0m')
          and cl[3].endswith('\x1b[1;31mClones client site\x1b[0m'), cl)
    check('blank lines between sections', err.startswith('\n') and out.startswith('\n') and '\n\nSaved to' in err, (err[:80], out[:40]))
    check('fuzzer names not on screen', 'homoglyph' not in out and 'tld-swap' not in out)
    check('threat line carries tag and short reason', 'Threat' in lines[0] and 'Accepts any mail' in lines[0], lines[0])
    check('no scores or point values in plain output', '+40' not in out and 'owner ' not in out and 'threat 0' not in out)
    check('no baseline block in plain output', '[baseline]' not in err and 'registrar' not in err, err)
    check('one line header names ownership source', 'ownership: built in' in err.splitlines()[1], err.splitlines()[:2])
    check('summary counts line', 'registered lookalikes: 3 threat, 3 unknown' in err, err)
    check('short caveat', "Confirm them against the client's own list" in err)
    tags = [l.split()[-1] for l in lines]
    check('likely client tag for low confidence', any('Likely client' in l and 'acme-corpp.com' in l for l in lines))
    check('confirmed tag from client list', any('Confirmed' in l and 'acme-corp.org' in l and 'On client list' in l for l in lines))
    csvf = open(os.path.join(tmp, 'acme-corp.com_lookalikes.csv')).read()
    check('csv for the client alert', csvf.startswith('domain,ip,ns,mx,ownership,reason') and 'acme-c0rp.com' in csvf)
    check('csv has every lookalike', csvf.count('\n') == len(R) + 1)
    check('plain mode writes only the csv', sorted(os.listdir(tmp)) == ['acme-corp.com_lookalikes.csv', 'dt.json', 'known.txt'], os.listdir(tmp))
    R2, out2, err2, tmp2 = scenario_tests(extra=['--plain', '--available'], quiet=True)
    check('--available lists unregistered permutations', 'available to register (1)' in out2 and 'acme-cosp.com' in out2
          and 'acme-cosp.com,,,,Available,Not registered' in open(os.path.join(tmp2, 'acme-corp.com_lookalikes.csv')).read(), out2[-300:])
    R3, out3, *_ = scenario_tests(extra=[], quiet=True)
    check('--debug adds evidence lines', '+40 MX accepts mail for any recipient' in out3)


def autodetect_tests():
    # mirror ~/labrat/<client>/{dnstwistturbo,IP-Scope-Checker/scopecheck_*}
    root = tempfile.mkdtemp()
    os.makedirs(os.path.join(root, 'dnstwistturbo'))
    old = os.path.join(root, 'IP-Scope-Checker', 'scopecheck_20261120_090000')
    new = os.path.join(root, 'IP-Scope-Checker', 'scopecheck_20261127_141429')
    for d, ip in ((old, '8.8.4.4'), (new, '66.77.0.9')):
        os.makedirs(d)
        json.dump([{'tier': 'green', 'base_note': 'IP leased from X.', 'ips': [ip], 'owners': {}, 'client_domain_hit': ''}],
                  open(os.path.join(d, 'results.json'), 'w'))
    t = time.time()
    os.utime(os.path.join(old, 'results.json'), (t - 7 * 86400, t - 7 * 86400))
    here, T.HERE = T.HERE, os.path.join(root, 'dnstwistturbo')
    cwd = os.getcwd()
    os.chdir(T.HERE)
    try:
        check('auto detect picks newest scopecheck run', T.find_scopecheck_results() == os.path.join(new, 'results.json'),
              T.find_scopecheck_results())
        R, out, err, tmp = scenario_tests(quiet=True)
        check('auto detected run seeds baseline', R['acme-coro.com']['confidence'] == 'high' and 'scopecheck_20261127_141429' in err, err[:500])
        R2, out2, err2, _ = scenario_tests(extra=['--no-scopecheck-results'], quiet=True)
        check('--no-scopecheck-results disables it', 'none found' in err2 and R2['acme-coro.com']['confidence'] == 'low')
    finally:
        T.HERE = here
        os.chdir(cwd)


if __name__ == '__main__':
    unit_tests()
    live_local_tests()
    real_loader = T.load_scopecheck
    T.load_scopecheck = lambda path=None: None
    R0, *_ = scenario_tests()
    simple_output_tests()
    autodetect_tests()
    T.load_scopecheck = real_loader
    if os.path.isfile(SC_FILE):
        scopecheck_tests(R0)
    else:
        print('SKIP scopecheck tests: no scopecheck.py found (set SC_FILE)')
    print('\n{} failures'.format(len(FAILS)) if FAILS else '\nALL PASS')
    sys.exit(1 if FAILS else 0)

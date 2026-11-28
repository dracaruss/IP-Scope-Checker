# dnstwistturbo

dnstwistturbo wraps dnstwist for external penetration testing recon. It finds registered lookalikes of a client domain and decides, for each one, whether the client owns it as a defensive registration or whether it belongs to someone else and is a possible typosquatting or phishing threat.

Ownership is always inferred, never proven. Confirm every verdict against the client's own list of registered domains before it goes in a report.

## Install

Python 3.9 or newer is required. On Kali, use a virtual environment so pip does not clash with system packages.

```
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

If you would rather not use a virtual environment, run `pip install -r requirements.txt --break-system-packages` instead. A copy of dnstwist.py sitting in the same folder as the script also works.

## Use

Run it against the client's real domain, and give it the client's legal or brand name so it can match registration and network records.

```
python3 dnstwistturbo.py acme.com -c "Acme Corp"
```

The `-c` and `-d` flags work the same way they do in scopecheck. Use `-c` for each client name as it may appear in WHOIS or RDAP, and `-d` for any other domains the client owns. Both accept comma separated values and can be repeated.

If the client has given you a list of the domains they own, pass it with `--known`. Those domains are marked as confirmed, and the tool tells you when its own guess disagreed with the list.

```
python3 dnstwistturbo.py acme.com -c "Acme Corp" --known acme_domains.txt -o out/
```

To print only the unknown and likely malicious domains, one per line, so they can be piped into another tool, use `--list`.

```
python3 dnstwistturbo.py acme.com --list > lookalikes.txt
```

If you already have dnstwist JSON output, you can feed it in and skip the dnstwist run.

```
dnstwist -r -a -m -f json acme.com > dt.json
python3 dnstwistturbo.py acme.com --from-json dt.json
```

Run `python3 dnstwistturbo.py -h` to see every option, including switches that skip the HTTP, TLS, WHOIS or mail checks.

## Working with scopecheck

scopecheck runs first in the methodology, so dnstwistturbo builds on it and never the other way round. The easiest layout is to clone both repos side by side in one engagement folder, so that dnstwistturbo and IP-Scope-Checker sit next to each other. dnstwistturbo looks one folder up and finds scopecheck.py on its own, with no copying. It also finds scopecheck.py if it sits in the same folder or the folder you run from. Once found, dnstwistturbo uses its ownership lookup, its provider list and its client name matching, so the two tools agree on who owns an IP. If scopecheck.py lives somewhere else, point to it with `--scopecheck-py` or the `SCOPECHECK_PY` environment variable. If it cannot be found, dnstwistturbo falls back to its own built in lookup, and the baseline line at the top of the output tells you which one was used.

dnstwistturbo also finds your scopecheck results by itself. It picks the newest scopecheck_ folder that holds a results.json, looking in the IP-Scope-Checker repo, in its own folder, in the folder you run it from, and in the other folders one level up. It then treats the IPs scopecheck marked testable or testable with caveats as client IPs, adds any netblocks registered to the client, and adds the client domains from mail_domains.txt. A lookalike that resolves to one of the client's testable IPs is then scored as strongly client owned. The baseline at the top of the output names the scopecheck run it used and how old it is, so you can spot a stale run.

```
cd ../IP-Scope-Checker && python3 scopecheck.py -i scope.txt -c "Acme Corp" -d acme.com
cd ../dnstwistturbo && python3 dnstwistturbo.py acme.com -c "Acme Corp"
```

To use a specific run instead of the newest one, pass its folder with `--scopecheck`. To ignore scopecheck results completely, use `--no-scopecheck-results`.

Lookalikes tagged Client in the CSV can go back into scopecheck as new scope candidates once the client confirms them.

## Output

The main output is the dnstwist list of registered lookalikes. Each line shows the domain in blue, its IP, its nameserver and its mail server, followed by an ownership tag and a short reason. The worst threats come first, so the top of the list is what you alert the client about.

```
acme-c0rp.com   203.0.113.5   NS:ns1.digitalocean.com  MX:mail.acme-c0rp.com  Threat     Accepts any mail, registered 10d ago
acmecorp.com    104.16.2.2    NS:ada.ns.cloudflare.com                         Client     Redirects to client, client registrar
```

Threat is shown in red. It means the lookalike shows a real danger sign, such as a mail server that accepts mail for any address, a login page, or a copy of the client's website, and nothing ties it to the client. Each reason is printed in the same colour as its tag. Unknown in yellow means nothing ties the domain to the client and nothing looks dangerous yet. Parked means the domain sits with a parking or resale service, usually showing ads or a for sale page, rather than a real website. Likely client in blue means there is some evidence the client owns it, and Client or Confirmed in green means the evidence is strong or the domain is on the client's own list. A line with no records, such as a subdomain lookalike that sits under someone else's domain, says so in its reason.

Each run saves one file, `<domain>_lookalikes.csv`, with the domain, IP, nameserver, mail server, ownership tag and reason for every lookalike. Add `--available` to also list the lookalikes nobody has registered yet, which the client may want to register defensively. They appear on screen and in the same CSV tagged Available.

Add `--debug` to see the baseline fingerprint of the real domain, the fuzzer, the scores and the full evidence behind every tag. Debug mode also saves a `<domain>_debug.json` file with everything.

## Test

The test script checks the scoring logic offline with mocked network results, so it runs without internet access. It also tests the scopecheck integration when it can find a copy of scopecheck.py, which you can point it at with the `SC_FILE` environment variable.

```
python3 test_turbo.py
```

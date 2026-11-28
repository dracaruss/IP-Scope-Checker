# scopecheck

scopecheck takes a list of external pentest targets and tells you who owns each one, whether it is live, and what is running on it. It highlights anything that does not belong to the client, such as a Microsoft, AWS or Cloudflare address, and adds a short note on that provider's testing rules.

## Install

```
pip install -r requirements.txt
```

## Usage

Put your targets in a text file, one per line. The file can mix IP addresses, CIDR ranges, IP ranges, hostnames and URLs.

```
python3 scopecheck.py -i scope.txt -c "Acme Corp" -d acme.com
```

The `-c` option is the client's name as it would appear in WHOIS records, and `-d` is a domain the client owns. You can repeat both options as many times as you need.

## Colours

Everything in your file is assumed to be in scope, so the colour only tells you how to treat it. Green means testable with no special conditions, which covers the client's own IPs and static IPs leased from an ISP. Blue means testable with caveats, such as Azure, AWS, Hetzner, a CDN or a Microsoft 365 portal, where you stay inside the client's resources and avoid DoS. Red means the site is live but should be left alone, such as a vendor's SaaS platform or an email gateway. Grey means it cannot be reached, such as a private IP or a hostname that no longer resolves, and it also flags possible subdomain takeovers. Rows are sorted in that order: testable first, then caveats, then do not test, then not reachable. Every row shows the URLs and hostnames found for that target, plus a one line reason for its colour. After the main list, a recap groups the blue, red and grey rows by provider so you can copy each IP list in one go. If you write a hostname with its expected IP in brackets, such as `vpn.acme.com (203.0.113.10)`, the tool warns you when DNS points somewhere else. Any login portals found are also listed in their own section, with the portal type, URL and target.

## Domains for the mail check

At the end of each run the tool lists the client's domains for your DNS and mail checks. It collects them from your scope file, your `-d` list, certificates, redirects and CNAMEs, and saves them to `mail_domains.txt` in the output folder. Domains it saw that do not obviously belong to the client are listed separately, so you can confirm them before reporting on them. You can feed the file straight into the mail tool with `for d in $(cat mail_domains.txt); do ./mailcheck.sh $d; done`.

## Government clouds

Anything in a US government cloud or network is a hard stop. That covers Azure Government and its DoD regions, Microsoft 365 GCC High and DoD, AWS GovCloud, Oracle Government Cloud, .mil and .gov domains, and address space registered to the Department of Defense. These show as DO NOT TEST with a GOV CLOUD tag, and the tool never sends them any traffic. It spots them by hostname, by registry owner, and by the IP ranges Microsoft and AWS publish for their government regions. Those ranges are downloaded once a week and cached. If the download fails, the tool warns you that bare IPs in those clouds will not be caught.

## Useful options

Add `--screenshots` to capture each web page, `--shodan` to pull known ports and CVEs from Shodan, `--passive` to avoid sending any traffic to the targets, `--skip-red-probe` to avoid probing third party assets, and `--refresh-gov-ranges` to force a fresh download of the government cloud ranges. Run `python3 scopecheck.py -h` to see every option.

## Output

Each run creates a folder containing an HTML report that you can filter by colour, along with CSV and JSON versions of the results. If httpx, dnsx or gowitness are installed, the tool uses them automatically.

## Disclaimer

The rules of engagement notes are summaries. Always check the provider's current policy and the client's written authorisation before testing.

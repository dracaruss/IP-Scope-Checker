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

Green means testable with no special conditions, which covers the client's own IPs and static IPs leased from an ISP.  

Blue means testable with caveats, such as Azure, AWS, Hetzner, a CDN or a Microsoft 365 portal, where you stay inside the client's resources and avoid DoS.  

Red means the site is live but should be left alone, such as a vendor's SaaS platform or an email gateway.  

Grey means it cannot be reached, such as a private IP or a hostname that no longer resolves, and it also flags possible subdomain takeovers.  

Every row shows the URLs and hostnames found for that target, plus a one line reason for its colour. Any login portals found are also listed in their own section, with the portal type, URL and target.

## Useful options

`--screenshots` to capture each web page  
Open the HTML report in your browser. The screenshots show as thumbnails next to each URL in the "What it is" column, and clicking one opens it full size.  
`firefox scopecheck_<timestamp>/report.html`  
Use `xdg-open` instead of firefox to open it in your default browser. The image files themselves are in the screenshots folder inside that same output folder, so keep the folder together if you move or share the report.  

`--shodan` to pull known ports and CVEs from Shodan  
`--passive` to avoid sending any traffic to the targets  
`--skip-red-probe` to avoid probing third party assets.  

Run `python3 scopecheck.py -h` to see every option.  

## Output

Each run creates a folder containing an HTML report that you can filter by colour, along with CSV and JSON versions of the results. If httpx, dnsx or gowitness are installed, the tool uses them automatically.

## Disclaimer

The rules of engagement notes are summaries. Always check the provider's current policy and the client's written authorisation before testing.

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

Green means the address is registered to the client. Yellow means it belongs to an ISP or an unknown owner, so you should confirm it with the client. Red means it belongs to a third party provider, and the report includes that provider's rules of engagement. Grey means the address is private or the hostname does not resolve.

## Useful options

Add `--screenshots` to capture each web page, `--shodan` to pull known ports and CVEs from Shodan, `--passive` to avoid sending any traffic to the targets, and `--skip-red-probe` to avoid probing third party assets. Run `python3 scopecheck.py -h` to see every option.

## Output

Each run creates a folder containing an HTML report that you can filter by colour, along with CSV and JSON versions of the results. If httpx, dnsx or gowitness are installed, the tool uses them automatically.

## Disclaimer

The rules of engagement notes are summaries. Always check the provider's current policy and the client's written authorisation before testing.

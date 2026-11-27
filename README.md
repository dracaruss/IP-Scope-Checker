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

The `-c` option is the client's name as it would appear in WHOIS records.

The -c flag is the client's name as it appears in the WHOIS registration for their IP blocks, such as "Acme Corp". The tool checks it against the owner name on each IP, ignoring case, spaces and punctuation, and any match is marked green as a client asset. Without -c, nothing can turn green. If the client registers under several names, repeat the flag, like -c "Acme Corp" -c "Acme Holdings". Avoid very short names, because the check is a partial match and something like "ACM" could match unrelated organisations.

 `-d` is a domain the client owns. You can repeat both options as many times as you need.
 
The -d flag is a domain the client owns, such as acme.com. It doesn't change the colour. It adds evidence to the note by checking whether the hostname, CNAME, reverse DNS name or TLS certificate falls under that domain. For example, a Comcast IP whose certificate says vpn.acme.com is probably the client's leased line. An Azure IP serving acme.com is probably the client's own Azure resource. The flag also warns you when a hostname in your scope isn't under any of the client's domains.

## Colours

Green means the address is registered to the client. Yellow means it belongs to an ISP or an unknown owner, so you should confirm it with the client. Red means it belongs to a third party provider, and the report includes that provider's rules of engagement. Grey means the address is private or the hostname does not resolve.

## Useful options

`--screenshots` to capture each web page  
`--shodan` to pull known ports and CVEs from Shodan  
`--passive` to avoid sending any traffic to the targets  
`--skip-red-probe` to avoid probing third party assets  

Run `python3 scopecheck.py -h` to see every option.

## Output

Each run creates a folder containing an HTML report that you can filter by colour, along with CSV and JSON versions of the results. If httpx, dnsx or gowitness are installed, the tool uses them automatically.

## Disclaimer

The rules of engagement notes are summaries. Always check the provider's current policy and the client's written authorisation before testing.

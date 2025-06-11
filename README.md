# nuclei-cloudflare-bypass

This workflow discovers subdomains, scans for open ports, and identifies live HTTP services.
```bash
subfinder -dL root.txt -all -silent -o subs.txt && \
naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt && \
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt
```
#### Cloudflare Bypass

Attempts to bypass Cloudflare protection for HTTP services listed in `alive_http_services.txt`
```bash
python3 cloudflare_bypass.py -f alive_http_services.txt -o cf-bypass-results.txt
```

#### Accessible Inactive Hosts

Identifies inactive and potentially accessible hosts from a list of domains.
```bash
# Default mode (fast)
python3 inactive_hosts.py -f subs.txt

# Faster mode with more threads and shorter timeouts
python3 inactive_hosts.py -f subs.txt -w 50 --dns-timeout 2 --http-timeout 3

# Save results to a file
python3 inactive_hosts.py -f subs.txt -o results.txt
```

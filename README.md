# WAF Bypass and Inactive Hosts Finder

This workflow discovers subdomains, scans for open ports, and identifies live HTTP services.
```bash
subfinder -d domain.com -all -silent -o subs.txt && \
naabu -l subs.txt -s s -tp 100 -ec -c 50 -o naabu.txt && \
httpx -l naabu.txt -rl 500 -t 200 -o alive_http_services.txt
```
### Cloudflare Bypass

Attempts to bypass Cloudflare protection for HTTP services listed in `alive_http_services.txt`
```bash
python3 cloudflare_bypass.py -f alive_http_services.txt -o cf-bypass-results.txt
```
**Sample Output:**
```
[INFO] Loaded 3 targets
[STEP 1] Searching for targets behind Cloudflare WAF...
  [1/3] Checking example.com
    ✓ Behind Cloudflare (status: 403)
  [2/3] Checking test.com
    ○ Not behind Cloudflare (status: 200)
  [3/3] Checking https://site.com
    ○ Not behind Cloudflare (status: 404)

[RESULT OF SCANNING]
  Targets behind Cloudflare: 1
  Targets not behind Cloudflare: 2

[STEP 2] Testing WAF bypasses...
[TESTING] test.com
  [BYPASS FOUND!] Host: example.com -> status: 200 (no Cloudflare!)

[SAVED] Results saved to cf-bypass-results.txt

[WAF BYPASS RESULTS]

Bypass #1
Base URL: https://test.com
Host Header: example.com
Status Code: 200
Curl Command: curl -H "Host: example.com" https://test.com -k -L -I
Nuclei Command: nuclei -u https://test.com -H "Host: example.com" -rl 110 -c 25 
```
---

### Accessible Inactive Hosts

Identifies inactive and potentially accessible hosts from a list of domains in `subs.txt`
```bash
# Default mode (fast)
python3 inactive_hosts.py -f subs.txt

# Faster mode with more threads and shorter timeouts
python3 inactive_hosts.py -f subs.txt -w 50 --dns-timeout 2 --http-timeout 3

# Save results to a file
python3 inactive_hosts.py -f subs.txt -o inactive-hosts-results.txt
```
**Sample Output:**
```
[INFO] Loaded 3 targets
[STEP 1] Fast analysis of 3 targets...
[DNS] Parallel checking 3 domains (timeout=3s)...
  ✓ example.com
  ✗ inactive.com
  ✓ test.com

[RESULT OF ANALYSIS] (time: 2.45s)
  Active domains: 2
  Inactive domains: 1

[STEP 2] Host Header testing...
Testing 1 inactive domains through 2 active domains
  [ACCESS FOUND!] test.com -> inactive.com (200)

[ACCESS TO INACTIVE HOSTS]
[ACCESS #1]
Inactive Host: inactive.com
Active Host: test.com
Active URL: https://test.com
Status Code: 200 (original: 404)
...
Test Commands:
  curl -H "Host: inactive.com" https://test.com -k -L -I
  nuclei -u https://test.com -H "Host: inactive.com" -rl 110 -c 25
...

[SAVED] Results saved to inactive-hosts-results.txt
```

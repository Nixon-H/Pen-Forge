#!/bin/bash
OS_ID=""
SUDO_REFRESH_PID=""
declare -g SPINNER_PID=""
declare -g CLEANUP_RUNNING=false
PREREQUISITES_MET=false
if [[ -d "/usr/local/go/bin" ]]; then
export GOROOT="/usr/local/go"
export GOPATH="${GOPATH:-$HOME/Tools/Go-Tools}"
export PATH="$GOPATH/bin:$GOROOT/bin:$PATH"
export PATH="$HOME/.local/bin:$PATH"
fi
if [[ -f "$HOME/.cargo/env" ]]; then
source "$HOME/.cargo/env"
fi
#set -eu
#set -o pipefail
export GIT_CLONE_TIMEOUT=300
declare -gA BINARY_NAME_MAP=(
["xnlinkfinder"]="xnLinkFinder"
["golinkfinder"]="GoLinkFinder"
["gxss"]="Gxss"
["uforall"]="UForAll"
["wcvs"]="Web-Cache-Vulnerability-Scanner"
)
menu_cleanup() {
$CLEANUP_RUNNING && exit 0
CLEANUP_RUNNING=true
[[ $(ps -o stat= -p $$) =~ T ]] && exit 0
echo -e "\n\nExiting menu gracefully due to user request. Goodbye!"
if [[ -n "${SUDO_REFRESH_PID:-}" ]] && kill -0 "$SUDO_REFRESH_PID" 2>/dev/null; then
kill "$SUDO_REFRESH_PID" 2>/dev/null || true
fi
if [[ -n "${SPINNER_PID:-}" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
kill -9 "$SPINNER_PID" 2>/dev/null || true
wait "$SPINNER_PID" 2>/dev/null || true
fi
find /tmp -maxdepth 1 -name 'sorted_tools.tmp.*' -type f -user "$(id -u)" -delete 2>/dev/null || true
find /tmp -maxdepth 1 -name 'tmp.*' -type f -user "$(id -u)" -delete 2>/dev/null || true
exit 0
}
cleanup_on_exit() {
$CLEANUP_RUNNING && return
CLEANUP_RUNNING=true
local exit_code=$?
if [[ $exit_code -ne 0 ]]; then
if [[ $exit_code -eq 130 || $exit_code -eq 148 ]]; then
:
else
echo -e "\n\nPerforming cleanup before exit (Code: $exit_code)..."
fi
fi
if [[ -n "${SUDO_REFRESH_PID:-}" ]] && kill -0 "$SUDO_REFRESH_PID" 2>/dev/null; then
kill "$SUDO_REFRESH_PID" 2>/dev/null || true
fi
if [[ -n "${SPINNER_PID:-}" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
kill -9 "$SPINNER_PID" 2>/dev/null || true
wait "$SPINNER_PID" 2>/dev/null || true
fi
find /tmp -maxdepth 1 -name 'sorted_tools.tmp.*' -type f -user "$(id -u)" -delete 2>/dev/null || true
find /tmp -maxdepth 1 -name 'tmp.*' -type f -user "$(id -u)" -delete 2>/dev/null || true
if [[ $exit_code -ne 0 && $exit_code -ne 130 && $exit_code -ne 148 ]]; then
echo "Cleanup finished."
fi
trap - EXIT
exit $exit_code
}
trap menu_cleanup SIGINT SIGTSTP
trap cleanup_on_exit EXIT
declare -A TOOLS_DB=(
["amass"]="recon-enum|Amass|go install github.com/owasp-amass/amass/v3/...@latest|DNS enumeration and network mapping|Subdomains, IP ranges, DNS records"
["subfinder"]="recon-enum|Subfinder|go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest|Passive subdomain enumeration|Subdomains from 30+ sources"
["assetfinder"]="recon-enum|Assetfinder|go install github.com/tomnomnom/assetfinder@latest|Find assets from various sources|Domains, IPs, certificates"
["crobat"]="recon-enum|Crobat|go install github.com/cgboal/sonarsearch/cmd/crobat@latest|Query historical DNS database|DNS history, past subdomains"
["asnmap"]="recon-enum|Asnmap|go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest|Map Autonomous System Numbers|IP ranges, ASN details"
["dnsx"]="recon-enum|Dnsx|go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest|Multi-threaded DNS resolver|DNS records (A, CNAME, MX, TXT, etc.)"
["puredns"]="recon-enum|Puredns|go install github.com/d3mondev/puredns/v2@latest|DNS bruteforce and wildcard filtering|Hidden subdomains, valid DNS zones"
["cero"]="recon-enum|Cero|go install github.com/glebarez/cero@latest|Extract subdomains from TLS certs|Subdomains, SANs from certificates"
["certinfo"]="recon-enum|Certinfo|go install github.com/rix4uni/certinfo@latest|Extract details from TLS certs|Certificate details, common names, SANs"
["chaos"]="recon-enum|Chaos|go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest|Query Chaos public dataset|Subdomains from the Chaos dataset"

["github-subdomains"]="recon-enum|Github-subdomains|go install github.com/gwen001/github-subdomains@latest|Find subdomains in GitHub code|Subdomains from GitHub search results"
["goaltdns"]="recon-enum|Goaltdns|go install github.com/subfinder/goaltdns@latest|Generate permutations for subdomains|Potential subdomains via mutations"
["gotator"]="recon-enum|Gotator|go install github.com/Josue87/gotator@latest|Advanced permutation subdomain generator|Complex subdomain permutations"

["go-dork"]="osint-recon|go-dork|go install github.com/dwisiswant0/go-dork@latest|Google dorking tool|Fast command-line tool for running Google dork queries"

["hakrevdns"]="recon-enum|Hakrevdns|go install github.com/hakluke/hakrevdns@latest|Massive reverse DNS lookups|Hostnames from large IP ranges"
["haktrails"]="recon-enum|Haktrails|go install github.com/hakluke/haktrails@latest|Query SecurityTrails API|Subdomains, historical DNS"
["haktrailsfree"]="recon-enum|Haktrailsfree|go install github.com/rix4uni/haktrailsfree@latest|Free SecurityTrails subdomain enum|Subdomains using free API tier"

["massdns"]="recon-enum|MassDNS|( rm -rf \"$HOME/build-temp/massdns\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/blechschmidt/massdns.git \"$HOME/build-temp/massdns\" && cd \"$HOME/build-temp/massdns\" && make && sudo cp bin/massdns /usr/local/bin/ )|High-speed DNS resolver|Resolved IP addresses for domain lists"

["proxify"]="proxy-manip|proxify|go install github.com/projectdiscovery/proxify/cmd/proxify@latest|Swiss Army knife proxy|Capture, manipulate, and replay HTTP/HTTPS traffic"

["shosubgo"]="recon-enum|Shosubgo|go install github.com/incogbyte/shosubgo@latest|Enumerate subdomains from Shodan|Subdomains from Shodan.io"
["shuffledns"]="recon-enum|Shuffledns|go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest|DNS resolver and bruteforcer|Valid subdomains from a wordlist"
["subdog"]="recon-enum|Subdog|go install github.com/rix4uni/subdog@latest|Passive subdomain enumeration|Passive subdomains"

["subjack"]="sub-takeover|Subjack|go install github.com/haccer/subjack@latest|Subdomain takeover scanner|Checks a list of subdomains for takeover vulnerabilities"
["wcvs"]="vuln-scan|WCVS|go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest|Web Cache Poisoning scanner|Scans for web cache poisoning and deception vulnerabilities"

["altdns"]="recon-enum|Altdns|pipx install --force git+https://github.com/infosec-au/altdns.git|Generate subdomain permutations|New subdomains from permutations"
["dnsgen"]="recon-enum|Dnsgen|pip3 install dnsgen --break-system-packages|Generate domain permutations|Permuted subdomains for bruteforcing"
["ripgen"]="recon-enum|Ripgen|export PATH=\"$HOME/.cargo/bin:$PATH\" && cargo install ripgen|Permutation generator for DNS|Wordlist mutations for subdomain fuzzing"
["analyticsrelationships"]="recon-enum|AnalyticsRelationships|( export GOPATH=\"$HOME/Tools/Go-Tools\" && rm -rf \"$HOME/build-temp/AnalyticsRelationships\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Josue87/AnalyticsRelationships.git \"$HOME/build-temp/AnalyticsRelationships\" && cd \"$HOME/build-temp/AnalyticsRelationships\" && go mod tidy && go build -ldflags=\"-s\" -o \"$GOPATH/bin/analyticsrelationships\" )|Find domains with same Google Analytics ID|Related domains via analytics ID"
["crt"]="recon-enum|Crt|go install github.com/cemulus/crt@latest|Certificate Transparency log search|Subdomains from CT logs"
["cspfinder"]="recon-enum|Cspfinder|go install github.com/rix4uni/cspfinder@latest|Find domains in CSP headers|Domains and subdomains from CSP"
["csprecon"]="recon-enum|Csprecon|go install github.com/edoardottt/csprecon/cmd/csprecon@latest|Discover domains from CSP headers|Domains from Content-Security-Policy"
["emailfinder"]="recon-enum|Emailfinder|go install github.com/rix4uni/emailfinder@latest|Find email addresses for a domain|Email addresses"
["favirecon"]="recon-enum|Favirecon|go install github.com/edoardottt/favirecon/cmd/favirecon@latest|Find assets via favicon hashing|Related domains, tech stacks"
["favinfo"]="recon-enum|Favinfo|go install github.com/rix4uni/favinfo@latest|Extract info from favicons|Tech stacks, related assets"
["github-endpoints"]="recon-enum|Github-endpoints|go install github.com/gwen001/github-endpoints@latest|Find endpoints in GitHub code|API endpoints, URLs"
["hakip2host"]="recon-enum|Hakip2host|go install github.com/hakluke/hakip2host@latest|Find hostnames for IPs|Hostnames from IP addresses"
["ip2org"]="recon-enum|Ip2org|go install github.com/rix4uni/ip2org@latest|Get organization name for an IP|Organization names"
["ipfinder"]="recon-enum|Ipfinder|go install github.com/rix4uni/ipfinder@latest|Find IPs and subnets for a company|IP ranges, subnets"
["org2asn"]="recon-enum|Org2asn|go install github.com/rix4uni/org2asn@latest|Get ASN for an organization|Autonomous System Numbers"
["tldfinder"]="recon-enum|Tldfinder|go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest|Find other TLDs for a domain|Associated TLDs for a brand"
["whoxysubs"]="recon-enum|Whoxysubs|go install github.com/rix4uni/whoxysubs@latest|Find subdomains using Whoxy API|Subdomains from Whois records"
["xsubfind3r"]="recon-enum|Xsubfind3r|go install github.com/hueristiq/xsubfind3r/cmd/xsubfind3r@latest|Powerful passive subdomain enumerator|Subdomains from various sources"
["katana"]="web-crawl|Katana|go install github.com/projectdiscovery/katana/cmd/katana@latest|Fast web crawler with JS parsing|URLs, endpoints, forms, links"
["gospider"]="web-crawl|Gospider|go install github.com/jaeles-project/gospider@latest|Web spider with JS execution|Dynamic URLs, AJAX endpoints"
["hakrawler"]="web-crawl|Hakrawler|go install github.com/hakluke/hakrawler@latest|Simple recursive web crawler|All accessible URLs and endpoints"
["gau"]="web-crawl|Gau|go install github.com/lc/gau/v2/cmd/gau@latest|Fetch historical URLs|Past URLs, deleted endpoints"
["waybackurls"]="web-crawl|Waybackurls|go install github.com/tomnomnom/waybackurls@latest|Extract URLs from Wayback Machine|Archived URLs, old endpoints"
["crawley"]="web-crawl|Crawley|go install github.com/s0rg/crawley/cmd/crawley@latest|Web page crawler|URLs, endpoints, links"
["gourlex"]="web-crawl|Gourlex|go install github.com/trap-bytes/gourlex@latest|Collect URLs from various sources|URLs from Wayback, CommonCrawl, etc."
["pathfinder"]="web-crawl|Pathfinder|( rm -rf \"$HOME/build-temp/pathfinder\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Print3M/pathfinder.git \"$HOME/build-temp/pathfinder\" && cd \"$HOME/build-temp/pathfinder\" && go build && sudo mv pathfinder /usr/local/bin/ )|Discover URL paths from JS files|Paths and endpoints from JS"
["roboxtractor"]="web-crawl|Roboxtractor|( rm -rf \"$HOME/build-temp/roboxtractor\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Josue87/roboxtractor.git \"$HOME/build-temp/roboxtractor\" && cd \"$HOME/build-temp/roboxtractor\" && go build && sudo mv roboxtractor /usr/local/bin/ )|Extract URLs from robots.txt|Endpoints listed in robots.txt"
["urlgrab"]="web-crawl|Urlgrab|( rm -rf \"$HOME/build-temp/urlgrab\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/iamstoxe/urlgrab.git \"$HOME/build-temp/urlgrab\" && cd \"$HOME/build-temp/urlgrab\" && export GOPATH=\"$HOME/Tools/Go-Tools\" && go build -o \"$GOPATH/bin/urlgrab\" && chmod +x \"$GOPATH/bin/urlgrab\" )|Extract URLs from web pages|URLs from HTML source"
["waymore"]="web-crawl|Waymore|pipx install waymore|Find more URLs from Wayback Machine|Extensive URLs from multiple archives"
["xcrawl3r"]="web-crawl|Xcrawle3r|go install github.com/hueristiq/xcrawl3r/cmd/xcrawl3r@latest|Extensive URL crawler|URLs from multiple historical archives"
["golinkfinder"]="web-crawl|GoLinkFinder|go install github.com/rix4uni/GoLinkFinder@latest|Find links in web pages|URLs, endpoints, social media links"
["linx"]="web-crawl|Linx|go install github.com/riza/linx/cmd/linx@latest|Extract links from a website|All links from a given URL"
["pathcrawler"]="web-crawl|Pathcrawler|go install github.com/rix4uni/pathcrawler@latest|Crawl paths from JS files|File paths, API endpoints"
["robotxt"]="web-crawl|Robotxt|go install github.com/rix4uni/robotxt@latest|Extract endpoints from robots.txt|Disallowed paths, sitemaps"
["urlfinder"]="web-crawl|Urlfinder|go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest|Find URLs in JS and HTML|URLs and endpoints"
["xurlfind3r"]="web-crawl|Xurlfind3r|go install github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@latest|Fetch URLs from curated sources|URLs from AlienVault, Wayback, etc."
["sqlmap"]="sqli-detect|SQLMap|sudo apt-get install -y sqlmap|Automated SQLi detection & exploitation|SQL injection, database dumps, auth bypass"
["gosqli"]="sqli-detect|Gosqli|go install github.com/rix4uni/gosqli@latest|Find parameters vulnerable to SQLi|Vulnerable query parameters"
["ghauri"]="exploit|Ghauri|( command -v pip3 >/dev/null && rm -rf \"$HOME/build-temp/ghauri\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/r0oth3x49/ghauri.git \"$HOME/build-temp/ghauri\" && cd \"$HOME/build-temp/ghauri\" && pip3 install -r requirements.txt --break-system-packages && pip3 install . --break-system-packages )|Advanced SQLi exploitation tool|Complex SQLi, WAF bypass"
["dalfox"]="xss-detect|Dalfox|go install github.com/hahwul/dalfox/v2@latest|Reflected & DOM XSS scanner|Reflected XSS, DOM XSS, parameter injection"
["kxss"]="xss-detect|Kxss|go install github.com/Emoe/kxss@latest|Parameter-based Reflected XSS|XSS in query/form parameters"
["gxss"]="xss-detect|Gxss|go install github.com/KathanP19/Gxss@latest|Reflected XSS scanner|Reflected XSS payloads"
["xsschecker"]="xss-detect|Xsschecker|go install github.com/rix4uni/xsschecker@latest|XSS vulnerability verification|Confirmation of XSS in various contexts"
["xssrecon"]="xss-detect|Xssrecon|( rm -rf \"$HOME/build-temp/xssrecon\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/rix4uni/xssrecon.git \"$HOME/build-temp/xssrecon\" && cd \"$HOME/build-temp/xssrecon\" && go install )|Comprehensive XSS reconnaissance|Stored, Reflected, DOM, and Blind XSS"
["crlfuzz"]="http-inject|Crlfuzz|go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest|CRLF injection scanner|CRLF injection, HTTP response splitting"
["galer"]="http-inject|Galer|go install github.com/dwisiswant0/galer@latest|HTTP header analyzer|Header bypass techniques, injection points"
["ffuf"]="fuzzing|Ffuf|go install github.com/ffuf/ffuf/v2@latest|Fast web fuzzer|Hidden dirs, vhosts, parameters"
["gobuster"]="fuzzing|Gobuster|go install github.com/OJ/gobuster/v3@latest|Directory and DNS bruteforcing|Hidden dirs, subdomains, file backups"
["fuzzuli"]="fuzzing|Fuzzuli|go install github.com/musana/fuzzuli@latest|Simple parameter and directory fuzzer|Fuzzy matches in endpoints"
["subdomainfuzz"]="fuzzing|Subdomainfuzz|go install github.com/rix4uni/subdomainfuzz@latest|Subdomain enumeration via fuzzing|Non-standard subdomains"
["dirsearch"]="fuzzing|Dirsearch|pipx install dirsearch|Advanced web path scanner|Hidden directories, files, backup pages"
["feroxbuster"]="fuzzing|Feroxbuster|set -e; wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip -O /tmp/ferox.zip; unzip -o /tmp/ferox.zip -d /tmp; sudo dpkg -i /tmp/feroxbuster*.deb; rm /tmp/ferox.zip /tmp/feroxbuster*.deb|Recursive content discovery|Hidden files and directories"
["ppfuzz"]="fuzzing|Ppfuzz|set -e; wget https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.2/ppfuzz-v1.0.2-x86_64-unknown-linux-musl.tar.gz -O /tmp/ppfuzz.tar.gz; tar -xzf /tmp/ppfuzz.tar.gz -C /tmp; sudo mv /tmp/ppfuzz /usr/local/bin/; rm /tmp/ppfuzz.tar.gz|Prototype Pollution Fuzzer|Prototype Pollution vulnerabilities"
["arjun"]="fuzzing|Arjun|pipx install arjun|HTTP parameter discovery suite|Hidden GET/POST parameters"
["paramfinder"]="fuzzing|Paramfinder|go install github.com/rix4uni/paramfinder@latest|Find hidden parameters|GET/POST parameters"
["msarjun"]="fuzzing|Msarjun|go install github.com/rix4uni/msarjun@latest|Find hidden parameters in multiple URLs|Hidden parameters across many endpoints"
["shortscan"]="fuzzing|Shortscan|go install github.com/bitquark/shortscan/cmd/shortscan@latest|IIS short file name scanner|IIS tilde enumeration vulnerabilities"
["naabu"]="scanning|Naabu|go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest|Fast port scanner|Open ports, running services"
["masscan"]="scanning|Masscan|sudo apt-get install -y masscan|Internet-scale port scanner|All listening ports on networks"
["httpx"]="scanning|Httpx|go install github.com/projectdiscovery/httpx/cmd/httpx@latest|HTTP server prober|Live web servers, tech, redirects"
["httprobe"]="scanning|Httprobe|go install github.com/tomnomnom/httprobe@latest|Check for HTTP/HTTPS servers|Accessible web services"
["smap"]="scanning|Smap|go install github.com/s0md3v/smap/cmd/smap@latest|Port scanner with Shodan integration|Open ports and service banners"
["aquatone"]="scanning|Aquatone|set -e; wget \"https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip\" -O /tmp/aquatone.zip; unzip -o /tmp/aquatone.zip -d /tmp; sudo mv /tmp/aquatone /usr/local/bin/; rm /tmp/aquatone.zip|Visual inspection of websites|Screenshots of web services"
["ftpx"]="scanning|Ftpx|go install github.com/rix4uni/ftpx@latest|FTP vulnerability scanner|Anonymous FTP access, sensitive files"
["gowitness"]="scanning|Gowitness|go install github.com/sensepost/gowitness@latest|Website screenshotting tool|Visual recon via screenshots"
["portmap"]="scanning|Portmap|go install github.com/rix4uni/portmap@latest|Map open ports for a list of hosts|Open ports"
["techx"]="scanning|Techx|go install github.com/rix4uni/techx@latest|Technology detection tool|Web technologies (frameworks, servers)"
["x8"]="scanning|x8|set -e; wget https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz -O /tmp/x8.gz; gunzip /tmp/x8.gz; chmod +x /tmp/x8; sudo mv /tmp/x8 /usr/local/bin/|Hidden parameter discovery|Bruteforce hidden parameters"
["gitleaks"]="secrets|Gitleaks|go install github.com/zricethezav/gitleaks/v8@latest|Scan git repos for secrets|Exposed secrets, API keys, tokens"
["trufflehog"]="secrets|Trufflehog|curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b \"$HOME/Tools/Go-Tools/bin\"|Scan for secrets in multiple sources|AWS keys, DB creds, tokens"
["cariddi"]="secrets|Cariddi|go install github.com/edoardottt/cariddi/cmd/cariddi@latest|Find sensitive data during crawling|Passwords, API keys, emails, paths"
["gitrepoenum"]="secrets|Gitrepoenum|go install github.com/rix4uni/gitrepoenum@latest|Enumerate .git repositories on a domain|Exposed .git directories"
["goop"]="secrets|Goop|go install github.com/deletescape/goop@latest|Search for exposed .git directories|Exposed .git directories"
["dotgit"]="secrets|Dotgit|pipx install dotgit|Extract .git repositories|Source code from exposed .git folders"
["hakcheckurl"]="auth-test|Hakcheckurl|go install github.com/hakluke/hakcheckurl@latest|Check URL validity and response codes|Valid endpoints, 401/403 auth issues"
["hakoriginfinder"]="auth-test|Hakoriginfinder|go install github.com/hakluke/hakoriginfinder@latest|Find origin servers behind WAFs|Real origin IPs, WAF bypass"
["corscanner"]="auth-test|Corscanner|pipx install corscanner|Scan for CORS misconfigurations|CORS vulnerabilities"
["unfurl"]="url-analysis|Unfurl|go install github.com/tomnomnom/unfurl@latest|Parse and extract URL components|Parameters, patterns in URLs"
["gron"]="url-analysis|Gron|go install github.com/tomnomnom/gron@latest|Make JSON greppable|API responses, JSON data"
["qsreplace"]="url-analysis|Qsreplace|go install github.com/tomnomnom/qsreplace@latest|Replace query string values|Parameter mutation, injection payloads"
["anew"]="url-analysis|Anew|go install github.com/tomnomnom/anew@latest|Append only new lines to files|Unique URLs, deduplication"
["meg"]="url-analysis|Meg|go install github.com/tomnomnom/meg@latest|Fetch multiple URLs|Titles, redirects, body content"
["alterx"]="url-analysis|Alterx|go install github.com/projectdiscovery/alterx/cmd/alterx@latest|Alter and filter URL parameters|Parameter tampering, value replacement"
["dlevel"]="url-analysis|Dlevel|go install github.com/rix4uni/dlevel@latest|Extract URLs of a specific depth|URLs filtered by path depth"
["dmut"]="url-analysis|Dmut|go install github.com/bp0lr/dmut@latest|Domain mutation and permutation|Potential phishing domains"
["fff"]="url-analysis|Fff|go install github.com/tomnomnom/fff@latest|Fast web fetcher|Mass HTTP requests"
["haklistgen"]="url-analysis|Haklistgen|go install github.com/hakluke/haklistgen@latest|Generate wordlists from web pages|Custom wordlists from site content"
["urldedupe"]="url-analysis|UrlDedupe|( rm -rf \"$HOME/build-temp/urldedupe\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/ameenmaali/urldedupe.git \"$HOME/build-temp/urldedupe\" && cd \"$HOME/build-temp/urldedupe\" && cmake CMakeLists.txt && make && sudo cp urldedupe /usr/local/bin/ )|Fast URL deduplication|Unique URLs from large lists"
["uro"]="url-analysis|Uro|pipx install uro|Deduplicate, filter, and analyze URLs|URL list management, deduplication"
["recollapse"]="url-analysis|Recollapse|pipx install --force git+https://github.com/0xacb/recollapse.git|Collapse wordlists for bruteforcing|Wordlist optimization"
["linkinspector"]="url-analysis|Linkinspector|go install github.com/rix4uni/linkinspector@latest|Inspect and categorize links|Internal, external, and social media links"
["mantra"]="url-analysis|Mantra|go install github.com/Brosck/mantra@latest|Find secrets in web pages|API keys, tokens, sensitive info"
["oosexclude"]="url-analysis|Oosexclude|go install github.com/rix4uni/oosexclude@latest|Exclude out-of-scope URLs|Filtered URL lists"
["pvreplace"]="url-analysis|Pvreplace|go install github.com/rix4uni/pvreplace@latest|Replace parameter values in URLs|Payload injection, parameter fuzzing"
["uforall"]="url-analysis|UForAll|go install github.com/rix4uni/UForAll@latest|Generate URLs from a list of hosts|List of URLs for scanning"
["wordgen"]="url-analysis|Wordgen|go install github.com/rix4uni/wordgen@latest|Generate wordlists from web pages|Custom wordlists"
["nuclei"]="vuln-scan|Nuclei|go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest|Template-based vulnerability scanner|CVEs, RCE, SSRF, LFI, auth bypass"
["cvemap"]="vuln-scan|Cvemap|go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest|Map CVEs to technologies|CVE details, vulnerable versions"
["jaeles"]="vuln-scan|Jaeles|go install github.com/jaeles-project/jaeles@latest|Web vulnerability scanner|Multiple vuln types via signatures"
["gf"]="vuln-scan|Gf|go install github.com/tomnomnom/gf@latest|Wrapper to find vulnerabilities|LFI, RCE, SSRF patterns in URLs"
["gungnir"]="vuln-scan|Gungnir|go install github.com/g0ldencybersec/gungnir/cmd/gungnir@latest|Vulnerability scanner|Various web vulnerabilities"
["uncover"]="vuln-scan|Uncover|go install github.com/projectdiscovery/uncover/cmd/uncover@latest|Find vulnerable hosts using search engines|Exposed hosts on Shodan, Censys, etc."
["bbot"]="vuln-scan|Bbot|pipx install bbot|OSINT & reconnaissance framework|Subdomains, vulnerabilities, exposed services"
["wpscan"]="vuln-scan|WPScan|if [ \"${OS_ID:-}\" == \"kali\" ]; then sudo apt-get install -y wpscan; elif command -v gem &>/dev/null; then sudo gem install wpscan; else echo \"Cannot install WPScan: gem not found\"; fi|WordPress vulnerability scanner|Vulnerable plugins, themes, configs"
["sublist3r"]="vuln-scan|Sublist3r|sudo apt-get install -y sublist3r|Subdomain enumeration tool|Subdomains from various search engines"
["getjs"]="js-analysis|GetJS|go install github.com/003random/getJS/v2@latest|Extract JavaScript files|All JS files, endpoints in code"
["jsfinder"]="js-analysis|Jsfinder|go install github.com/kacakb/jsfinder@latest|Find endpoints in JavaScript|API endpoints, hidden URLs from JS"
["jsubfinder"]="js-analysis|Jsubfinder|go install github.com/ThreatUnkown/jsubfinder@latest|Find subdomains in JavaScript|Subdomains hardcoded in JS"
["jsluice"]="js-analysis|Jsluice|go install github.com/BishopFox/jsluice/cmd/jsluice@latest|Extract secrets from JavaScript|API endpoints, tokens, config data"
["subjs"]="js-analysis|Subjs|go install github.com/lc/subjs@latest|Extract subdomains from JavaScript|Referenced subdomains in JS code"
["linkfinder"]="js-analysis|LinkFinder|( command -v pip3 >/dev/null && rm -rf \"$HOME/build-temp/LinkFinder\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/GerbenJavado/LinkFinder.git \"$HOME/build-temp/LinkFinder\" && cd \"$HOME/build-temp/LinkFinder\" && pip3 install -r requirements.txt --break-system-packages && chmod +x linkfinder.py && sudo rm -f /usr/local/bin/linkfinder && sudo cp linkfinder.py /usr/local/bin/linkfinder )|Find endpoints in JavaScript|URLs and endpoints in JS code"
["xnlinkfinder"]="js-analysis|XnLinkFinder|pipx install xnLinkFinder|Find endpoints in various files|URLs and endpoints in JS and other files"
["jshunter"]="js-analysis|Jshunter|go install github.com/cc1a2b/jshunter@latest|Hunt for secrets in JS files|API keys, tokens, sensitive data"
["sourcemapper"]="js-analysis|Sourcemapper|go install github.com/denandz/sourcemapper@latest|Analyze JavaScript source maps|Original source code, hidden endpoints"
["s3scanner"]="cloud|S3Scanner|go install github.com/sa7mon/s3scanner@latest|Scan for open AWS S3 buckets|Public S3 buckets, accessible data"
["cdncheck"]="cloud|Cdncheck|go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest|Identify CDN and real IPs|CDN provider, potential WAF bypass"
["mx-takeover"]="cloud|Mx-takeover|go install github.com/musana/mx-takeover@latest|Check for MX record takeovers|Vulnerable MX records"
["subzy"]="cloud|Subzy|go install github.com/PentestPad/subzy@latest|Subdomain takeover scanner|Vulnerable CNAME/NS records"
["shodan"]="cloud|Shodan|pipx install shodan|Official Shodan CLI client|Exposed services, devices on the internet"
["pler"]="cloud|Pler|pip3 install python-pler --break-system-packages|Check for S3 bucket permissions|S3 bucket misconfigurations"
["spk"]="cloud|Spk|go install github.com/dhn/spk@latest|SPF and DMARC record scanner|Email security misconfigurations"
["notify"]="misc-util|Notify|go install github.com/projectdiscovery/notify/cmd/notify@latest|Send notifications to Slack, Discord|Notifications for long-running scans"
["interactsh-client"]="misc-util|Interactsh-client|go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest|Out-of-band (OAST) client|Blind vulnerabilities (SSRF, XSS)"
["mapcidr"]="misc-util|Mapcidr|go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest|CIDR and IP manipulation utility|IP ranges, CIDR blocks"
["tlsx"]="misc-util|Tlsx|go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest|TLS swiss army knife|TLS versions, cipher suites, SANs"
["interlace"]="misc-util|Interlace|pipx install --force git+https://github.com/codingo/Interlace.git|Handle large target lists|Parallel command execution"
["ssb"]="misc-util|Ssb|curl -sSfL 'https://git.io/kitabisa-ssb' | sudo sh -s -- -b /usr/local/bin|Screenshotting tool|Screenshots of web pages"
["rcert"]="misc-util|Rcert|( rm -rf \"$HOME/build-temp/rcert\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/rix4uni/rcert.git \"$HOME/build-temp/rcert\" && sudo mv \"$HOME/build-temp/rcert/rcert\" /usr/local/bin/ && sudo chmod +x /usr/local/bin/rcert )|Reverse certificate lookup|Domains sharing the same certificate"
["timelimitx"]="misc-util|Timelimitx|go install github.com/rix4uni/timelimitx@latest|Timeout wrapper for commands|Time-limited command execution"
["udon"]="misc-util|Udon|go install github.com/dhn/udon@latest|URL decoder/encoder|URL encoding/decoding"
)
PREREQUISITES_MET=false
GREEN='\033[0;32m'; YELLOW='\033[1;33m'; RED='\033[0;31m'; CYAN='\033[0;36m'; NC='\033[0m'
CUSTOM_DB_FILE="$HOME/.pen-forge-custom.db"
declare -gA CUSTOM_TOOLS_DB
declare -gA CUSTOM_TOOLS_INDEX_TO_KEY
#grep_fixed_string_quote() {
#printf '%s' "$1"
#}
check_critical_commands() {
local missing=0
local cmd
for cmd in "$@"; do
if ! command -v "$cmd" &>/dev/null; then
echo -e "${RED}[x] CRITICAL: Command '$cmd' not found. Please install it.${NC}" >&2
missing=1
fi
done
return $missing
}
keep_sudo_alive() {
while true; do
if ! sudo -v; then
echo -e "\n${RED}[!] sudo refresh failed. Exiting keep-alive loop.${NC}" >&2
exit 1
fi
sleep 240
done
}
ensure_critical_packages() {
local packages=("$@")
local missing=()
for pkg in "${packages[@]}"; do
if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
missing+=("$pkg")
fi
done
if [[ ${#missing[@]} -gt 0 ]]; then
echo -e "${YELLOW}[*] Missing critical packages: ${missing[*]}${NC}"
echo -e "${YELLOW}[*] Installing automatically...${NC}"
if ! sudo apt-get update -qq; then
echo -e "${RED}[x] Failed to update package lists${NC}"
return 1
fi
if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}"; then
echo -e "${RED}[x] Failed to install: ${missing[*]}${NC}"
return 1
fi
echo -e "${GREEN}[+] Successfully installed: ${missing[*]}${NC}"
fi
return 0
}
START_SPINNER() {
if [[ -n "${SPINNER_PID:-}" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
kill -9 "$SPINNER_PID" 2>/dev/null || true
wait "$SPINNER_PID" 2>/dev/null || true
unset SPINNER_PID
printf "\033[G\033[K"
fi
local processing="${1}"; START_TIME=$(date +%s)
local chars=("⠋" "⠙" "⠹" "⠸" "⠼" "⠴" "⠦" "⠧" "⠇" "⠏")
local parent_pid=$$
(
trap '' EXIT INT TERM TSTP
local warning_shown=false
while true; do
local elapsed=$(( $(date +%s) - START_TIME ))
if [[ $elapsed -ge 500 ]] && [[ "$warning_shown" == false ]]; then
printf "\n${YELLOW}[!] This is taking longer than expected (compiling?). (Abort if stuck.) ${NC}\n"
warning_shown=true
fi
for char in "${chars[@]}"; do
if ! kill -0 $parent_pid 2>/dev/null; then exit 0; fi
printf "\033[G${YELLOW}[%s]${NC} %s ${CYAN}(%ss)${NC} \033[K" "${char}" "${processing}" "${elapsed}"
sleep 0.05
done
done
) &
SPINNER_PID=$!
}
STOP_SPINNER() {
if [[ -n "${SPINNER_PID:-}" ]] && kill -0 "$SPINNER_PID" 2>/dev/null; then
kill -9 "$SPINNER_PID" 2>/dev/null || true
wait "$SPINNER_PID" 2>/dev/null || true
fi
unset SPINNER_PID
if [[ -n "${START_TIME:-}" ]]; then
if [[ "$START_TIME" =~ ^[0-9]+$ ]]; then
TIME=$(( $(date +%s) - START_TIME ))
else
TIME=0
fi
else
TIME=0
fi
printf "\033[G\033[K"
}
install_tool_robust() {
local display_name="$1"
local check_command="$2"
local install_command="$3"
local check_key="${check_command,,}"
if [[ -n "$check_command" ]] && [[ -v BINARY_NAME_MAP["$check_key"] ]]; then
local actual_binary="${BINARY_NAME_MAP["$check_key"]}"
check_command="$actual_binary"
fi
local max_attempts=3
local -r TOOL_INSTALL_TIMEOUT=900
local LOG_FILE=""
trap '[[ -n "$LOG_FILE" ]] && rm -f "$LOG_FILE" 2>/dev/null' RETURN
local tool_exists=false
local gopath_bin=""
if [[ -n "${GOPATH:-}" && -n "$check_command" ]]; then
gopath_bin="$GOPATH/bin/$check_command"
fi
local pipx_bin="$HOME/.local/bin/$check_command"
if [[ -n "$check_command" ]]; then
if command -v "$check_command" &>/dev/null || \
[[ -n "$gopath_bin" && -x "$gopath_bin" ]] || \
[[ -x "$pipx_bin" ]]; then
tool_exists=true
fi
fi
if [[ "${IS_MANUAL_INSTALL:-false}" == false ]] && [[ "${FORCE_UPDATE:-false}" == false ]] && [[ "$tool_exists" == true ]]; then
printf "${YELLOW}[~] %-25s - SKIPPED${NC}\n" "$display_name"
local local_bin="/usr/local/bin/$check_command"
trap - RETURN
return 0
fi
for attempt in $(seq 1 $max_attempts); do
if [ $attempt -gt 1 ]; then
local sleep_time=$((5 * (1 << (attempt - 1))))
echo -e "${YELLOW}[~] Retrying installation for $display_name in ${sleep_time}s (attempt $attempt/$max_attempts)...${NC}"
sleep $sleep_time
fi
if [[ "${IS_MANUAL_INSTALL:-false}" == true ]]; then
echo -e "${CYAN}[*] Performing pre-installation cleanup for manual install...${NC}"
START_SPINNER "Cleaning Go module cache"
if command -v go &>/dev/null; then
go clean -cache -modcache &>/dev/null || true
else
echo "Go command not found, skipping modcache clean." &>/dev/null
fi
STOP_SPINNER
printf "${GREEN}[+] Go module cache cleaned: %s seconds${NC}\n" "$TIME"
fi
sync; echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null 2>&1
if [[ "${IS_MANUAL_INSTALL:-false}" == true ]]; then
echo -e "${CYAN}[*] Installing $display_name ${NC}"
fi
START_SPINNER "Installing $display_name"
LOG_FILE=$(mktemp)
if [[ -z "$LOG_FILE" ]]; then
STOP_SPINNER
printf "${RED}[x] %-25s - FAILED: Could not create temporary log file.${NC}\n" "$display_name"
return 1
fi
local current_goroot="${GOROOT:-/usr/local/go}"
local current_gopath="${GOPATH:-$HOME/Tools/Go-Tools}"
local current_path="${PATH:-}"
local subshell_path="$current_path"
[[ ":$subshell_path:" != *":$current_gopath/bin:"* ]] && subshell_path="$current_gopath/bin:$subshell_path"
[[ ":$subshell_path:" != *":$current_goroot/bin:"* ]] && subshell_path="$current_goroot/bin:$subshell_path"
[[ ":$subshell_path:" != *":$HOME/.cargo/bin:"* ]] && subshell_path="$HOME/.cargo/bin:$subshell_path"
[[ ":$subshell_path:" != *":$HOME/.local/bin:"* ]] && subshell_path="$HOME/.local/bin:$subshell_path"
local env_setup="export GOROOT='$current_goroot'; \
export GOPATH='$current_gopath'; \
export PATH='$subshell_path'; \
export GIT_CLONE_TIMEOUT='${GIT_CLONE_TIMEOUT}'; \
export TMPDIR='$HOME/build-temp/go-build'; \
source '$HOME/.cargo/env' 2>/dev/null || true;"
env_setup+=" \
export GOMEMLIMIT='2GiB'; \
export GOFLAGS='-buildvcs=false';"
echo "[DEBUG] $(date): Running command for $display_name: $env_setup $install_command" >> /tmp/pen-forge-install.log
timeout --signal=INT --kill-after=10s "$TOOL_INSTALL_TIMEOUT" bash -c "
trap 'echo \"[DEBUG SUB] Received INT, exiting with 130\" >> /tmp/pen-forge-install.log; exit 130' INT
err_report() {
local err_code=\$?
echo \"[DEBUG SUB][$$] Error on line \$1: command '\$BASH_COMMAND' failed with exit code \$err_code.\" >> /tmp/pen-forge-install.log
}
trap 'err_report \$LINENO' ERR
set -e
echo \"[DEBUG SUB][$$] Environment setup: ${env_setup}\" >> /tmp/pen-forge-install.log
echo \"[DEBUG SUB][$$] Effective command: ${install_command}\" >> /tmp/pen-forge-install.log
echo \"[DEBUG SUB][$$] GOFLAGS=\$(env | grep GOFLAGS || echo 'GOFLAGS not set')\" >> /tmp/pen-forge-install.log
echo \"[DEBUG SUB][$$] GOMEMLIMIT=\$(env | grep GOMEMLIMIT || echo 'GOMEMLIMIT not set')\" >> /tmp/pen-forge-install.log
echo \"[DEBUG SUB][$$] PATH=\$(env | grep PATH)\" >> /tmp/pen-forge-install.log
echo \"[DEBUG SUB][$$] --- Starting actual command --- \" >> /tmp/pen-forge-install.log
$env_setup eval \"${install_command}\"
cmd_exit_code=\$?
echo \"[DEBUG SUB][$$] --- Command sequence finished (final exit code: \$cmd_exit_code) --- \" >> /tmp/pen-forge-install.log
exit \$cmd_exit_code
" &> "$LOG_FILE"
local EXIT_CODE=$?
STOP_SPINNER
if [[ $EXIT_CODE -eq 0 ]] && grep -qi "already seems to be installed" "$LOG_FILE"; then
local tool_found_after_pipx=false
if [[ -n "$check_command" ]]; then
if command -v "$check_command" &>/dev/null || \
[[ -n "$gopath_bin" && -x "$gopath_bin" ]] || \
[[ -x "$pipx_bin" ]]; then
tool_found_after_pipx=true
fi
fi
if $tool_found_after_pipx; then
printf "${YELLOW}[~] %-25s - ALREADY INSTALLED${NC}\n" "$display_name"
trap - RETURN; rm -f "$LOG_FILE" 2>/dev/null; return 0
else
local mapped_name_key="${check_command,,}"
local mapped_name="${BINARY_NAME_MAP[$mapped_name_key]:-$check_command}"
printf "${YELLOW}[!] %-25s - INSTALLED (pipx) but binary '$check_command' not found. Check name.${NC}\n" "$display_name"
echo -e "${YELLOW}    Hint: Binary name might be different (e.g., $mapped_name).${NC}"
trap - RETURN; rm -f "$LOG_FILE" 2>/dev/null; return 0
fi
fi
if sudo dmesg 2>/dev/null | tail -20 | grep -qi "killed process"; then
printf "${RED}[x] %-25s - FAILED: KILLED BY OOM KILLER${NC}\n" "$display_name"
if [[ -f "$LOG_FILE" ]]; then
echo -e "${YELLOW}--- Log (potential OOM context) ---${NC}"
if [[ $(wc -l < "$LOG_FILE") -le 30 ]]; then cat "$LOG_FILE"; else tail -30 "$LOG_FILE"; fi
echo -e "${YELLOW}---------------------------------${NC}"
fi
return 1
fi
hash -r; sleep 0.1
local tool_found_after=false
if [[ -n "$check_command" ]]; then
if command -v "$check_command" &>/dev/null || \
[[ -n "$gopath_bin" && -x "$gopath_bin" ]] || \
[[ -x "$pipx_bin" ]]; then
tool_found_after=true
fi
else
if [[ $EXIT_CODE -eq 0 ]]; then
echo -e "${YELLOW}[~] Warning: No check command for $display_name, assuming success based on exit code 0.${NC}"
tool_found_after=true
fi
fi
local install_failed=false
if [ "$EXIT_CODE" -eq 124 ]; then
printf "${RED}[x] %-25s - FAILED: TIMEOUT (>${TOOL_INSTALL_TIMEOUT}s)${NC}\n" "$display_name"
install_failed=true
elif [ "$EXIT_CODE" -eq 0 ] && $tool_found_after; then
printf "${GREEN}[+] %-25s - INSTALLED: %s seconds${NC}\n" "$display_name" "$TIME"
trap - RETURN; rm -f "$LOG_FILE" 2>/dev/null; return 0
else
install_failed=true
if [ "$EXIT_CODE" -eq 0 ] && ! $tool_found_after; then
printf "${RED}[x] %-25s - FAILED (Cmd OK but binary '$check_command' missing): %s seconds${NC}\n" "$display_name" "$TIME"
else
printf "${RED}[x] %-25s - FAILED (exit: %s): %s seconds${NC}\n" "$display_name" "$EXIT_CODE" "$TIME"
fi
fi
if [[ "$install_failed" == true ]]; then
echo -e "${YELLOW}--- Log for $display_name (Attempt $attempt/$max_attempts) ---${NC}"
if [[ -f "$LOG_FILE" ]]; then
if [[ $(wc -l < "$LOG_FILE") -le 30 ]]; then
cat "$LOG_FILE"
else
tail -30 "$LOG_FILE"
fi
else
echo "[!] Log file not found."
fi
echo -e "${YELLOW}---------------------------------${NC}"
fi
done
echo -e "${RED}[x] Failed to install $display_name after $max_attempts attempts.${NC}"
return 1
}
show_menu() {
local term_width
term_width=$(tput cols 2>/dev/null) || term_width=80
local threshold=95
if [ "$term_width" -gt "$threshold" ]; then
echo ""
echo "      ██████╗ ███████╗███╗   ██╗       ███████╗ ██████╗ ██████╗  ██████╗ ███████╗      "
echo "      ██╔══██╗██╔════╝████╗  ██║       ██╔════╝██╔═══██╗██╔══██╗██╔════╝ ██╔════╝      "
echo "      ██████╔╝█████╗  ██╔██╗ ██║█████╗ █████╗  ██║   ██║██████╔╝██║  ███╗█████╗        "
echo "      ██╔═══╝ ██╔══╝  ██║╚██╗██║╚════╝ ██╔══╝  ██║   ██║██╔══██╗██║   ██║██╔══╝        "
echo "      ██║     ███████╗██║ ╚████║       ██║     ╚██████╔╝██║  ██║╚██████╔╝███████╗      "
echo "      ╚═╝     ╚══════╝╚═╝  ╚═══╝       ╚═╝      ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝      "
echo "                                                                                       "
echo "                                              GitHub: https://github.com/Nixon-H       "
else
echo ""
echo "      ░█▀█░█▀▀░█▀█░░░░░█▀▀░█▀█░█▀▄░█▀▀░█▀▀      "
echo "      ░█▀▀░█▀▀░█░█░▄▄▄░█▀▀░█░█░█▀▄░█░█░█▀▀      "
echo "      ░▀░░░▀▀▀░▀░▀░░░░░▀░░░▀▀▀░▀░▀░▀▀▀░▀▀▀      "
echo "                                                "
echo "                            GitHub: Nixon-H     "
fi
echo "========================================="
echo "           Pen-Forge Toolkit Menu            "
echo "========================================="
echo "1. Install Toolkit (Full)"
echo "2. Manual Tool Installation"
echo "3. Uninstall Tools"
echo "4. Clean Logs"
echo "5. Custom Tool Management"
echo "6. Help"
echo "7. Exit"
echo "-----------------------------------------"
}
show_help() {
clear
echo "================================ Help ================================="
echo
echo " [1] Install Toolkit (Full):"
echo "        Runs the complete, automated installation script to set up the"
echo "        entire cybersecurity toolkit."
echo
echo " [2] Manual Tool Installation:"
echo "        Browse and install tools individually by category. First run sets up"
echo "        required dependencies (Go, Rust, etc.)."
echo "        - If installation hangs (spinner runs 2+ min), press Ctrl+C to abort"
echo "        - Check logs in /tmp/pen-forge-install.log for detailed error messages"
echo "        - You can retry the installation after fixing issues"
echo
echo " [3] Uninstall Tools:"
echo "        Runs the cleanup script to remove all installed tools,"
echo "        configurations, dependencies, and reconfigures swap memory."
echo
echo " [4] Clean Logs:"
echo "        Removes any 'wget-log' files from the current directory."
echo
echo " [5] Custom Tool Management:"
echo "        Add, install, or remove your own custom tools. Definitions are"
echo "        saved locally for future use."
echo
echo " [6] Help:"
echo "        Shows this help screen."
echo
echo " [7] Exit:"
echo "        Exits the script gracefully."
echo
echo "======================================================================"
read -p "Press [Enter] to return to the menu." < /dev/tty
}
clean_tmp_directory_action() {
echo "-----------------------------------------"
START_SPINNER "Cleaning script-specific logs from /tmp/..."
sleep 0.1
local -a files_to_delete=()
mapfile -d '' files_to_delete < <(find /tmp -maxdepth 1 -type f -user "$(id -u)" \( \
    -name 'pen-forge-install.log' -o \
    -name 'toolkit_uninstall_*.log' -o \
    -name 'sorted_tools.tmp.*' -o \
    -name 'tmp.*' -o \
    -name 'README.md' -o \
    -name 'LICENSE.txt' \
\) -print0 2>/dev/null)
local deleted_count=${#files_to_delete[@]}
if [[ $deleted_count -gt 0 ]]; then
find /tmp -maxdepth 1 -type f -user "$(id -u)" \( \
    -name 'pen-forge-install.log' -o \
    -name 'toolkit_uninstall_*.log' -o \
    -name 'sorted_tools.tmp.*' -o \
    -name 'tmp.*' -o \
    -name 'README.md' -o \
    -name 'LICENSE.txt' \
\) -delete 2>/dev/null || true
fi
STOP_SPINNER
if [[ $deleted_count -eq 0 ]]; then
printf "\033[G\033[K${GREEN}[+] No script logs found in /tmp/. Already clean!${NC}\n"
else
printf "\033[G\033[K${GREEN}[+] Removed $deleted_count script log file(s) from /tmp/.${NC}\n"
fi
}
clean_wget_logs_action() {
echo "-----------------------------------------"
START_SPINNER "Cleaning 'wget-log*' files from current directory..."
sleep 0.1
local -a files_to_delete=()
mapfile -d '' files_to_delete < <(find . -maxdepth 1 -type f -name 'wget-log*' -print0 2>/dev/null)
local deleted_count=${#files_to_delete[@]}
if [[ $deleted_count -gt 0 ]]; then
find . -maxdepth 1 -type f -name 'wget-log*' -delete 2>/dev/null || true
fi
STOP_SPINNER
if [[ $deleted_count -eq 0 ]]; then
printf "\033[G\033[K${GREEN}[+] No 'wget-log*' files found. Already clean!${NC}\n"
else
printf "\033[G\033[K${GREEN}[+] Removed $deleted_count 'wget-log' file(s).${NC}\n"
fi
}
show_cleanup_menu() {
while true; do
clear
echo "========================================="
echo "              Cleanup Menu               "
echo "========================================="
echo "1. Clean Script Logs from /tmp/"
echo "   (Removes pen-forge-install.log, toolkit_uninstall_*.log, etc.)"
echo
echo "2. Clean 'wget-log' files"
echo "   (Removes wget-log* files from the current directory)"
echo
echo "3. Clean ALL (Both 1 and 2)"
echo
echo "0. Back to Main Menu"
echo "-----------------------------------------"
read -p "Enter your choice [0-3]: " choice < /dev/tty
case $choice in
1)
clear
echo "========================================="
echo "             Cleaning /tmp/ Logs         "
echo "========================================="
clean_tmp_directory_action
echo "-----------------------------------------"
read -p "Press [Enter] to return to the cleanup menu." < /dev/tty
;;
2)
clear
echo "========================================="
echo "         Cleaning 'wget-log' Files       "
echo "========================================="
clean_wget_logs_action
echo "-----------------------------------------"
read -p "Press [Enter] to return to the cleanup menu." < /dev/tty
;;
3)
clear
echo "========================================="
echo "             Cleaning ALL Logs           "
echo "========================================="
clean_tmp_directory_action
clean_wget_logs_action
echo "-----------------------------------------"
echo " All cleanup actions complete!"
read -p "Press [Enter] to return to the cleanup menu." < /dev/tty
;;
0)
return
;;
*)
echo "Invalid option. Please try again."
sleep 2
;;
esac
done
}
install_tools() {
clear
local FORCE_UPDATE=false
local REPLY=""
while true; do
read -p "Force re-installation of all tools? [Press Enter for default 'NO'] (y/N): " -n 1 -r REPLY < /dev/tty
echo
case "$REPLY" in
[Yy])
FORCE_UPDATE=true
break
;;
[Nn]|"")
FORCE_UPDATE=false
break
;;
*)
echo -e "${RED}[x] Invalid input. Please enter 'y' or 'n'.${NC}" >&2
;;
esac
done
export FORCE_UPDATE
export IS_MANUAL_INSTALL=false
echo -e "${YELLOW}[*] Refreshing sudo timestamp...${NC}"
if ! sudo -v; then echo -e "${RED}[x] Sudo authentication failed.${NC}"; return 1; fi
echo -e "${GREEN}[+] Sudo timestamp refreshed.${NC}"
keep_sudo_alive &
SUDO_REFRESH_PID=$!
export SUDO_REFRESH_PID
(
set -e
trap 'echo "Error in install_tools subshell on line $LINENO. Exit code: $?" >&2' ERR
trap 'echo -e "\n\n${RED}[!] Installation aborted by user.${NC}"; exit 130' INT TERM
if [[ "$FORCE_UPDATE" == true ]]; then
echo "[*] UPDATE MODE: Forcing re-installation of all tools."
fi
OS_ID=""; if [ -f /etc/os-release ]; then
if grep -qi "kali" /etc/os-release; then OS_ID="kali";
elif grep -qi "parrot" /etc/os-release; then OS_ID="parrot";
elif grep -qi "ubuntu" /etc/os-release; then OS_ID="ubuntu";
else OS_ID=$(grep -oP '^ID=\K\w+' /etc/os-release); fi
fi
case "$OS_ID" in
kali|ubuntu|parrot|debian) echo -e "${GREEN}[+] Detected $OS_ID.${NC}" ;;
*) echo -e "${RED}[x] Unsupported OS: '${OS_ID:-unknown}'. Aborting.${NC}"; exit 1 ;;
esac
export OS_ID
install_tool() {
install_tool_robust "$1" "$2" "$3"
}
echo "[*] Starting the toolkit setup process..."
if ! ensure_critical_packages "jq" "bc" "curl" "wget" "git"; then
echo -e "${RED}[x] Failed to install critical packages.${NC}"
exit 1
fi
if ! check_critical_commands "sudo" "curl" "wget" "git" "grep" "awk" "tput" "jq" "bc"; then
echo -e "${RED}[x] Aborting due to missing critical commands.${NC}"
exit 1
fi
if [[ ! -w "$HOME" ]]; then
echo -e "${RED}[x] CRITICAL: Home directory $HOME is not writable. Aborting.${NC}"
exit 1
fi
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 1: Preparing System & Package Manager...${NC}"
echo "=================================================================="
handle_apt_locks() {
echo "[*] Checking for existing apt locks..."; sudo apt-get install -y -qq psmisc &>/dev/null || true
if sudo fuser /var/lib/dpkg/lock-frontend >/dev/null 2>&1 || sudo fuser /var/lib/apt/lists/lock >/dev/null 2>&1 || sudo lsof /var/lib/dpkg/lock >/dev/null 2>&1; then
echo -e "${YELLOW}[~] Apt lock detected. Attempting to resolve automatically...${NC}"
sudo killall apt apt-get dpkg &>/dev/null || true; sleep 2
sudo rm -f /var/lib/apt/lists/lock /var/lib/dpkg/lock /var/lib/dpkg/lock-frontend &>/dev/null || true
sudo dpkg --configure -a &>/dev/null; echo -e "${GREEN}[+] Apt lock resolution attempted.${NC}"
else
echo -e "${GREEN}[+] Apt lock free.${NC}"
fi
}
handle_apt_locks
echo -e "${YELLOW}[*] Cleaning, updating, and upgrading system packages...${NC}"
local LOG_FILE; LOG_FILE=$(mktemp)
START_SPINNER "Updating system (apt update, upgrade)"
if ! (sudo DEBIAN_FRONTEND=noninteractive apt-get clean && \
sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && \
sudo DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y -qq && \
sudo DEBIAN_FRONTEND=noninteractive apt-get dist-upgrade -y -qq) &> "$LOG_FILE"; then
STOP_SPINNER
printf "${RED}[x] System update FAILED: %s seconds${NC}\n" "$TIME"
echo -e "${YELLOW}--- Last 30 lines of log for System Update ---${NC}"; tail -30 "$LOG_FILE"; echo -e "${YELLOW}---------------------------------${NC}"
rm -f "$LOG_FILE"; exit 1
fi
STOP_SPINNER
printf "${GREEN}[+] System updated successfully: %s seconds${NC}\n" "$TIME"
rm -f "$LOG_FILE"
echo -e "${YELLOW}[*] Installing prerequisite packages...${NC}"
if [ "$OS_ID" == "debian" ]; then
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake libtool autoconf automake libssl-dev libpcre2-dev rsync net-tools dmidecode python3-pip python3-setuptools python3 dos2unix xsel jq yq npm pkg-config parallel cewl perl chromium masscan sqlmap sublist3r ruby ruby-dev psmisc bc libudev1)
elif [ "$OS_ID" == "parrot" ]; then
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake libtool autoconf automake libssl-dev libpcre3-dev rsync net-tools dmidecode python3-pip dos2unix xsel jq yq npm pkg-config parallel cewl perl chromium masscan sqlmap sublist3r ruby ruby-dev psmisc bc libudev1)
elif [ "$OS_ID" == "kali" ]; then
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake libtool autoconf automake libssl-dev libpcre3-dev rsync net-tools dmidecode python3-pip dos2unix xsel jq yq npm pkg-config libudev-dev parallel cewl perl chromium masscan sqlmap sublist3r ruby ruby-dev psmisc bc)
else
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake libtool autoconf automake libssl-dev libpcre3-dev rsync net-tools dmidecode python3-pip dos2unix xsel jq yq npm pkg-config libudev-dev parallel cewl perl chromium masscan sqlmap sublist3r ruby ruby-dev psmisc bc)
fi
local missing_pkgs=()
for pkg in "${PACKAGES[@]}"; do
if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
missing_pkgs+=("$pkg")
fi
done
if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
echo "[*] Installing missing prerequisites: ${missing_pkgs[*]}"
START_SPINNER "Installing ${#missing_pkgs[@]} prerequisites"
local PKG_LOG_FILE; PKG_LOG_FILE=$(mktemp)
if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing_pkgs[@]}" &> "$PKG_LOG_FILE"; then
STOP_SPINNER
printf "${RED}[x] Failed to install prerequisites: %s seconds${NC}\n" "$TIME"
echo -e "${YELLOW}--- Last 30 lines of log for Prerequisite Install ---${NC}"; tail -30 "$PKG_LOG_FILE"; echo -e "${YELLOW}---------------------------------${NC}"
rm -f "$PKG_LOG_FILE"; exit 1
fi
STOP_SPINNER
printf "${GREEN}[+] Prerequisites installed successfully: %s seconds${NC}\n" "$TIME"
rm -f "$PKG_LOG_FILE"
else
echo "[+] All prerequisites already installed."
fi
echo "[*] Verifying critical prerequisite packages..."
CRITICAL_PKGS=("build-essential" "git" "curl" "wget" "pipx" "bc")
for pkg in "${CRITICAL_PKGS[@]}"; do
if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
echo -e "${RED}[x] CRITICAL: Essential package '$pkg' failed to install or verify. Aborting.${NC}"
exit 1
fi
done
echo -e "${GREEN}[+] Critical packages verified successfully.${NC}"
echo "[+] Checking system swap memory..."; TARGET_SWAP_GB=16
required_swap_kb=$((TARGET_SWAP_GB * 1024 * 1024))
current_swap_kb=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
if ! [[ "$current_swap_kb" =~ ^[0-9]+$ ]]; then current_swap_kb=0; fi
current_swap_gb=$(awk "BEGIN {printf \"%.2f\", $current_swap_kb / 1024 / 1024}")
if [[ -z "$current_swap_gb" ]]; then current_swap_gb=0.00; fi
echo -e "${CYAN}[*] Current swap: ${current_swap_gb}GB. Target: ${TARGET_SWAP_GB}GB.${NC}"
if [ "$current_swap_kb" -lt "$((required_swap_kb * 95 / 100))" ]; then
echo -e "${YELLOW}[~] Active swap is insufficient. Creating a new swap file...${NC}"
FS_TYPE=$(findmnt -n -o FSTYPE /)
local SWAP_FILE_PATH="/swapfile"
START_SPINNER "Creating ${TARGET_SWAP_GB}GB swap file on '$FS_TYPE' filesystem"
local SWAP_LOG_FILE; SWAP_LOG_FILE=$(mktemp)
sudo swapoff -a &>> "$SWAP_LOG_FILE" || true
sudo rm -f /swapfile &>> "$SWAP_LOG_FILE" || true
if [ -d /swap ]; then
sudo btrfs subvolume delete /swap &>> "$SWAP_LOG_FILE" || sudo rm -rf /swap &>> "$SWAP_LOG_FILE";
fi
if [ "$FS_TYPE" == "btrfs" ]; then
SWAP_FILE_PATH="/swap/swapfile"
sudo mkdir -p /swap || true
if ! sudo btrfs subvolume list / | grep -q ' /swap$'; then
sudo btrfs subvolume create /swap &>> "$SWAP_LOG_FILE" || echo "Subvol create failed, dir might exist?" >> "$SWAP_LOG_FILE"
fi
sudo chattr +C /swap &>> "$SWAP_LOG_FILE" || true
sudo touch "$SWAP_FILE_PATH" || true
if ! sudo dd if=/dev/zero of="$SWAP_FILE_PATH" bs=1G count=${TARGET_SWAP_GB} status=none oflag=sync &>> "$SWAP_LOG_FILE"; then
STOP_SPINNER; printf "${RED}[x] %-25s - FAILED (dd): %s seconds${NC}\n" "Swap file creation" "$TIME"
echo -e "${YELLOW}--- Log: Swap Creation ---${NC}"; cat "$SWAP_LOG_FILE"; echo -e "${YELLOW}--- End Log ---${NC}"
rm -f "$SWAP_LOG_FILE"; exit 1
fi
else
if ! sudo fallocate -l ${TARGET_SWAP_GB}G "$SWAP_FILE_PATH" &>> "$SWAP_LOG_FILE"; then
echo -e "${YELLOW}[~] fallocate failed. Falling back to 'dd' (this may be slow)...${NC}" &>> "$SWAP_LOG_FILE"
sudo rm -f "$SWAP_FILE_PATH" || true
if ! sudo dd if=/dev/zero of="$SWAP_FILE_PATH" bs=1G count=${TARGET_SWAP_GB} status=none oflag=sync &>> "$SWAP_LOG_FILE"; then
STOP_SPINNER; printf "${RED}[x] %-25s - FAILED (fallocate & dd): %s seconds${NC}\n" "Swap file creation" "$TIME"
echo -e "${YELLOW}--- Log: Swap Creation ---${NC}"; cat "$SWAP_LOG_FILE"; echo -e "${YELLOW}--- End Log ---${NC}"
rm -f "$SWAP_LOG_FILE"; exit 1
fi
fi
fi
sudo chmod 600 "$SWAP_FILE_PATH" &>> "$SWAP_LOG_FILE"
if ! sudo mkswap "$SWAP_FILE_PATH" &>> "$SWAP_LOG_FILE"; then
STOP_SPINNER; printf "${RED}[x] %-25s - FAILED (mkswap): %s seconds${NC}\n" "Swap file creation" "$TIME"
echo -e "${YELLOW}--- Log: Swap Creation ---${NC}"; cat "$SWAP_LOG_FILE"; echo -e "${YELLOW}--- End Log ---${NC}"
rm -f "$SWAP_LOG_FILE"; exit 1
fi
if ! sudo swapon "$SWAP_FILE_PATH" &>> "$SWAP_LOG_FILE"; then
STOP_SPINNER; printf "${RED}[x] %-25s - FAILED (swapon): %s seconds${NC}\n" "Swap file creation" "$TIME"
echo -e "${YELLOW}--- Log: Swap Creation ---${NC}"; cat "$SWAP_LOG_FILE"; echo -e "${YELLOW}--- End Log ---${NC}"
rm -f "$SWAP_LOG_FILE"; exit 1
fi
STOP_SPINNER; rm -f "$SWAP_LOG_FILE"
echo "[*] Verifying swap activation..."; swap_verified=false
for i in {1..5}; do
new_swap_kb=$(grep SwapTotal /proc/meminfo | awk '{print $2}')
if [[ "$new_swap_kb" -ge "$((required_swap_kb * 90 / 100))" ]]; then
swap_verified=true; break
fi; sleep 1
done
if [ "$swap_verified" = false ]; then printf "${RED}[x] Swap verification failed.${NC}\n"; exit 1; fi
sudo sed -i.bak '/swap/d' /etc/fstab
echo "\"$SWAP_FILE_PATH\" none swap sw 0 0" | sudo tee -a /etc/fstab >/dev/null
printf "${GREEN}[+] Swap file created and activated successfully.${NC}\n"
fi
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 2: Installing Go & Configuring Environment...${NC}"
echo "=================================================================="
if [[ "$FORCE_UPDATE" == false ]] && [[ -x "/usr/local/go/bin/go" ]]; then
echo -e "${YELLOW}[~] Go already in /usr/local/go. SKIPPED${NC}"
else
LATEST_GO_VERSION=$(curl -s https://go.dev/dl/?mode=json | jq -r '[.[] | select(.stable==true)][0].version' | sed 's/^go//')
if [[ -z "$LATEST_GO_VERSION" ]]; then
echo "${RED}Error: Could not determine latest Go version.${NC}"; exit 1;
fi
echo "[*] Downloading Go version: $LATEST_GO_VERSION"
START_SPINNER "Installing Go"
if ! curl -Ls "https://go.dev/dl/go${LATEST_GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz; then
STOP_SPINNER; echo "${RED}Error: Failed to download Go tarball.${NC}"; exit 1;
fi
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
STOP_SPINNER; printf "${GREEN}[+] Go installed successfully: %s seconds${NC}\n" "$TIME"
fi
echo "[+] Configuring shell environment..."
export GOROOT="/usr/local/go"; export GOPATH="$HOME/Tools/Go-Tools"
local current_path="${PATH:-}"
[[ ":$current_path:" != *":$GOPATH/bin:"* ]] && current_path="$GOPATH/bin:$current_path"
[[ ":$current_path:" != *":$GOROOT/bin:"* ]] && current_path="$GOROOT/bin:$current_path"
[[ ":$current_path:" != *":$HOME/.cargo/bin:"* ]] && current_path="$HOME/.cargo/bin:$current_path"
[[ ":$current_path:" != *":$HOME/.local/bin:"* ]] && current_path="$HOME/.local/bin:$current_path"
export PATH="$current_path"
if ! command -v go &>/dev/null; then echo -e "${RED}[x] CRITICAL: Go binary not found in PATH after installation. Aborting.${NC}"; exit 1; fi
echo "[*] Go version $(go version) is now active."
SHELL_CONFIG_FILE=""; case "$SHELL" in */zsh) SHELL_CONFIG_FILE="$HOME/.zshrc" ;; */bash) SHELL_CONFIG_FILE="$HOME/.bashrc" ;; *) SHELL_CONFIG_FILE="$HOME/.profile" ;; esac
if [[ -f "$SHELL_CONFIG_FILE" || "$SHELL_CONFIG_FILE" == "$HOME/.profile" ]]; then
if ! grep -q '# CYBERSEC TOOLKIT PATHS' "$SHELL_CONFIG_FILE" 2>/dev/null; then
echo "[*] Writing Go environment configuration to $SHELL_CONFIG_FILE..."
printf "\n# CYBERSEC TOOLKIT PATHS\nexport GOROOT=/usr/local/go\nexport GOPATH=\$HOME/Tools/Go-Tools\nexport PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.cargo/bin:\$HOME/.local/bin:\$PATH\n\n" >> "$SHELL_CONFIG_FILE"
fi
else
echo -e "${YELLOW}[~] Shell config file $SHELL_CONFIG_FILE not found. Writing to $HOME/.profile instead.${NC}"
SHELL_CONFIG_FILE="$HOME/.profile"
touch "$SHELL_CONFIG_FILE"
if ! grep -q '# CYBERSEC TOOLKIT PATHS' "$SHELL_CONFIG_FILE" 2>/dev/null; then
echo "[*] Writing Go environment configuration to $SHELL_CONFIG_FILE..."
printf "\n# CYBERSEC TOOLKIT PATHS\nexport GOROOT=/usr/local/go\nexport GOPATH=\$HOME/Tools/Go-Tools\nexport PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.cargo/bin:\$HOME/.local/bin:\$PATH\n\n" >> "$SHELL_CONFIG_FILE"
fi
fi
echo "[+] Ensuring pipx path is configured..."; pipx ensurepath > /dev/null 2>&1 || true
echo "[+] Creating directory structure..."; mkdir -p "$GOPATH/bin" "$HOME/build-temp/go-build"
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 3: Installing Go-based tools...${NC}"
echo "=================================================================="
echo "[+] Optimizing Go build environment..."
export GOPROXY="https://proxy.golang.org,https://goproxy.io,direct"
export GOMEMLIMIT="2GiB"
export GOSUMDB="sum.golang.org"
export GOFLAGS="-buildvcs=false"
export GOGC=50
START_SPINNER "Cleaning Go module cache (initial)"
go clean -cache -modcache &>/dev/null || true
STOP_SPINNER
printf "${GREEN}[+] Go module cache cleaned: %s seconds${NC}\n" "$TIME"
TOOL_COUNTER=0
install_tool "Amass" "amass" "go install github.com/owasp-amass/amass/v3/...@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Alterx" "alterx" "go install github.com/projectdiscovery/alterx/cmd/alterx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Anew" "anew" "go install github.com/tomnomnom/anew@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Assetfinder" "assetfinder" "go install github.com/tomnomnom/assetfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Asnmap" "asnmap" "go install github.com/projectdiscovery/asnmap/cmd/asnmap@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Cariddi" "cariddi" "go install github.com/edoardottt/cariddi/cmd/cariddi@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Cdncheck" "cdncheck" "go install github.com/projectdiscovery/cdncheck/cmd/cdncheck@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Cero" "cero" "go install github.com/glebarez/cero@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Certinfo" "certinfo" "go install github.com/rix4uni/certinfo@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Chaos" "chaos" "go install github.com/projectdiscovery/chaos-client/cmd/chaos@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Crawley" "crawley" "go install github.com/s0rg/crawley/cmd/crawley@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Crobat" "crobat" "go install github.com/cgboal/sonarsearch/cmd/crobat@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Crlfuzz" "crlfuzz" "go install github.com/dwisiswant0/crlfuzz/cmd/crlfuzz@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Crt" "crt" "go install github.com/cemulus/crt@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Cspfinder" "cspfinder" "go install github.com/rix4uni/cspfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Csprecon" "csprecon" "go install github.com/edoardottt/csprecon/cmd/csprecon@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Cvemap" "cvemap" "go install github.com/projectdiscovery/cvemap/cmd/cvemap@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Dalfox" "dalfox" "go install github.com/hahwul/dalfox/v2@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Dlevel" "dlevel" "go install github.com/rix4uni/dlevel@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Dmut" "dmut" "go install github.com/bp0lr/dmut@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
if (( TOOL_COUNTER % 20 == 0 )); then go clean -cache -modcache &>/dev/null || true; fi
install_tool "Dnsx" "dnsx" "go install github.com/projectdiscovery/dnsx/cmd/dnsx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Emailfinder" "emailfinder" "go install github.com/rix4uni/emailfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Favirecon" "favirecon" "go install github.com/edoardottt/favirecon/cmd/favirecon@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Favinfo" "favinfo" "go install github.com/rix4uni/favinfo@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Fff" "fff" "go install github.com/tomnomnom/fff@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Ffuf" "ffuf" "go install github.com/ffuf/ffuf/v2@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Ftpx" "ftpx" "go install github.com/rix4uni/ftpx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Fuzzuli" "fuzzuli" "go install github.com/musana/fuzzuli@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Galer" "galer" "go install github.com/dwisiswant0/galer@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gau" "gau" "go install github.com/lc/gau/v2/cmd/gau@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "GetJS" "getJS" "go install github.com/003random/getJS/v2@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gf" "gf" "go install github.com/tomnomnom/gf@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Github-endpoints" "github-endpoints" "go install github.com/gwen001/github-endpoints@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Github-subdomains" "github-subdomains" "go install github.com/gwen001/github-subdomains@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gitrepoenum" "gitrepoenum" "go install github.com/rix4uni/gitrepoenum@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gitleaks" "gitleaks" "go install github.com/zricethezav/gitleaks/v8@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gobuster" "gobuster" "go install github.com/OJ/gobuster/v3@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Goaltdns" "goaltdns" "go install github.com/subfinder/goaltdns@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Golinkfinder" "golinkfinder" "go install github.com/rix4uni/GoLinkFinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Goop" "goop" "go install github.com/deletescape/goop@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
if (( TOOL_COUNTER % 20 == 0 )); then go clean -cache -modcache &>/dev/null || true; fi
install_tool "Gospider" "gospider" "go install github.com/jaeles-project/gospider@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gosqli" "gosqli" "go install github.com/rix4uni/gosqli@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gotator" "gotator" "go install github.com/Josue87/gotator@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gourlex" "gourlex" "go install github.com/trap-bytes/gourlex@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gowitness" "gowitness" "go install github.com/sensepost/gowitness@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gron" "gron" "go install github.com/tomnomnom/gron@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gungnir" "gungnir" "go install github.com/g0ldencybersec/gungnir/cmd/gungnir@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Gxss" "gxss" "go install github.com/KathanP19/Gxss@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Go-dork" "go-dork" "go install github.com/dwisiswant0/go-dork@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Hakcheckurl" "hakcheckurl" "go install github.com/hakluke/hakcheckurl@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Hakip2host" "hakip2host" "go install github.com/hakluke/hakip2host@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Haklistgen" "haklistgen" "go install github.com/hakluke/haklistgen@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Hakoriginfinder" "hakoriginfinder" "go install github.com/hakluke/hakoriginfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Hakrawler" "hakrawler" "go install github.com/hakluke/hakrawler@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Hakrevdns" "hakrevdns" "go install github.com/hakluke/hakrevdns@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Haktrails" "haktrails" "go install github.com/hakluke/haktrails@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Haktrailsfree" "haktrailsfree" "go install github.com/rix4uni/haktrailsfree@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Httpx" "httpx-toolkit" "go install github.com/projectdiscovery/httpx/cmd/httpx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Httprobe" "httprobe" "go install github.com/tomnomnom/httprobe@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Interactsh-client" "interactsh-client" "go install github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Ip2org" "ip2org" "go install github.com/rix4uni/ip2org@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
if (( TOOL_COUNTER % 20 == 0 )); then go clean -cache -modcache &>/dev/null || true; fi
install_tool "Ipfinder" "ipfinder" "go install github.com/rix4uni/ipfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Jaeles" "jaeles" "go install github.com/jaeles-project/jaeles@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Jsfinder" "jsfinder" "go install github.com/kacakb/jsfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Jshunter" "jshunter" "go install github.com/cc1a2b/jshunter@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Jsluice" "jsluice" "go install github.com/BishopFox/jsluice/cmd/jsluice@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Jsubfinder" "jsubfinder" "go install github.com/ThreatUnkown/jsubfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Katana" "katana" "go install github.com/projectdiscovery/katana/cmd/katana@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Kxss" "kxss" "go install github.com/Emoe/kxss@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Linx" "linx" "go install github.com/riza/linx/cmd/linx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Linkinspector" "linkinspector" "go install github.com/rix4uni/linkinspector@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Mantra" "mantra" "go install github.com/Brosck/mantra@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Mapcidr" "mapcidr" "go install github.com/projectdiscovery/mapcidr/cmd/mapcidr@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Meg" "meg" "go install github.com/tomnomnom/meg@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Msarjun" "msarjun" "go install github.com/rix4uni/msarjun@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Mx-takeover" "mx-takeover" "go install github.com/musana/mx-takeover@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Naabu" "naabu" "go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Notify" "notify" "go install github.com/projectdiscovery/notify/cmd/notify@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Nuclei" "nuclei" "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Oosexclude" "oosexclude" "go install github.com/rix4uni/oosexclude@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Org2asn" "org2asn" "go install github.com/rix4uni/org2asn@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
if (( TOOL_COUNTER % 20 == 0 )); then go clean -cache -modcache &>/dev/null || true; fi
install_tool "Paramfinder" "paramfinder" "go install github.com/rix4uni/paramfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Pathcrawler" "pathcrawler" "go install github.com/rix4uni/pathcrawler@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Portmap" "portmap" "go install github.com/rix4uni/portmap@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Puredns" "puredns" "go install github.com/d3mondev/puredns/v2@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Pvreplace" "pvreplace" "go install github.com/rix4uni/pvreplace@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Proxify" "proxify" "go install github.com/projectdiscovery/proxify/cmd/proxify@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Qsreplace" "qsreplace" "go install github.com/tomnomnom/qsreplace@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Robotxt" "robotxt" "go install github.com/rix4uni/robotxt@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "S3scanner" "s3scanner" "go install github.com/sa7mon/s3scanner@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Shortscan" "shortscan" "go install github.com/bitquark/shortscan/cmd/shortscan@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Shosubgo" "shosubgo" "go install github.com/incogbyte/shosubgo@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Shuffledns" "shuffledns" "go install github.com/projectdiscovery/shuffledns/cmd/shuffledns@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Smap" "smap" "go install github.com/s0md3v/smap/cmd/smap@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Sourcemapper" "sourcemapper" "go install github.com/denandz/sourcemapper@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Spk" "spk" "go install github.com/dhn/spk@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Subdog" "subdog" "go install github.com/rix4uni/subdog@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Subdomainfuzz" "subdomainfuzz" "go install github.com/rix4uni/subdomainfuzz@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Subfinder" "subfinder" "go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Subjs" "subjs" "go install github.com/lc/subjs@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Subzy" "subzy" "go install github.com/PentestPad/subzy@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Subjack" "subjack" "go install github.com/haccer/subjack@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
if (( TOOL_COUNTER % 20 == 0 )); then go clean -cache -modcache &>/dev/null || true; fi
install_tool "Techx" "techx" "go install github.com/rix4uni/techx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Timelimitx" "timelimitx" "go install github.com/rix4uni/timelimitx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Tldfinder" "tldfinder" "go install github.com/projectdiscovery/tldfinder/cmd/tldfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Tlsx" "tlsx" "go install github.com/projectdiscovery/tlsx/cmd/tlsx@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Udon" "udon" "go install github.com/dhn/udon@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Uforall" "uforall" "go install github.com/rix4uni/UForAll@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Uncover" "uncover" "go install github.com/projectdiscovery/uncover/cmd/uncover@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Unfurl" "unfurl" "go install github.com/tomnomnom/unfurl@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Urlfinder" "urlfinder" "go install github.com/projectdiscovery/urlfinder/cmd/urlfinder@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Waybackurls" "waybackurls" "go install github.com/tomnomnom/waybackurls@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Whoxysubs" "whoxysubs" "go install github.com/rix4uni/whoxysubs@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Wordgen" "wordgen" "go install github.com/rix4uni/wordgen@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "WCVS" "wcvs" "go install github.com/Hackmanit/Web-Cache-Vulnerability-Scanner@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Xcrawle3r" "xcrawl3r" "go install github.com/hueristiq/xcrawl3r/cmd/xcrawl3r@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Xsschecker" "xsschecker" "go install github.com/rix4uni/xsschecker@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Xsubfind3r" "xsubfind3r" "go install github.com/hueristiq/xsubfind3r/cmd/xsubfind3r@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
install_tool "Xurlfind3r" "xurlfind3r" "go install github.com/hueristiq/xurlfind3r/cmd/xurlfind3r@latest" && TOOL_COUNTER=$((TOOL_COUNTER+1))
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 4: Installing Python tools (pipx/pip3)...${NC}"
echo "=================================================================="
install_tool "Arjun" "arjun" "pipx install arjun"
install_tool "Bbot" "bbot" "pipx install bbot"
install_tool "Corscanner" "corscanner" "pipx install corscanner"
install_tool "Dirsearch" "dirsearch" "pipx install dirsearch"
install_tool "Dotgit" "dotgit" "pipx install dotgit"
install_tool "Shodan" "shodan" "pipx install shodan"
install_tool "Uro" "uro" "pipx install uro"
install_tool "Waymore" "waymore" "pipx install waymore"
install_tool "XnLinkFinder" "xnlinkfinder" "pipx install xnLinkFinder"
install_tool "Altdns" "altdns" "pipx install --force git+https://github.com/infosec-au/altdns.git"
install_tool "Interlace" "interlace" "pipx install --force git+https://github.com/codingo/Interlace.git"
install_tool "Recollapse" "recollapse" "pipx install --force git+https://github.com/0xacb/recollapse.git"
install_tool "Dnsgen" "dnsgen" "pip3 install dnsgen --break-system-packages"
install_tool "Pler" "pler" "pip3 install python-pler --break-system-packages"
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 5: Installing Rust and Rust-based tools...${NC}"
echo "=================================================================="
if ! command -v rustc &>/dev/null || [[ "$FORCE_UPDATE" == true ]]; then
install_tool "Rust" "rustc" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
else
echo -e "${YELLOW}[~] Rust already installed. SKIPPED${NC}"
fi
if [ -f "$HOME/.cargo/env" ]; then
source "$HOME/.cargo/env"
export PATH="$HOME/.cargo/bin:$PATH"
fi
install_tool "Feroxbuster" "feroxbuster" 'set -e; wget https://github.com/epi052/feroxbuster/releases/latest/download/feroxbuster_amd64.deb.zip -O /tmp/ferox.zip; unzip -o /tmp/ferox.zip -d /tmp; sudo dpkg -i /tmp/feroxbuster*.deb; rm /tmp/ferox.zip /tmp/feroxbuster*.deb'
install_tool "Ppfuzz" "ppfuzz" 'set -e; wget https://github.com/dwisiswant0/ppfuzz/releases/download/v1.0.2/ppfuzz-v1.0.2-x86_64-unknown-linux-musl.tar.gz -O /tmp/ppfuzz.tar.gz; tar -xzf /tmp/ppfuzz.tar.gz -C /tmp; sudo mv /tmp/ppfuzz /usr/local/bin/; rm /tmp/ppfuzz.tar.gz'
install_tool "x8" "x8" 'set -e; wget https://github.com/Sh1Yo/x8/releases/download/v4.3.0/x86_64-linux-x8.gz -O /tmp/x8.gz; gunzip /tmp/x8.gz; chmod +x /tmp/x8; sudo mv /tmp/x8 /usr/local/bin/'
install_tool "Ripgen" "ripgen" 'export PATH="$HOME/.cargo/bin:$PATH" && cargo install ripgen'
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 6: Building tools from source...${NC}"
echo "=================================================================="
install_tool "MassDNS" "massdns" "( rm -rf \"$HOME/build-temp/massdns\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/blechschmidt/massdns.git \"$HOME/build-temp/massdns\" && cd \"$HOME/build-temp/massdns\" && make && sudo cp bin/massdns /usr/local/bin/ )" || :
install_tool "AnalyticsRelationships" "analyticsrelationships" "( export GOPATH=\"$HOME/Tools/Go-Tools\" && rm -rf \"$HOME/build-temp/AnalyticsRelationships\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Josue87/AnalyticsRelationships.git \"$HOME/build-temp/AnalyticsRelationships\" && cd \"$HOME/build-temp/AnalyticsRelationships\" && go mod tidy && go build -ldflags=\"-s\" -o \"$GOPATH/bin/analyticsrelationships\" )" || :
install_tool "Pathfinder" "pathfinder" "( rm -rf \"$HOME/build-temp/pathfinder\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Print3M/pathfinder.git \"$HOME/build-temp/pathfinder\" && cd \"$HOME/build-temp/pathfinder\" && go build && sudo mv pathfinder /usr/local/bin/ )" || :
install_tool "Roboxtractor" "roboxtractor" "( rm -rf \"$HOME/build-temp/roboxtractor\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Josue87/roboxtractor.git \"$HOME/build-temp/roboxtractor\" && cd \"$HOME/build-temp/roboxtractor\" && go build && sudo mv roboxtractor /usr/local/bin/ )" || :
install_tool "Urlgrab" "urlgrab" "( rm -rf \"$HOME/build-temp/urlgrab\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/iamstoxe/urlgrab.git \"$HOME/build-temp/urlgrab\" && cd \"$HOME/build-temp/urlgrab\" && export GOPATH=\"$HOME/Tools/Go-Tools\" && go build -o \"$GOPATH/bin/urlgrab\" && chmod +x \"$GOPATH/bin/urlgrab\" )" || :
install_tool "Xssrecon" "xssrecon" "( rm -rf \"$HOME/build-temp/xssrecon\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/rix4uni/xssrecon.git \"$HOME/build-temp/xssrecon\" && cd \"$HOME/build-temp/xssrecon\" && go install )" || :
install_tool "UrlDedupe" "urldedupe" "( rm -rf \"$HOME/build-temp/urldedupe\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/ameenmaali/urldedupe.git \"$HOME/build-temp/urldedupe\" && cd \"$HOME/build-temp/urldedupe\" && cmake CMakeLists.txt && make && sudo cp urldedupe /usr/local/bin/ )" || :
install_tool "LinkFinder" "linkfinder" "( command -v pip3 >/dev/null && rm -rf \"$HOME/build-temp/LinkFinder\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/GerbenJavado/LinkFinder.git \"$HOME/build-temp/LinkFinder\" && cd \"$HOME/build-temp/LinkFinder\" && pip3 install -r requirements.txt --break-system-packages && chmod +x linkfinder.py && sudo rm -f /usr/local/bin/linkfinder && sudo cp linkfinder.py /usr/local/bin/linkfinder )" || :
install_tool "Ghauri" "ghauri" "( command -v pip3 >/dev/null && rm -rf \"$HOME/build-temp/ghauri\" && timeout $GIT_CLONE_TIMEOUT git clone --depth 1 https://github.com/r0oth3x49/ghauri.git \"$HOME/build-temp/ghauri\" && cd \"$HOME/build-temp/ghauri\" && pip3 install -r requirements.txt --break-system-packages && pip3 install . --break-system-packages )" || :
install_tool "Trufflehog" "trufflehog" 'curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh | sh -s -- -b "$HOME/Tools/Go-Tools/bin"' || :
install_tool "Aquatone" "aquatone" 'set -e; wget "https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip" -O /tmp/aquatone.zip; unzip -o /tmp/aquatone.zip -d /tmp; sudo mv /tmp/aquatone /usr/local/bin/; rm /tmp/aquatone.zip' || :
install_tool "Ssb" "ssb" "curl -sSfL 'https://git.io/kitabisa-ssb' | sudo sh -s -- -b /usr/local/bin"
install_tool "Rcert" "rcert" "( rm -rf \"$HOME/build-temp/rcert\" && timeout $GIT_CLONE_TIMEOUT git clone https://github.com/rix4uni/rcert.git \"$HOME/build-temp/rcert\" && sudo mv \"$HOME/build-temp/rcert/rcert\" /usr/local/bin/ && sudo chmod +x /usr/local/bin/rcert )" || :
install_tool "WPScan" "wpscan" "if [ \"${OS_ID:-}\" == \"kali\" ]; then sudo apt-get install -y wpscan; elif command -v gem &>/dev/null; then sudo gem install wpscan; else echo \"Cannot install WPScan: gem not found\"; fi" || :
START_SPINNER "Cleaning up build directory"
rm -rf "$HOME/build-temp" || true
STOP_SPINNER
printf "${GREEN}[+] Build directory cleaned: %s seconds${NC}\n" "$TIME"
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 7: Setting up GF Patterns...${NC}"
echo "=================================================================="
START_SPINNER "Setting up GF Patterns"
GF_LOG=$(mktemp)
{
mkdir -p ~/.gf && rm -rf ~/.gf/*
timeout $GIT_CLONE_TIMEOUT git clone https://github.com/Nixon-H/gf-patterns.git /tmp/gf-patterns-temp || echo "GF Patterns clone failed/timed out" >> "$GF_LOG"
if [[ -d /tmp/gf-patterns-temp ]]; then
cp /tmp/gf-patterns-temp/*.json ~/.gf/
rm -rf /tmp/gf-patterns-temp
fi
} &>> "$GF_LOG"
STOP_SPINNER
if ! ls ~/.gf/*.json &>/dev/null; then
printf "${YELLOW}[!] Warning: GF patterns may not have installed correctly. Check logs if needed.${NC}\n"
else
printf "${GREEN}[+] GF Patterns installed successfully: %s seconds${NC}\n" "$TIME"
fi
rm -f "$GF_LOG"
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 8: Downloading essential wordlists...${NC}"
echo "=================================================================="
START_SPINNER "Downloading wordlists"
mkdir -p "$HOME/Tools/Wordlists"; WORDLIST_DIR="$HOME/Tools/Wordlists"
URLS=(
"https://wordlists-cdn.assetnote.io/data/manual/best-dns-wordlist.txt"
"https://raw.githubusercontent.com/trickest/resolvers/main/resolvers-trusted.txt"
"https://raw.githubusercontent.com/six2dez/OneListForAll/main/onelistforallshort.txt"
)
WARNINGS=""
for url in "${URLS[@]}"; do
filename=$(basename "$url")
if ! curl -Ls --retry 3 --retry-delay 5 --connect-timeout 20 --max-time 60 "$url" -o "$WORDLIST_DIR/$filename"; then
WARNINGS="${WARNINGS}\n[!] Warning: Failed to download $filename"
rm -f "$WORDLIST_DIR/$filename"
fi
done
STOP_SPINNER
printf "${GREEN}[+] Wordlist download attempt finished: %s seconds${NC}\n" "$TIME"
if [[ -n "$WARNINGS" ]]; then
echo -e "${YELLOW}${WARNINGS}${NC}"
fi
echo ""; echo "=================================================================="
echo -e "${GREEN}[+] SECTION 9: Performing final system cleanup...${NC}"
echo "=================================================================="
START_SPINNER "Performing final system cleanup (apt autoremove, clean)"
sudo apt-get -qq autoremove -y &>/dev/null || true
sudo apt-get -qq clean &>/dev/null || true
if command -v journalctl &>/dev/null; then
sudo journalctl --vacuum-size=50M &>/dev/null || true
fi
STOP_SPINNER
printf "${GREEN}[+] System cleanup complete: %s seconds${NC}\n" "$TIME"
echo ""
echo -e "${GREEN}[*][*][*] All installations are complete! [*][*][*]${NC}"
echo -e "${YELLOW}[*] IMPORTANT: Please run 'source $SHELL_CONFIG_FILE' or restart your terminal to apply environment changes.${NC}"
if [[ -n "${SUDO_REFRESH_PID:-}" ]] && kill -0 "$SUDO_REFRESH_PID" 2>/dev/null; then
kill "$SUDO_REFRESH_PID" 2>/dev/null || true
fi
)
local subshell_exit_code=$?
if [[ -n "${SUDO_REFRESH_PID:-}" ]] && kill -0 "$SUDO_REFRESH_PID" 2>/dev/null; then
kill "$SUDO_REFRESH_PID" 2>/dev/null || true
fi
if [[ $subshell_exit_code -ne 0 && $subshell_exit_code -ne 130 ]]; then
echo -e "${RED}[!] Installation subshell exited unexpectedly with error code: $subshell_exit_code.${NC}"
elif [[ $subshell_exit_code -eq 130 ]]; then
:
fi
echo
echo "======================================================================"
read -p "Installation process finished. Press [Enter] to return to the menu." < /dev/tty
}
ensure_prerequisites() {
if [[ "$PREREQUISITES_MET" == true ]]; then
return
fi
clear
echo "======================================================================"
echo "        First-time manual setup: Preparing your environment...          "
echo "======================================================================"
set -e
trap 'echo "Error during prerequisite setup on line $LINENO. Exit code: $?" >&2; exit 1' ERR
trap 'echo -e "\n\n${RED}[!] Prerequisite setup aborted by user.${NC}"; { [[ -n "${SUDO_REFRESH_PID:-}" ]] && kill "$SUDO_REFRESH_PID" 2>/dev/null || true; }; exit 130' INT TERM
echo -e "${YELLOW}[*] Refreshing sudo timestamp...${NC}"
if ! sudo -v; then echo -e "${RED}[x] Sudo authentication failed.${NC}"; exit 1; fi
echo -e "${GREEN}[+] Sudo timestamp refreshed.${NC}"
keep_sudo_alive &
SUDO_REFRESH_PID=$!
export SUDO_REFRESH_PID
echo ""; echo -e "${CYAN}--- Preparing System Package Manager ---${NC}"
OS_ID=""; if [ -f /etc/os-release ]; then
if grep -qi "kali" /etc/os-release; then OS_ID="kali";
elif grep -qi "parrot" /etc/os-release; then OS_ID="parrot";
elif grep -qi "ubuntu" /etc/os-release; then OS_ID="ubuntu";
else OS_ID=$(grep -oP '^ID=\K\w+' /etc/os-release); fi
fi
case "$OS_ID" in
kali|ubuntu|parrot|debian) echo -e "${GREEN}[+] Detected $OS_ID.${NC}" ;;
*) echo -e "${RED}[x] Unsupported OS: '${OS_ID:-unknown}'. Cannot set up prerequisites.${NC}"; exit 1 ;;
esac
export OS_ID
if ! ensure_critical_packages "jq" "bc" "curl" "wget" "git"; then
echo -e "${RED}[x] Failed to install critical packages.${NC}"
exit 1
fi
if ! check_critical_commands "sudo" "curl" "wget" "git" "grep" "awk" "tput" "jq" "bc"; then
echo -e "${RED}[x] Aborting due to missing critical commands.${NC}"
exit 1
fi
if [[ ! -w "$HOME" ]]; then
echo -e "${RED}[x] CRITICAL: Home directory $HOME is not writable. Aborting.${NC}"
exit 1
fi
START_SPINNER "Updating system package lists (apt update)"
local UPDATE_LOG; UPDATE_LOG=$(mktemp)

#if ! (sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y -qq) &> "$UPDATE_LOG"; then
if ! (sudo DEBIAN_FRONTEND=noninteractive apt-get update -qq && sudo DEBIAN_FRONTEND=noninteractive apt-get --fix-broken install -y -qq) &> "$UPDATE_LOG" < /dev/null; then

STOP_SPINNER
echo -e "${RED}[x] Failed to update package lists.${NC}"
echo -e "${YELLOW}--- Last 30 lines of log for apt update ---${NC}"; tail -30 "$UPDATE_LOG"; echo -e "${YELLOW}---------------------------------${NC}"
rm -f "$UPDATE_LOG"; exit 1
fi
STOP_SPINNER; printf "${GREEN}[+] System package lists updated: %s seconds${NC}\n" "$TIME"
rm -f "$UPDATE_LOG"
echo -e "${YELLOW}[*] Installing critical prerequisite packages...${NC}"
if [ "$OS_ID" == "debian" ]; then
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake python3-pip python3-setuptools python3 dos2unix jq npm pkg-config libudev1 psmisc bc)
elif [ "$OS_ID" == "parrot" ]; then
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake python3-pip dos2unix jq npm pkg-config libudev1 psmisc bc)
else
PACKAGES=(build-essential libpcap-dev pipx unzip wget git curl cmake python3-pip dos2unix jq npm pkg-config libudev-dev psmisc bc)
fi
local missing_pkgs=()
for pkg in "${PACKAGES[@]}"; do
if ! dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
missing_pkgs+=("$pkg")
fi
done
if [[ ${#missing_pkgs[@]} -gt 0 ]]; then
echo "[*] Installing missing prerequisites: ${missing_pkgs[*]}"
START_SPINNER "Installing ${#missing_pkgs[@]} prerequisites"
local PKG_LOG_FILE; PKG_LOG_FILE=$(mktemp)
if ! sudo DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing_pkgs[@]}" &> "$PKG_LOG_FILE"; then
STOP_SPINNER
echo -e "${RED}[x] Failed to install critical prerequisite(s).${NC}"
echo -e "${YELLOW}--- Last 30 lines of log for Prerequisite Install ---${NC}"; tail -30 "$PKG_LOG_FILE"; echo -e "${YELLOW}---------------------------------${NC}"
rm -f "$PKG_LOG_FILE"; exit 1
fi
STOP_SPINNER; printf "${GREEN}[+] Installed prerequisite(s): %-15s (%ss)${NC}\n" "${missing_pkgs[*]}" "$TIME"
rm -f "$PKG_LOG_FILE"
else
echo "[+] Critical prerequisites already installed."
fi
echo ""; echo -e "${CYAN}--- Installing Core Dependencies (Go, Rust) ---${NC}"
echo "[+] Pre-defining environment and creating directories..."
export GOROOT="/usr/local/go"
export GOPATH="$HOME/Tools/Go-Tools"
mkdir -p "$GOPATH/bin" "$HOME/build-temp/go-build"
if [[ ! -x "/usr/local/go/bin/go" ]]; then
#echo ""; echo -e "${CYAN}--- Installing Core Dependencies (Go, Rust) ---${NC}"
#if [[ ! -x "/usr/local/go/bin/go" ]]; then
LATEST_GO_VERSION=$(curl -s https://go.dev/dl/?mode=json | jq -r '[.[] | select(.stable==true)][0].version' | sed 's/^go//')
if [[ -z "$LATEST_GO_VERSION" ]]; then
echo "${RED}Error: Could not determine latest Go version.${NC}"; exit 1;
fi
echo "[*] Downloading Go version: $LATEST_GO_VERSION"
START_SPINNER "Installing Go"
if ! curl -Ls "https://go.dev/dl/go${LATEST_GO_VERSION}.linux-amd64.tar.gz" -o /tmp/go.tar.gz; then
STOP_SPINNER; echo "${RED}Error: Failed to download Go tarball.${NC}"; exit 1;
fi
sudo rm -rf /usr/local/go && sudo tar -C /usr/local -xzf /tmp/go.tar.gz && rm /tmp/go.tar.gz
STOP_SPINNER; printf "${GREEN}[+] Go installed successfully: %s seconds${NC}\n" "$TIME"
fi
if ! command -v rustc &>/dev/null; then
export IS_MANUAL_INSTALL=true
install_tool_robust "Rust" "rustc" "curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y"
unset IS_MANUAL_INSTALL
fi
if [ -f "$HOME/.cargo/env" ]; then source "$HOME/.cargo/env"; fi
echo "[+] Configuring shell environment for this session..."
#export GOROOT="/usr/local/go"
#export GOPATH="$HOME/Tools/Go-Tools"
local current_path="${PATH:-}"
[[ ":$current_path:" != *":$GOPATH/bin:"* ]] && current_path="$GOPATH/bin:$current_path"
[[ ":$current_path:" != *":$GOROOT/bin:"* ]] && current_path="$GOROOT/bin:$current_path"
[[ ":$current_path:" != *":$HOME/.cargo/bin:"* ]] && current_path="$HOME/.cargo/bin:$current_path"
[[ ":$current_path:" != *":$HOME/.local/bin:"* ]] && current_path="$HOME/.local/bin:$current_path"
export PATH="$current_path"
if ! command -v go &>/dev/null; then echo -e "${RED}[x] CRITICAL: Go not found in PATH after setup.${NC}"; exit 1; fi
if ! command -v rustc &>/dev/null; then echo -e "${RED}[x] CRITICAL: Rust not found in PATH after setup.${NC}"; exit 1; fi
echo "[*] Go version $(go version) is now active in this session."
echo "[*] Rust version $(rustc --version | head -n 1) is now active in this session."
SHELL_CONFIG_FILE=""; case "$SHELL" in */zsh) SHELL_CONFIG_FILE="$HOME/.zshrc" ;; */bash) SHELL_CONFIG_FILE="$HOME/.bashrc" ;; *) SHELL_CONFIG_FILE="$HOME/.profile" ;; esac
if [[ -f "$SHELL_CONFIG_FILE" || "$SHELL_CONFIG_FILE" == "$HOME/.profile" ]]; then
if ! grep -q '# CYBERSEC TOOLKIT PATHS' "$SHELL_CONFIG_FILE" 2>/dev/null; then
echo "[*] Writing configuration to $SHELL_CONFIG_FILE for persistence..."
printf "\n# CYBERSEC TOOLKIT PATHS\nexport GOROOT=/usr/local/go\nexport GOPATH=\$HOME/Tools/Go-Tools\nexport PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.cargo/bin:\$HOME/.local/bin:\$PATH\n\n" >> "$SHELL_CONFIG_FILE"
echo -e "${YELLOW}[*] Please run 'source $SHELL_CONFIG_FILE' or restart your terminal later for changes to persist.${NC}"
fi
else
echo -e "${YELLOW}[~] Shell config file $SHELL_CONFIG_FILE not found. Writing to $HOME/.profile instead.${NC}"
SHELL_CONFIG_FILE="$HOME/.profile"
touch "$SHELL_CONFIG_FILE"
if ! grep -q '# CYBERSEC TOOLKIT PATHS' "$SHELL_CONFIG_FILE" 2>/dev/null; then
echo "[*] Writing configuration to $SHELL_CONFIG_FILE for persistence..."
printf "\n# CYBERSEC TOOLKIT PATHS\nexport GOROOT=/usr/local/go\nexport GOPATH=\$HOME/Tools/Go-Tools\nexport PATH=\$GOPATH/bin:\$GOROOT/bin:\$HOME/.cargo/bin:\$HOME/.local/bin:\$PATH\n\n" >> "$SHELL_CONFIG_FILE"
echo -e "${YELLOW}[*] Please run 'source $SHELL_CONFIG_FILE' or restart your terminal later for changes to persist.${NC}"
fi
fi
echo "[+] Ensuring pipx path is configured..."; pipx ensurepath > /dev/null 2>&1 || true
if [[ -n "${SUDO_REFRESH_PID:-}" ]] && kill -0 "$SUDO_REFRESH_PID" 2>/dev/null; then kill "$SUDO_REFRESH_PID" 2>/dev/null || true; fi
trap - ERR INT TERM
PREREQUISITES_MET=true
export PREREQUISITES_MET
export GOROOT
export GOPATH
export PATH
echo ""; echo "======================================================================"
echo "         Prerequisite setup complete. You can now install tools.         "
echo "======================================================================"
sleep 2
}
show_categories_menu() {
clear
echo "========================================="
echo "        Tool Installation by Category      "
echo "========================================="
echo " 1. Reconnaissance & Enumeration"
echo " 2. Web Crawling & Discovery"
echo " 3. SQL Injection (SQLi)"
echo " 4. XSS Detection"
echo " 5. CRLF & HTTP Injection"
echo " 6. Directory & DNS Fuzzing"
echo " 7. Port & Service Scanning"
echo " 8. Secrets & Credentials"
echo " 9. Authentication Issues"
echo "10. URL & Parameter Analysis"
echo "11. Vulnerability Scanning"
echo "12. JavaScript Analysis"
echo "13. Cloud & Infrastructure"
echo "14. Advanced Exploitation"
echo "15. Misc Utilities"
echo "16. View All Tools"
echo " 0. Back to Main Menu"
echo "-----------------------------------------"
}
display_category_tools() {
local category="$1"
local category_name="$2"
local old_ifs="$IFS"
trap "IFS=\"$old_ifs\"" RETURN
clear
echo "========================================="
echo "         Tools in: $category_name"
echo "========================================="
echo
local -a category_tools_keys=()
for tool_key in "${!TOOLS_DB[@]}"; do
local tool_cat="${TOOLS_DB["$tool_key"]%%|*}"
if [[ "$tool_cat" == "$category" ]]; then
category_tools_keys+=("$tool_key")
fi
done
if [ ${#category_tools_keys[@]} -eq 0 ]; then
echo "No tools found in this category."
read -p "Press [Enter] to return to categories menu." < /dev/tty
return
fi
local sortable_tools=()
for key in "${category_tools_keys[@]}"; do
IFS='|' read -r _ name _ <<< "${TOOLS_DB["$key"]}"
[[ -n "$name" ]] && sortable_tools+=("$name|$key")
done
if [ ${#sortable_tools[@]} -eq 0 ]; then
echo "No tools found in this category after processing."
read -p "Press [Enter] to return." < /dev/tty
return
fi
local tmp_sort_file
tmp_sort_file=$(mktemp /tmp/sorted_tools.tmp.XXXXXX) || { echo "Failed to create temp file"; return 1; }
trap 'rm -f "$tmp_sort_file" 2>/dev/null; IFS="$old_ifs"' RETURN
printf "%s\n" "${sortable_tools[@]}" | LC_ALL=C sort -f > "$tmp_sort_file"
mapfile -t sorted_tools < "$tmp_sort_file"
rm -f "$tmp_sort_file"
trap "IFS=\"$old_ifs\"" RETURN
local tool_keys_sorted=()
if [[ ${#sorted_tools[@]} -gt 0 && -n "${sorted_tools[0]:-}" ]]; then
for item in "${sorted_tools[@]}"; do
[[ -n "$item" ]] && tool_keys_sorted+=("$(echo "$item" | rev | cut -d'|' -f1 | rev)")
done
else
echo "Error sorting tools or no tools found after sort."
read -p "Press [Enter] to return." < /dev/tty
return
fi
for i in "${!tool_keys_sorted[@]}"; do
local tool_key="${tool_keys_sorted[$i]}"
if [[ -v TOOLS_DB["$tool_key"] ]]; then
local name short_desc long_desc
local data="${TOOLS_DB["$tool_key"]}"
local name=$(echo "$data" | cut -d'|' -f2)
local short_desc=$(echo "$data" | cut -d'|' -f4)
local long_desc=$(echo "$data" | cut -d'|' -f5)
printf "%2d. %-20s\n" $((i+1)) "${name:-Unknown}"
echo "        Purpose: ${short_desc:-N/A}"
echo "        Finds: ${long_desc:-N/A}"
echo ""
else
echo "Warning: Invalid tool key found during display: $tool_key"
fi
done
echo " 0. Back to Categories"
echo "-----------------------------------------"
read -p "Enter tool number to install (or 0 to go back): " tool_choice < /dev/tty
if [[ "$tool_choice" == "0" ]]; then
return
fi
# --- FIX: Validate input IS a number *before* doing math ---
    if ! [[ "$tool_choice" =~ ^[0-9]+$ ]]; then
        echo -e "${RED}[x] Invalid choice. Must be a single number.${NC}"
        sleep 2
        return
    fi # <--- THIS 'fi' IS THE FIX

    local choice_index=$((tool_choice - 1))
    if [ "$choice_index" -ge 0 ] && [ "$choice_index" -lt ${#tool_keys_sorted[@]} ]; then
        local selected_tool_key="${tool_keys_sorted[$choice_index]}"
        if [[ -v TOOLS_DB["$selected_tool_key"] ]]; then
            install_single_tool "$selected_tool_key"
        else
            echo "Error: Selected tool key '$selected_tool_key' is invalid."
            sleep 2
        fi
    else
        echo "Invalid choice. Please try again."
        sleep 2
    fi
}
display_all_tools() {
local old_ifs="$IFS"
trap "IFS=\"$old_ifs\"" RETURN
clear
echo "========================================="
echo "               All Available Tools           "
echo "========================================="
echo
local -a all_tool_keys=("${!TOOLS_DB[@]}")
if [ ${#all_tool_keys[@]} -eq 0 ]; then
echo "Tool database is empty."
read -p "Press [Enter] to return." < /dev/tty
return
fi
local sortable_tools=()
for key in "${all_tool_keys[@]}"; do
IFS='|' read -r _ name _ <<< "${TOOLS_DB["$key"]}"
[[ -n "$name" ]] && sortable_tools+=("$name|$key")
done
if [ ${#sortable_tools[@]} -eq 0 ]; then
echo "Tool database is empty after processing."
read -p "Press [Enter] to return." < /dev/tty
return
fi
local tmp_sort_file
tmp_sort_file=$(mktemp /tmp/sorted_tools.tmp.XXXXXX) || { echo "Failed to create temp file"; return 1; }
trap 'rm -f "$tmp_sort_file" 2>/dev/null; IFS="$old_ifs"' RETURN
printf "%s\n" "${sortable_tools[@]}" | LC_ALL=C sort -f > "$tmp_sort_file"
mapfile -t sorted_tools < "$tmp_sort_file"
rm -f "$tmp_sort_file"
trap "IFS=\"$old_ifs\"" RETURN
local tool_keys_sorted=()
if [[ ${#sorted_tools[@]} -gt 0 && -n "${sorted_tools[0]:-}" ]]; then
for item in "${sorted_tools[@]}"; do
[[ -n "$item" ]] && tool_keys_sorted+=("$(echo "$item" | rev | cut -d'|' -f1 | rev)")
done
else
echo "Error sorting tools or no tools found after sort."
read -p "Press [Enter] to return." < /dev/tty
return
fi
for i in "${!tool_keys_sorted[@]}"; do
local tool_key="${tool_keys_sorted[$i]}"
if [[ -v TOOLS_DB["$tool_key"] ]]; then
local data="${TOOLS_DB["$tool_key"]}"
local cat=$(echo "$data" | cut -d'|' -f1)
local name=$(echo "$data" | cut -d'|' -f2)
printf "%3d. %-25s [%-15s]\n" $((i+1)) "${name:-Unknown}" "${cat:-N/A}"
else
echo "Warning: Invalid tool key found during display: $tool_key"
fi
done
echo "   0. Back to Categories Menu"
echo "-----------------------------------------"
read -p "Enter tool number to install (or 0 to go back): " tool_choice < /dev/tty
if [[ "$tool_choice" == "0" ]]; then
return
fi
if ! [[ "$tool_choice" =~ ^[0-9]+$ ]]; then
    echo -e "${RED}[x] Invalid choice. Must be a single number.${NC}"
    sleep 2
    return
fi

local choice_index=$((tool_choice - 1))
if [ "$choice_index" -ge 0 ] && [ "$choice_index" -lt ${#tool_keys_sorted[@]} ]; then
    local selected_tool_key="${tool_keys_sorted[$choice_index]}"
    if [[ -v TOOLS_DB["$selected_tool_key"] ]]; then
        install_single_tool "$selected_tool_key"
    else
        echo "Error: Selected tool key '$selected_tool_key' is invalid."
        sleep 2
    fi
else
    echo "Invalid choice. Please try again."
    sleep 2
fi
}
install_single_tool() {
local tool_key="$1"
local old_ifs="$IFS"
trap "IFS=\"$old_ifs\"" RETURN
if [[ ! -v TOOLS_DB["$tool_key"] ]]; then
echo -e "${RED}Tool key '$tool_key' not found in database.${NC}"
sleep 2
return
fi
local data="${TOOLS_DB["$tool_key"]}"
local category=$(echo "$data" | cut -d'|' -f1)
local name=$(echo "$data" | cut -d'|' -f2)
local cmd=$(echo "$data" | cut -d'|' -f3)
local short_desc=$(echo "$data" | cut -d'|' -f4)
local long_desc=$(echo "$data" | cut -d'|' -f5)
if [[ -z "$name" ]] || [[ -z "$cmd" ]]; then
echo -e "${RED}[x] Failed to parse tool data for key: $tool_key${NC}"
echo "Check TOOLS_DB format near this entry."
read -p "Press [Enter] to continue." < /dev/tty
return
fi
clear
echo "========================================="
echo "            Installing: $name"
echo "========================================="
echo "Category: $category"
echo "Purpose: $short_desc"
echo "Finds: $long_desc"
echo
ensure_prerequisites || { echo "${RED}Prerequisite setup failed. Cannot install tool.${NC}"; sleep 3; return 1; }
local check_command="$tool_key"
local check_key="${check_command,,}"
if [[ -n "$check_command" ]] && [[ -v BINARY_NAME_MAP["$check_key"] ]]; then
local actual_binary="${BINARY_NAME_MAP["$check_key"]}"
check_command="$actual_binary"
fi
local gopath_bin=""
if [[ -n "${GOPATH:-}" && -n "$check_command" ]]; then
gopath_bin="$GOPATH/bin/$check_command"
fi
local pipx_bin="$HOME/.local/bin/$check_command"
local tool_exists=false
if [[ -n "$check_command" ]]; then
if command -v "$check_command" &>/dev/null || \
[[ -n "$gopath_bin" && -x "$gopath_bin" ]] || \
[[ -x "$pipx_bin" ]]; then
tool_exists=true
fi
fi
local proceed_install=true
if $tool_exists; then
echo -e "${YELLOW}[!] Tool '$name' is already installed.${NC}"
local REPLY=""
while true; do
read -p "Do you want to force re-installation? (y/N): " -n 1 -r REPLY < /dev/tty
echo
case "$REPLY" in
[Yy])
echo -e "${CYAN}[*] Forcing re-installation of $name...${NC}"
proceed_install=true
break
;;
[Nn]|"")
printf "${YELLOW}[~] %-25s - SKIPPED BY USER${NC}\n" "$name"
proceed_install=false
break
;;
*)
echo -e "${RED}[x] Invalid input. Please enter 'y' or 'n'.${NC}" >&2
;;
esac
done
fi
if [[ "$proceed_install" == true ]]; then
if [[ -z "${GOPATH:-}" ]] || [[ -z "${GOROOT:-}" ]]; then
echo -e "${RED}[!] Environment variables lost! Re-initializing...${NC}"
export GOROOT="/usr/local/go"
export GOPATH="$HOME/Tools/Go-Tools"
export PATH="$GOPATH/bin:$GOROOT/bin:$HOME/.cargo/bin:$HOME/.local/bin:$PATH"
fi  
export IS_MANUAL_INSTALL=true
install_tool_robust "$name" "$tool_key" "$cmd"
unset IS_MANUAL_INSTALL
fi
read -p "Press [Enter] to continue." < /dev/tty
}
manual_install_menu() {
while true; do
show_categories_menu
read -p "Enter your choice [0-16]: " choice < /dev/tty
if [[ "$choice" =~ ^[1-9]$|^1[0-6]$ ]]; then
if ! ensure_prerequisites; then
echo "${RED}Prerequisite setup failed. Cannot proceed with manual installation.${NC}"
sleep 3
continue
fi
fi
case $choice in
1) display_category_tools "recon-enum" "Reconnaissance & Enumeration" ;;
2) display_category_tools "web-crawl" "Web Crawling & Discovery" ;;
3) display_category_tools "sqli-detect" "SQL Injection (SQLi)" ;;
4) display_category_tools "xss-detect" "XSS Detection" ;;
5) display_category_tools "http-inject" "CRLF & HTTP Injection" ;;
6) display_category_tools "fuzzing" "Directory & DNS Fuzzing" ;;
7) display_category_tools "scanning" "Port & Service Scanning" ;;
8) display_category_tools "secrets" "Secrets & Credentials" ;;
9) display_category_tools "auth-test" "Authentication Issues" ;;
10) display_category_tools "url-analysis" "URL & Parameter Analysis" ;;
11) display_category_tools "vuln-scan" "Vulnerability Scanning" ;;
12) display_category_tools "js-analysis" "JavaScript Analysis" ;;
13) display_category_tools "cloud" "Cloud & Infrastructure" ;;
14) display_category_tools "exploit" "Advanced Exploitation" ;;
15) display_category_tools "misc-util" "Misc Utilities" ;;
16) display_all_tools ;;
0) return ;;
*) echo "Invalid choice. Try again."; sleep 2 ;;
esac
done
}
uninstall_tools() {
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
clear
echo -e "${YELLOW}[*] Refreshing sudo timestamp for uninstall...${NC}"
if ! sudo -v; then
echo -e "${RED}[x] Sudo authentication failed. Cannot proceed with uninstall.${NC}"
read -p "Press [Enter] to return to the menu." < /dev/tty
return 1
fi
echo -e "${GREEN}[+] Sudo timestamp refreshed.${NC}"
local LOG_FILE
local UNINSTALL_LOG_FILE
UNINSTALL_LOG_FILE="/tmp/toolkit_uninstall_$(date +%F_%T).log"
touch "$UNINSTALL_LOG_FILE"
trap 'echo -e "\n\n${RED}[!] Uninstall aborted by user.${NC}"; return 130' INT TERM
msg() { echo -e "\n${GREEN}[*]${NC} ${CYAN}$1${NC}"; }
show_error() {
STOP_SPINNER
echo -e "${RED}[x] $1${NC}"
echo -e "${YELLOW}--- Last 10 lines from log ($UNINSTALL_LOG_FILE) ---${NC}"
tail -n 10 "$UNINSTALL_LOG_FILE" | sed 's/^/    /g'
echo -e "${YELLOW}--------------------------------------------${NC}"
}
echo -e "\n${GREEN}[*]${NC} ${CYAN}A full log of this uninstall run will be saved to:${NC}"
echo -e "${CYAN}    $UNINSTALL_LOG_FILE${NC}"
echo -e "\n${RED}!!! CAUTION !!!${NC}"
echo "This script will UNINSTALL the toolkit and RECONFIGURE your swap memory."
local REPLY=""
while true; do
read -p "Are you absolutely sure you want to continue? [Press Enter for default 'NO'] (y/N): " -n 1 -r REPLY < /dev/tty
echo
case "$REPLY" in
[Yy])
echo "[*] Proceeding with uninstallation..."
break
;;
[Nn]|"")
echo -e "${YELLOW}[-] Aborting.${NC}"
sleep 1
trap - INT TERM
return 0
;;
*)
echo -e "${RED}[x] Invalid input. Please enter 'y' or 'n'.${NC}" >&2
;;
esac
done
msg "SECTION 1: Removing Go & Go-based tools..."
START_SPINNER "Removing Go directories"
if ! sudo rm -rf /usr/local/go "$HOME/go" "$HOME/Tools" &>> "$UNINSTALL_LOG_FILE"; then
show_error "Failed to remove Go directories."
fi
STOP_SPINNER
echo "[+] Removed Go installation and workspaces."
msg "SECTION 2: Removing Rust & Rust-based tools..."
START_SPINNER "Uninstalling Rust and removing directories"
local rust_failed=false
if command -v cargo &>/dev/null; then
cargo uninstall ripgen &>> "$UNINSTALL_LOG_FILE" || true
fi
if command -v rustup &>/dev/null; then 
rustup self uninstall -y &>> "$UNINSTALL_LOG_FILE" || rust_failed=true
fi
rm -rf "$HOME/.cargo" "$HOME/.rustup" &>> "$UNINSTALL_LOG_FILE" || rust_failed=true
if $rust_failed; then
show_error "Some Rust removal commands failed. Check log."
fi
STOP_SPINNER
echo "[+] Removed Cargo and Rustup directories."
msg "SECTION 3: Cleaning shell configuration (.zshrc & .bashrc & .profile)..."
SHELL_FILES=("$HOME/.zshrc" "$HOME/.bashrc" "$HOME/.profile")
for file in "${SHELL_FILES[@]}"; do
if [ -f "$file" ]; then
sed -i.bak '/^# CYBERSEC TOOLKIT PATHS/,/^$/d' "$file" &>> "$UNINSTALL_LOG_FILE"
rm -f "$file.bak" &>> "$UNINSTALL_LOG_FILE"
echo "[+] Cleaned $file."
fi
done
msg "SECTION 4: Uninstalling Python tools..."
if command -v pipx &> /dev/null; then
echo "[*] Listing all pipx-installed tools before removal..."
pipx list 2>/dev/null || true
PYTHON_PIPX_TOOLS=(arjun bbot corscanner dirsearch dotgit shodan uro waymore xnLinkFinder py-altdns interlace recollapse)
echo "[*] Uninstalling known toolkit pipx tools..."
for tool in "${PYTHON_PIPX_TOOLS[@]}"; do
if pipx list 2>/dev/null | grep -qw "$tool"; then
echo "[~] Attempting to uninstall via pipx: $tool"
pipx uninstall "$tool" &>> "$UNINSTALL_LOG_FILE" || { echo -e "${YELLOW}[!] Warning: Failed to uninstall $tool via pipx.${NC}" >&2; }
fi
done
echo "[+] Attempted to uninstall pipx tools via pipx command."
echo "[*] Cleaning up potential leftover symlinks/files in ~/.local/bin/ for toolkit tools..."
for tool in "${PYTHON_PIPX_TOOLS[@]}"; do
    
    # --- ADD THESE LINES ---
    local potential_names=("$tool")
    local mapped_name="${BINARY_NAME_MAP[$tool]}"
    [[ -n "$mapped_name" ]] && potential_names+=("$mapped_name")
    # --- END ADD ---

for name_variant in "${potential_names[@]}"; do
local link_path="$HOME/.local/bin/$name_variant"
if [[ -e "$link_path" ]]; then
echo "[~] Removing potentially leftover file/link: $link_path"
if ! rm -fv "$link_path" &>> "$UNINSTALL_LOG_FILE"; then echo "${YELLOW}[!] Warning: Failed to remove $link_path${NC}" >&2; fi
fi
done
done
echo "[+] Cleaned up potential toolkit-related files from ~/.local/bin/."
fi
if command -v pip3 &> /dev/null; then
PYTHON_PIP3_TOOLS=(dnsgen python-pler ghauri)
START_SPINNER "Uninstalling pip3 tools (dnsgen, python-pler, ghauri)"
pip3 uninstall -y "${PYTHON_PIP3_TOOLS[@]}" --break-system-packages &>> "$UNINSTALL_LOG_FILE" || true
STOP_SPINNER
echo "[+] Attempted to uninstall pip3 tools."
fi
msg "SECTION 5: Removing binaries & packages from source/other methods..."
START_SPINNER "Removing binaries and source-installed packages"
BINS_TO_REMOVE=(massdns urldedupe linkfinder rcert analyticsrelationships trufflehog xssrecon urlgrab pathfinder roboxtractor ssb aquatone ppfuzz x8 feroxbuster)
for bin_name in "${BINARY_NAME_MAP[@]}"; do BINS_TO_REMOVE+=("$bin_name"); done
local unique_bins; unique_bins=$(printf "%s\n" "${BINS_TO_REMOVE[@]}" | sort -u)
echo "$unique_bins" | while IFS= read -r bin_name; do
if [[ -n "$bin_name" ]]; then
sudo rm -f "/usr/local/bin/$bin_name" &>> "$UNINSTALL_LOG_FILE"
sudo rm -f "$HOME/Tools/Go-Tools/bin/$bin_name" &>> "$UNINSTALL_LOG_FILE"
fi
done
if command -v dpkg &>/dev/null && dpkg -s feroxbuster &>/dev/null; then sudo dpkg --purge feroxbuster &>> "$UNINSTALL_LOG_FILE" || true; fi
if command -v gem &>/dev/null; then if gem list --local | grep -q 'wpscan'; then sudo gem uninstall wpscan --executables &>> "$UNINSTALL_LOG_FILE" || true; fi; fi
STOP_SPINNER
echo "[+] Removed binaries and source-installed packages."
msg "SECTION 6: Removing configurations & temp directories..."
START_SPINNER "Removing config and temp directories"
rm -rf "$HOME/.gf" "$HOME/build-temp" &>> "$UNINSTALL_LOG_FILE"
rm -f "$CUSTOM_DB_FILE" &>> "$UNINSTALL_LOG_FILE"
STOP_SPINNER
echo "[+] Removed config and temp directories."
msg "SECTION 7: Reconfiguring Swap Memory..."
echo "[~] Disabling ALL active swap devices..."
START_SPINNER "Running swapoff -a"
local swapoff_success=true
if ! sudo swapoff -a &>> "$UNINSTALL_LOG_FILE"; then
swapoff_success=false
fi
if ! $swapoff_success; then
show_error "Failed to disable all swap devices. Errors during removal/creation might occur."
sleep 2
else
STOP_SPINNER
echo "[+] All swap devices disabled."
fi
sleep 1
echo "[~] Removing existing swap file configurations from fstab..."
START_SPINNER "Cleaning /etc/fstab"
sudo sed -i.bak '\|\/swapfile|d' /etc/fstab &>> "$UNINSTALL_LOG_FILE"
sudo sed -i.bak '\|\/swap\/swapfile|d' /etc/fstab &>> "$UNINSTALL_LOG_FILE"
sudo rm -f /etc/fstab.bak &>> "$UNINSTALL_LOG_FILE"
STOP_SPINNER
echo "[~] Attempting removal of potential swap files/volumes..."
START_SPINNER "Removing old /swapfile paths"
sudo rm -f /swapfile &>> "$UNINSTALL_LOG_FILE" || true
sudo rm -f /swap/swapfile &>> "$UNINSTALL_LOG_FILE" || true
STOP_SPINNER
if [ -d /swap ]; then
echo "[*] Found /swap directory/subvolume. Attempting removal..."
if sudo btrfs subvolume list / | grep -q ' /swap$'; then
echo "[~] Attempting to delete btrfs subvolume /swap..."
START_SPINNER "Deleting btrfs subvolume /swap"
if ! sudo btrfs subvolume delete /swap &>> "$UNINSTALL_LOG_FILE"; then
sleep 1
if ! sudo btrfs subvolume delete /swap &>> "$UNINSTALL_LOG_FILE"; then
show_error "Failed to delete /swap btrfs subvolume after retry. Attempting rm -rf."
sudo rm -rf /swap &>> "$UNINSTALL_LOG_FILE" || true
else
STOP_SPINNER
echo "[+] btrfs subvolume /swap deleted on retry."
fi
else
STOP_SPINNER
echo "[+] btrfs subvolume /swap deleted."
fi
else
echo "[~] /swap exists but is not a btrfs subvolume. Removing as directory..."
START_SPINNER "Removing /swap directory"
sudo rm -rf /swap &>> "$UNINSTALL_LOG_FILE" || true
STOP_SPINNER
fi
if [ -e /swap ]; then
echo "${YELLOW}[!] Warning: Failed to completely remove /swap.${NC}"
else
echo "[+] /swap successfully removed."
fi
else
echo "[~] /swap path not found, skipping specific removal."
fi
echo "[+] Old swap configurations/paths removed/attempted removal."
setup_swap_uninstall() {
echo -e "\n[~] Creating a new, intelligently-sized swap file..."
local MEM_KB MEM_GB SWAP_SIZE_GB FS_TYPE SWAP_PATH
MEM_KB=$(grep MemTotal /proc/meminfo | awk '{print $2}')
MEM_GB=$((MEM_KB / 1024 / 1024))
if [ "$MEM_GB" -lt 2 ]; then SWAP_SIZE_GB=4
elif [ "$MEM_GB" -le 8 ]; then SWAP_SIZE_GB=$MEM_GB
else SWAP_SIZE_GB=8; fi
echo "[*] RAM detected: ${MEM_GB}GB. New swap size: ${SWAP_SIZE_GB}GB."
FS_TYPE=$(findmnt -n -o FSTYPE /)
SWAP_PATH="/swapfile"
LOG_FILE=$(mktemp) 
trap '[[ -n "$LOG_FILE" ]] && rm -f "$LOG_FILE" 2>/dev/null' RETURN
if [ "$FS_TYPE" = "btrfs" ]; then
echo "[*] Detected btrfs filesystem. Creating swap in /swap subvolume..."
SWAP_PATH="/swap/swapfile"
if [ -e /swap ]; then
echo "${RED}[x] /swap path still exists unexpectedly. Cannot create subvolume safely.${NC}"; return 1;
fi
echo "[~] Creating /swap subvolume..."
START_SPINNER "Creating /swap subvolume"
if ! sudo btrfs subvolume create /swap &> "$LOG_FILE"; then
STOP_SPINNER
echo "${RED}[x] Failed to create /swap subvolume. Error: $?${NC}"; cat "$LOG_FILE"; return 1;
fi
STOP_SPINNER
echo "[+] /swap subvolume created."
sudo chattr +C /swap &>> "$LOG_FILE" || { echo "${YELLOW}[!] Warning: Failed to set No_COW attribute on /swap.${NC}"; }
sudo touch "$SWAP_PATH" &>> "$LOG_FILE" || { echo "${RED}[x] Failed to touch swapfile $SWAP_PATH.${NC}"; cat "$LOG_FILE"; return 1; }
echo "[*] Using dd to allocate swap on btrfs (may take time)..."
sudo truncate -s 0 "$SWAP_PATH" &>> "$LOG_FILE" || { echo "${YELLOW}[!] Warning: Failed to truncate swapfile $SWAP_PATH before dd.${NC}"; }
START_SPINNER "Allocating ${SWAP_SIZE_GB}GB swap on btrfs (dd)"
if ! sudo dd if=/dev/zero of="$SWAP_PATH" bs=1G count=$SWAP_SIZE_GB oflag=sync &> "$LOG_FILE"; then
STOP_SPINNER
echo "${RED}[x] dd failed for btrfs swap file creation.${NC}"; cat "$LOG_FILE"; return 1;
fi
STOP_SPINNER
else
echo "[*] Detected non-btrfs filesystem ($FS_TYPE). Creating swap with fallocate..."
START_SPINNER "Allocating ${SWAP_SIZE_GB}G swap (fallocate)"
if ! sudo fallocate -l "${SWAP_SIZE_GB}G" "$SWAP_PATH" &> "$LOG_FILE"; then
STOP_SPINNER
echo -e "${YELLOW}[~] fallocate failed. Falling back to 'dd' (this may be slow)...${NC}"
sudo rm -f "$SWAP_PATH" &>/dev/null || true
START_SPINNER "Allocating ${SWAP_SIZE_GB}GB swap (dd fallback)"
if ! sudo dd if=/dev/zero of="$SWAP_PATH" bs=1G count=$SWAP_SIZE_GB oflag=sync &> "$LOG_FILE"; then
STOP_SPINNER
echo "${RED}[x] dd fallback failed for swap file creation.${NC}"; cat "$LOG_FILE"; return 1;
fi
STOP_SPINNER
else
STOP_SPINNER
echo "[+] fallocate successful."
fi
fi
echo "[*] Setting permissions and activating swap..."
START_SPINNER "Setting permissions and activating swap (chmod, mkswap, swapon)"
sudo chmod 600 "$SWAP_PATH" &>> "$LOG_FILE" || { STOP_SPINNER; echo "${RED}[x] Failed to chmod swapfile.${NC}"; cat "$LOG_FILE"; return 1; }
if ! sudo mkswap "$SWAP_PATH" &>> "$LOG_FILE"; then STOP_SPINNER; echo "${RED}[x] mkswap failed.${NC}"; cat "$LOG_FILE"; return 1; fi
if ! sudo swapon "$SWAP_PATH" &>> "$LOG_FILE"; then STOP_SPINNER; echo "${RED}[x] swapon failed.${NC}"; cat "$LOG_FILE"; return 1; fi
STOP_SPINNER
sleep 0.1 # <--- ADD THIS LINE
echo "[*] Adding swap entry to /etc/fstab..."
if ! grep -qF "\"$SWAP_PATH\" none swap" /etc/fstab; then
echo "\"$SWAP_PATH\" none swap sw 0 0" | sudo tee -a /etc/fstab > /dev/null
fi
echo "[+] New swap file created and activated."
rm -f "$LOG_FILE" 2>/dev/null
trap - RETURN
return 0
}
if ! setup_swap_uninstall; then
echo "${RED}[x] Failed to set up new swap file during uninstall cleanup.${NC}"
trap - INT TERM
return 1
fi
msg "SECTION 8: Cleaning up APT packages..."
START_SPINNER "Running apt-get --fix-broken install"
if ! sudo apt-get --fix-broken install -y -qq &>> "$UNINSTALL_LOG_FILE"; then
show_error "apt-get --fix-broken install failed."
fi
STOP_SPINNER
local OS_ID
OS_ID=$(grep -E '^ID=' /etc/os-release | cut -d'=' -f2 | tr -d '"')
if [ "$OS_ID" == "debian" ]; then
PACKAGES_TO_UNINSTALL=(libpcap-dev libssl-dev libpcre2-dev python3-setuptools pkg-config parallel ruby-dev cmake libtool autoconf automake psmisc dos2unix xsel yq npm cewl)
PACKAGES_TO_UNINSTALL+=(libudev1)
else
PACKAGES_TO_UNINSTALL=(libpcap-dev libssl-dev libpcre3-dev pkg-config parallel ruby-dev cmake libtool autoconf automake psmisc dos2unix xsel yq npm cewl)
[[ "$OS_ID" == "parrot" ]] && PACKAGES_TO_UNINSTALL+=(libudev1) || PACKAGES_TO_UNINSTALL+=(libudev-dev)
dpkg -s sublist3r &>/dev/null && PACKAGES_TO_UNINSTALL+=(sublist3r)
dpkg -s wpscan &>/dev/null && PACKAGES_TO_UNINSTALL+=(wpscan)
dpkg -s sqlmap &>/dev/null && PACKAGES_TO_UNINSTALL+=(sqlmap)
dpkg -s masscan &>/dev/null && PACKAGES_TO_UNINSTALL+=(masscan)
dpkg -s pipx &>/dev/null && PACKAGES_TO_UNINSTALL+=(pipx)
echo "[*] Removing specific prerequisite packages..."
local existing_packages_to_uninstall=()
for pkg in "${PACKAGES_TO_UNINSTALL[@]}"; do
if dpkg-query -W -f='${Status}' "$pkg" 2>/dev/null | grep -q "ok installed"; then
existing_packages_to_uninstall+=("$pkg")
fi
done
if [[ ${#existing_packages_to_uninstall[@]} -gt 0 ]]; then
echo "[*] Purging: ${existing_packages_to_uninstall[*]}"
START_SPINNER "Purging ${#existing_packages_to_uninstall[@]} apt packages"
if ! sudo DEBIAN_FRONTEND=noninteractive apt-get purge -y "${existing_packages_to_uninstall[@]}" &>> "$UNINSTALL_LOG_FILE"; then
show_error "Failed to purge some apt packages."
echo -e "${YELLOW}[!] Warning: Failed to remove some prerequisite packages. Check logs.${NC}"
fi
STOP_SPINNER
else
echo "[~] No specific prerequisite packages found installed via apt to remove."
fi
echo "[*] Running apt autoremove and clean..."
START_SPINNER "Running apt autoremove and clean"
sudo DEBIAN_FRONTEND=noninteractive apt-get autoremove -y --purge &>> "$UNINSTALL_LOG_FILE" && sudo DEBIAN_FRONTEND=noninteractive apt-get clean &>> "$UNINSTALL_LOG_FILE"
STOP_SPINNER
echo "[+] Prerequisite packages cleaned."
fi
msg "Cleanup and reconfiguration finished!"
echo -e "${GREEN}[*]${NC} ${CYAN}Full uninstall log is available at: ${UNINSTALL_LOG_FILE}${NC}"
trap - INT TERM
echo
echo "======================================================================"
read -p "Uninstallation process finished. Press [Enter] to return to the menu." < /dev/tty
}
extract_binary_name() {
local install_cmd="$1"
local bin_name=""
install_cmd=$(echo "$install_cmd" | xargs)
if [[ "$install_cmd" =~ go[[:space:]]+install ]]; then
bin_name=$(echo "$install_cmd" | grep -oP '/cmd/([^/@[:space:]]+)' | rev | cut -d'/' -f1 | rev | head -n1)
if [[ -z "$bin_name" ]]; then
bin_name=$(echo "$install_cmd" | grep -oP 'github\.com/[^[:space:]]+/\K[^/@[:space:]]+$' | tail -n1)
fi
elif [[ "$install_cmd" =~ (pipx|pip3)[[:space:]]+install ]]; then
if [[ "$install_cmd" == *"git+"* ]]; then
bin_name=$(echo "$install_cmd" | grep -oP '/\K[^.@[:space:]]+(\.git)?$' | sed 's/\.git$//' | head -n1)
else
bin_name=$(echo "$install_cmd" | sed -n -E 's/^\s*(pipx|pip3)\s+install\s+((--|-[^-])\S+\s+)*([^[:space:]-]+).*/\4/p')
fi
[[ "$bin_name" == "python-pler" ]] && bin_name="pler"
elif [[ "$install_cmd" =~ cargo[[:space:]]+install ]]; then
bin_name=$(echo "$install_cmd" | sed -n -E 's/.*cargo\s+install\s+((--|-[^-])\S+\s+)*([^[:space:]]+).*/\3/p')
elif [[ "$install_cmd" =~ (cp|mv|ln|sudo[[:space:]]+cp|sudo[[:space:]]+mv|sudo[[:space:]]+ln)[[:space:]].*\/usr\/local\/bin\/ ]] || \
[[ "$install_cmd" =~ (cp|mv|ln|sudo[[:space:]]+cp|sudo[[:space:]]+mv|sudo[[:space:]]+ln)[[:space:]].*\$GOPATH\/bin\/ ]]; then
bin_name=$(echo "$install_cmd" | sed -E 's/.*(\/usr\/local\/bin\/|\$GOPATH\/bin\/)([^[:space:]\/]+)\s*$/\2/' | tail -n1)
elif [[ "$install_cmd" == *"trufflehog"* && "$install_cmd" == *curl* ]]; then
bin_name="trufflehog"
elif [[ "$install_cmd" == *"kitabisa-ssb"* && "$install_cmd" == *curl* ]]; then
bin_name="ssb"
elif [[ "$install_cmd" == *rustup.rs* ]]; then
bin_name="rustc"
fi
echo "$bin_name"
}
load_custom_tools_db() {
CUSTOM_TOOLS_DB=()
CUSTOM_TOOLS_INDEX_TO_KEY=()
declare -gA CUSTOM_TOOLS_DB
declare -gA CUSTOM_TOOLS_INDEX_TO_KEY
if [[ ! -f "$CUSTOM_DB_FILE" ]]; then
touch "$CUSTOM_DB_FILE"
chmod 600 "$CUSTOM_DB_FILE"
fi
if [[ ! -r "$CUSTOM_DB_FILE" ]]; then
echo "${RED}Error: Cannot read custom DB file: $CUSTOM_DB_FILE. Check permissions.${NC}" >&2
return 1
fi
local i=0
local old_ifs="$IFS"
local read_error=false
while true; do
IFS='|' read -r key cat name short long cmd
local read_status=$?
if [[ $read_status -gt 1 ]]; then
echo "${YELLOW}Warning: Potential read error parsing line in $CUSTOM_DB_FILE (status: $read_status)${NC}" >&2
read_error=true
continue
fi
[[ $read_status -eq 1 ]] && break
if [[ -n "$key" ]]; then
if [[ "$key" != custom_* ]]; then
echo "${YELLOW}Warning: Skipping invalid key '$key' (does not start with 'custom_') in $CUSTOM_DB_FILE${NC}" >&2
continue
fi
CUSTOM_TOOLS_DB["$key"]="$cat|$name|$short|$long|$cmd"
CUSTOM_TOOLS_INDEX_TO_KEY[$i]="$key"
i=$((i+1))
fi
done < "$CUSTOM_DB_FILE"
IFS="$old_ifs"
if [[ "$read_error" == true ]]; then
echo "${YELLOW}Warning: Some lines in the custom DB file may have been skipped due to errors.${NC}" >&2
fi
return 0
}
add_custom_tool() {
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
clear
echo "========================================="
echo "          Add a New Custom Tool          "
echo "========================================="
echo "This will guide you through adding a definition for a custom tool."
echo "The definition tells Pen-Forge how to list, install, and describe your tool."
echo
echo "You will be asked for the following details:"
echo "  - Tool Key: A unique, single word (no spaces or '|') used internally."
echo "              Ideally, this matches the command name (e.g., 'mytool')."
echo "              It cannot conflict with built-in tool keys."
echo "  - Display Name: How the tool's name should appear in menus (e.g., 'My Awesome Scanner')."
echo "  - Category: A short identifier for grouping (e.g., 'custom-recon', defaults to 'custom-tool')."
echo "  - Install Command: The *full* shell command needed to install the tool."
echo "                   (e.g., 'go install github.com/user/repo/cmd/mytool@latest',"
echo "                         'pipx install mytool', 'sudo apt install -y mytool', etc.)"
echo "                   Ensure this command works correctly in your terminal first!"
echo "  - Short Description: A brief summary of the tool's purpose."
echo "  - Long Description: What kind of information the tool finds or outputs."
echo
echo "Press Ctrl+C at any time to cancel adding the tool."
echo "-----------------------------------------"
local tool_key display_name category install_cmd short_desc long_desc prefixed_tool_key REPLY overwrite=false
local existing_line=""
read -p "Tool Key (one word, command name, e.g., 'mytool'): " tool_key < /dev/tty
if [[ -z "$tool_key" ]] || [[ "$tool_key" == *" "* ]] || [[ "$tool_key" == *"|"* ]]; then
echo -e "${RED}Invalid Tool Key. Must be a single word and cannot contain '|'. Aborting.${NC}"; sleep 2; return
fi
prefixed_tool_key="custom_$tool_key"
local check_key="${tool_key,,}"
if [[ -v TOOLS_DB["$check_key"] ]] || [[ -v BINARY_NAME_MAP["$check_key"] ]]; then
echo -e "${RED}[x] ERROR: Key '$tool_key' conflicts with a built-in tool or mapped name.${NC}"; sleep 3; return
fi
read -p "Display Name (e.g., 'My Awesome Scanner'): " display_name < /dev/tty
if [[ -z "$display_name" ]]; then echo -e "${RED}Display Name cannot be empty. Aborting.${NC}"; sleep 2; return; fi
read -p "Category (e.g., 'custom-recon', defaults to 'custom-tool'): " category < /dev/tty
if [[ -z "$category" ]]; then category="custom-tool"; fi
echo "Install Command (full command to install, e.g., 'go install ...'):"
read -e -p "> " install_cmd < /dev/tty
if [[ -z "$install_cmd" ]]; then echo -e "${RED}Install Command cannot be empty. Aborting.${NC}"; sleep 2; return; fi
read -p "Short Description (Purpose, optional): " short_desc < /dev/tty
if [[ -z "$short_desc" ]]; then short_desc="N/A"; fi
read -p "Long Description (Finds, optional): " long_desc < /dev/tty
if [[ -z "$long_desc" ]]; then long_desc="N/A"; fi
[[ ! -f "$CUSTOM_DB_FILE" ]] && touch "$CUSTOM_DB_FILE" && chmod 600 "$CUSTOM_DB_FILE"
(
exec 9>>"$CUSTOM_DB_FILE"
if ! flock -x -w 5 9; then
echo "${RED}Error: Could not acquire write lock on custom DB file.${NC}" >&2; exec 9>&-; exit 101;
fi
local current_content
current_content=$(cat "$CUSTOM_DB_FILE" 2>/dev/null || true)
existing_line=$(echo "$current_content" | grep -F "$prefixed_tool_key|" || true)
local new_content=()
overwrite=false
if [[ -n "$existing_line" ]]; then
echo -e "\n${YELLOW}[!] A custom tool with key '$tool_key' already exists.${NC}" >&2
while true; do
read -p "Do you want to overwrite it? [Press Enter for default 'NO'] (y/N): " -n 1 -r REPLY < /dev/tty
echo >&2
case "$REPLY" in
[Yy])
overwrite=true
break
;;
[Nn]|"")
echo "[*] Aborting." >&2
flock -u 9; exec 9>&-; exit 100
;;
*)
echo -e "${RED}[x] Invalid input. Please enter 'y' or 'n'.${NC}" >&2
;;
esac
done
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
fi
local new_line="$prefixed_tool_key|$category|$display_name|$short_desc|$long_desc|$install_cmd"
if [[ "$overwrite" == true ]]; then
local filtered_lines=()
while IFS= read -r line; do
[[ -n "$line" ]] && filtered_lines+=("$line")
done < <(echo "$current_content" | grep -F -v -- "$prefixed_tool_key|")
new_content=("${filtered_lines[@]}")
new_content+=("$new_line")
echo "[*] Old entry will be overwritten." >&2
else
if [[ -n "$current_content" ]]; then
mapfile -t new_content < <(echo "$current_content")
else
new_content=()
fi
new_content+=("$new_line")
echo "[*] New entry will be added." >&2
fi
local printf_status=1 
if [[ ${#new_content[@]} -gt 0 ]]; then
printf "%s\n" "${new_content[@]}" > "$CUSTOM_DB_FILE"
printf_status=$? 
else
: > "$CUSTOM_DB_FILE" 
printf_status=$? 
fi
if [[ $printf_status -ne 0 ]]; then
echo "${RED}Error: Failed to write to DB file (Code: $printf_status).${NC}" >&2
flock -u 9; exec 9>&-; exit 103
fi
flock -u 9 
)
local subshell_status=$?
exec 9>&- 2>/dev/null || true
if [[ $subshell_status -eq 100 ]]; then
echo "[*] Overwrite aborted by user."; sleep 2; return 0
elif [[ $subshell_status -eq 101 ]]; then
echo "${RED}Error: Timed out waiting for custom DB file lock.${NC}"; sleep 2; return 1
elif [[ $subshell_status -eq 102 ]]; then
echo "${RED}Error: Could not filter DB file for overwrite.${NC}"; sleep 2; return 1
elif [[ $subshell_status -eq 103 ]]; then
echo "${RED}Error: Failed to write to DB file.${NC}"; sleep 2; return 1
elif [[ $subshell_status -ne 0 ]]; then
echo "${RED}Error writing to custom DB file (Code: $subshell_status).${NC}"; sleep 2; return 1
fi
chmod 600 "$CUSTOM_DB_FILE"
echo -e "${GREEN}[+] Tool '$display_name' added/updated successfully!${NC}"
echo "[*] Exiting script..."
sleep 2
stty sane
exit 0
}
install_custom_tool() {
while true; do
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
clear
echo "========================================="
echo "          Install a Custom Tool          "
echo "========================================="
echo
if ! load_custom_tools_db; then
echo "${RED}Returning to menu...${NC}"
sleep 1
return
fi
local num_tools=${#CUSTOM_TOOLS_INDEX_TO_KEY[@]}
if [[ $num_tools -eq 0 ]]; then
echo "No custom tools have been added yet."
echo "Returning to menu..."
sleep 1
return
fi
for i in $(seq 0 $((num_tools - 1))); do
local key="${CUSTOM_TOOLS_INDEX_TO_KEY[$i]}"
if [[ -v CUSTOM_TOOLS_DB["$key"] ]]; then
local data="${CUSTOM_TOOLS_DB["$key"]}"
local old_ifs="$IFS"; trap "IFS=\"$old_ifs\"" RETURN
IFS='|' read -r cat name short_desc long_desc _ <<< "$data"
IFS="$old_ifs"; trap - RETURN
printf "%3d. %-25s [%-15s]\n" $((i+1)) "${name:-Unknown}" "${cat:-N/A}"
else
printf "%3d. ${RED}%-25s${NC} [${RED}ERROR: Key not found${NC}]\n" $((i+1)) "Invalid Entry"
fi
done
trap "" RETURN
echo "    0. Back to Custom Tool Menu"
echo "-----------------------------------------"
read -p "Enter tool number to install (or 0 to go back): " tool_choice < /dev/tty
if [[ "$tool_choice" == "0" ]]; then
return
fi
local choice_index=$((tool_choice - 1))
if [[ "$tool_choice" =~ ^[0-9]+$ ]] && [ "$choice_index" -ge 0 ] && [ "$choice_index" -lt $num_tools ]; then
local selected_key="${CUSTOM_TOOLS_INDEX_TO_KEY[$choice_index]}"
if [[ ! -v CUSTOM_TOOLS_DB["$selected_key"] ]]; then
echo "${RED}Error: Selected tool key '$selected_key' is invalid or missing.${NC}"
sleep 2
continue
fi
local data="${CUSTOM_TOOLS_DB["$selected_key"]}"
local old_ifs="$IFS"; trap "IFS=\"$old_ifs\"" RETURN
IFS='|' read -r category name short_desc long_desc cmd <<< "$data"
IFS="$old_ifs"; trap - RETURN
if [[ -z "$name" ]] || [[ -z "$cmd" ]]; then
echo -e "${RED}[x] Failed to parse custom tool data for key: $selected_key${NC}"
echo "The custom DB file '$CUSTOM_DB_FILE' might be corrupted."
echo "${RED}Returning to menu...${NC}"
sleep 2
continue
fi
clear
echo "========================================="
echo "              Installing: $name"
echo "========================================="
echo "Category: $category"
echo "Purpose: $short_desc"
echo "Finds: $long_desc"
echo
ensure_prerequisites || { echo "${RED}Prerequisite setup failed. Cannot install tools.${NC}"; sleep 3; continue; }
local check_name
check_name=$(extract_binary_name "$cmd")
if [[ -z "$check_name" ]]; then
check_name="${selected_key#custom_}"
echo -e "${YELLOW}[~] Could not reliably determine binary name, using key '$check_name' for check.${NC}"
fi
local gopath_bin=""
if [[ -n "${GOPATH:-}" && -n "$check_name" ]]; then
gopath_bin="$GOPATH/bin/$check_name"
fi
local pipx_bin="$HOME/.local/bin/$check_name"
local tool_exists=false
if [[ -n "$check_name" ]]; then
if command -v "$check_name" &>/dev/null || \
[[ -n "$gopath_bin" && -x "$gopath_bin" ]] || \
[[ -x "$pipx_bin" ]]; then
tool_exists=true
fi
fi
local proceed_install=true
if $tool_exists; then
echo -e "${YELLOW}[!] Tool '$name' is already installed.${NC}"
while true; do
read -p "Do you want to force re-installation? [Press Enter for default 'NO'] (y/N): " -n 1 -r REPLY < /dev/tty
echo
case "$REPLY" in
[Yy])
echo -e "${CYAN}[*] Forcing re-installation of $name...${NC}"
proceed_install=true
break
;;
[Nn]|"")
printf "${YELLOW}[~] %-25s - SKIPPED BY USER${NC}\n" "$name"
proceed_install=false
sleep 1
break
;;
*)
echo -e "${RED}[x] Invalid input. Please enter 'y' or 'n'.${NC}" >&2
;;
esac
done
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
fi
if [[ "$proceed_install" == true ]]; then
export IS_MANUAL_INSTALL=true
echo -e "${CYAN}[*] Running interactive install for '$name'.${NC}"
echo -e "${YELLOW}[!] You may be prompted for a password or other input.${NC}"
echo "-----------------------------------------------------"
eval "$cmd" < /dev/tty &> /dev/tty
local install_status=$?
unset IS_MANUAL_INSTALL
echo "-----------------------------------------------------"
echo ""
if [[ $install_status -eq 0 ]]; then
echo -e "${GREEN}[+] Installation of '$name' completed successfully!${NC}"
else
echo -e "${RED}[x] Installation of '$name' failed with exit code: $install_status${NC}"
echo "Please check the output above for errors."
fi
echo "Press Enter to return to the menu..."
read -r < /dev/tty
fi
else
echo "Invalid choice. Please try again."
sleep 2
fi
done
}
manage_custom_tools() {
while true; do
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
clear
echo "========================================="
echo "      List / Remove Custom Tools       "
echo "========================================="
echo
if ! load_custom_tools_db; then
echo "${RED}Returning to menu...${NC}"
sleep 1
return
fi
local num_tools=${#CUSTOM_TOOLS_INDEX_TO_KEY[@]}
if [[ $num_tools -eq 0 ]]; then
echo "No custom tools have been added yet."
echo "Returning to menu..."
sleep 1
return
fi
for i in $(seq 0 $((num_tools - 1))); do
local key="${CUSTOM_TOOLS_INDEX_TO_KEY[$i]}"
if [[ -v CUSTOM_TOOLS_DB["$key"] ]]; then
local data="${CUSTOM_TOOLS_DB["$key"]}"
local old_ifs="$IFS"; trap "IFS=\"$old_ifs\"" RETURN
IFS='|' read -r _ name _ _ _ <<< "$data"
IFS="$old_ifs"; trap - RETURN
local display_key="${key#custom_}"
printf "%3d. %-25s (Key: %s)\n" $((i+1)) "${name:-Unknown}" "$display_key"
else
printf "%3d. ${RED}%-25s${NC} [${RED}ERROR: Key not found${NC}]\n" $((i+1)) "Invalid Entry"
fi
done
trap "" RETURN
echo "   0. Back to Custom Tool Menu"
echo "-----------------------------------------"
read -p "Enter tool number to REMOVE (or 0 to go back): " tool_choice < /dev/tty
if [[ "$tool_choice" == "0" ]]; then
return
fi
local choice_index=$((tool_choice - 1))
if [[ "$tool_choice" =~ ^[0-9]+$ ]] && [ "$choice_index" -ge 0 ] && [ "$choice_index" -lt $num_tools ]; then
local selected_key="${CUSTOM_TOOLS_INDEX_TO_KEY[$choice_index]}"
if [[ ! -v CUSTOM_TOOLS_DB["$selected_key"] ]]; then
echo "${RED}Error: Selected tool key '$selected_key' is invalid or missing.${NC}"
sleep 2
continue
fi
local data="${CUSTOM_TOOLS_DB["$selected_key"]}"
local category name short_desc long_desc cmd
local old_ifs="$IFS"
IFS='|' read -r category name short_desc long_desc cmd <<< "$data"   
IFS="$old_ifs"
local display_key="${selected_key#custom_}"
echo -e "${YELLOW}[!] Are you sure you want to remove '$name' (Key: $display_key)?${NC}"
local REPLY=""
local do_remove=false
while true; do
read -p "This only removes the definition, not the installed tool. [Press Enter for default 'NO'] (y/N): " -n 1 -r REPLY < /dev/tty
echo
case "$REPLY" in
[Yy])
do_remove=true
break
;;
[Nn]|"")
do_remove=false
break
;;
*)
echo -e "${RED}[x] Invalid input. Please enter 'y' or 'n'.${NC}" >&2
;;
esac
done
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
if [[ "$do_remove" == true ]]; then
local remove_status=1
local temp_db_lines=()
local lock_acquired=false
if exec 9>>"$CUSTOM_DB_FILE"; then
if flock -x -w 5 9; then
lock_acquired=true
else
echo "${RED}Error: Could not acquire write lock on custom DB file for removal.${NC}" >&2
remove_status=101
fi
else
echo "${RED}Error: Could not open lock file descriptor for custom DB file.${NC}" >&2
fi
if [[ "$lock_acquired" == true ]]; then
mapfile -t temp_db_lines < <(grep -F -v -- "$selected_key|" "$CUSTOM_DB_FILE" || true) 
local grep_status=$?
if [[ $grep_status -eq 0 ]] || [[ $grep_status -eq 1 ]]; then
local filtered_lines=()
for line in "${temp_db_lines[@]}"; do
[[ -n "$line" ]] && filtered_lines+=("$line")
done
temp_db_lines=("${filtered_lines[@]}")
local write_status=1 
if [[ ${#temp_db_lines[@]} -gt 0 ]]; then
printf "%s\n" "${temp_db_lines[@]}" > "$CUSTOM_DB_FILE"
write_status=$? 
else
: > "$CUSTOM_DB_FILE" 
write_status=$? 
fi
if [[ $write_status -eq 0 ]]; then
if [[ -f "$CUSTOM_DB_FILE" ]]; then
remove_status=0
else
echo "${RED}Error: Custom DB file disappeared after writing.${NC}" >&2
fi
else
echo "${RED}Error: Failed to write filtered content back to custom DB file (Code: $write_status).${NC}" >&2
fi
else
echo "${RED}Error: grep failed while filtering custom DB file (Code: $grep_status).${NC}" >&2
fi
flock -u 9 
fi
exec 9>&- 2>/dev/null || true
if [[ $remove_status -eq 0 ]]; then
chmod 600 "$CUSTOM_DB_FILE"
echo -e "${GREEN}[+] Tool '$name' definition removed from custom list.${NC}"
sleep 2
stty sane
exit 0
elif [[ $remove_status -eq 101 ]]; then
: 
sleep 2
else
echo "${RED}Error removing tool definition from custom DB file.${NC}"
sleep 2
fi
else
echo "[*] Aborted."
sleep 2
fi
else
echo "Invalid choice. Please try again."
sleep 2
fi
done
}
custom_tool_menu() {
while true; do
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
clear
echo "========================================="
echo "         Custom Tool Management          "
echo "========================================="
echo "1. Install a Custom Tool"
echo "2. Add a New Custom Tool Definition"
echo "3. List / Remove Custom Tool Definitions"
echo "0. Back to Main Menu"
echo "-----------------------------------------"
stty sane
IFS= read -r -p "Enter your choice [0-3]: " choice < /dev/tty
case $choice in
1) install_custom_tool ;;
2) add_custom_tool ;;
3) manage_custom_tools ;;
0) return ;;
*) echo "Invalid option. Please try again."; sleep 2 ;;
esac
done
}
while true; do
while IFS= read -r -t 0.1 _ < /dev/tty; do :; done
unset SPINNER_PID START_TIME IS_MANUAL_INSTALL FORCE_UPDATE
CLEANUP_RUNNING=false
clear
show_menu
stty sane
IFS= read -r -p "Enter your choice [1-7]: " choice < /dev/tty
case $choice in
1) install_tools ;;
2) manual_install_menu ;;
3) uninstall_tools ;;
4) show_cleanup_menu ;;
5) custom_tool_menu ;;
6) show_help ;;
7) menu_cleanup ;;
*) echo "Invalid option. Please try again."; sleep 2 ;;
esac
done
exit 0

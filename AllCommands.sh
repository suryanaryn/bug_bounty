#!/bin/bash

# Content Discovery
  ./JSFScan.sh -l -e -s -m -d -f url/js -o url/JSFScan_result
  ./bypass_403.sh website-here

  /root/go/bin/./ffuf -u $1/FUZZ -w /root/tools/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -r
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/wordlist/apiwordlist.txt -r -t 200
  cat /root/targets/$1/*.ffuf | sort -u | tee -a /root/newtargets/$1/content_discovered.txt
  ffuf -u $1/FUZZ -mc 200,301,302,403,401 -t 150 -w ~/tools/dirsearch/db/ffuf_extension.txt

# Port Scan 

# attacks 
  cat urls/params | qsreplace |  kxss > attack/xss  
  jaeles config update --repo https://github.com/ghsec/ghsec-jaeles-signatures 
  cat $DOMAIN/subdomain/200sub.txt | jaeles scan -c 100 -L2 -o $DOMAIN/jaeles
  jaeles server


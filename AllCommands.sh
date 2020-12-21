#!/bin/bash

# Domain Analysis and spoofcheck
  python2 domain_analyzer.py -d fireeye.com -o -e
  ./spoofcheck.py fireeye.com
# Collect Live subdomains
  for DOMAIN in $(cat domain);do 
    mkdir $DOMAIN
    amass enum -passive -norecursive -noalts -config ../amass/config.ini -d $DOMAIN -o tmp.txt
    subfinder -d $DOMAIN -silent >> tmp.txt
    assetfinder --subs-only $DOMAIN  >> tmp.txt
    findomain -t $DOMAIN -c ../amass/bin/config.json --quiet >> tmp.txt
    echo "amass data $(cat tmp.txt|sort -u | wc -l)"  
    python /opt/bug_hunter/tools/github-subdomains.py -t 6c5ed8ab7b7c4b9232fcaea5c051b8977a624012 -d $DOMAIN >> tmp.txt
    /opt/bug_hunter/tools/./certfinder.sh $DOMAIN tmp.txt 
    echo "cert data $(cat tmp.txt | sort -u |wc -l)"
    shuffledns -d $DOMAIN -w ../../wordlist/top_subdomains.txt -r ../../wordlist/resolvers.txt -list tmp.txt -silent | sort -u |grep ".$DOMAIN"  >> $DOMAIN/subdomains.txt 
    echo "shuffledns data $(cat $DOMAIN/subdomains.txt | wc -l)"
    mkdir $DOMAIN/attack
    /opt/tool/CORStest/./corstest.py -p 75 $DOMAIN/subdomains.txt > tmp
    cat tmp | grep -v "Error:" | grep -v "Not vulnerable:" >> $DOMAIN/attack/cors
    subzy -targets $DOMAIN/subdomains.txt --hide_fails --concurrency 75 >> $DOMAIN/attack/STKO
    tko-subs -domains=$DOMAIN/subdomains.txt -data=../../config/providers-data.csv  -threads 50 -output=op.csv &> /dev/null
    cat op.csv | grep -v elb.amazon | grep true |tee -a $DOMAIN/attack/STKO

  # Collect Live subdomains
    mkdir $DOMAIN/subdomain  $DOMAIN/ip
    cat $DOMAIN/subdomains.txt | httpx -silent -threads 200 -status-code -ip -follow-redirects > all.txt
    # cat subdomains.txt | httpx -threads 200 -status-code -ip  >> all.txt
    cat all.txt | awk '{print $3}' | sort -u |  sed 's/\[//g' | sed 's/\]//g'> $DOMAIN/ip/ip_list.txt
    cat all.txt | sort -u | grep 2m20[0-9] | awk '{print $1}' > $DOMAIN/subdomain/200sub.txt 
    cat all.txt | sort -u | grep 1m40[1-3] | awk '{print $1}' > $DOMAIN/subdomain/401sub.txt 
    cat all.txt | sort -u | grep 3m5.. | awk '{print $1}' > $DOMAIN/subdomain/5xxsub.txt
    cat all.txt | sort -u | awk '{print $1}' > $DOMAIN/subdomain/allsubdmain
    # cat all.txt | sort -u | grep 3m3.. | awk '{print $1}' > $DOMAIN/subdomain/3xxsub.txt
    cat all.txt | sort -u | grep -v [1-3]m...| awk '{print $1}'  > $DOMAIN/subdomain/apisub.txt
    cat all.txt | awk '{print $1}' | sort -u | grep api >> $DOMAIN/subdomain/apisub.txt
    # show output of all files in wc -l

  # Spider & wayback subdomains
    mkdir $DOMAIN/urls
    echo "$DOMAIN" | waybackurls >> wayback.txt
    echo "$DOMAIN" | gau >> wayback.txt
    python3 /opt/bug_hunter/tools/github-endpoints.py -t 6c5ed8ab7b7c4b9232fcaea5c051b8977a624012 -d $DOMAIN  >> wayback.txt
    
    cat wayback.txt | sort -u > $DOMAIN/waybackurls.txt 
    cat all.txt | sort -u | awk '{print $1}' > tmp
    gospider -S tmp -c 10 -d 1 -t 20 --other-source --sitemap > gospider.txt
    cat gospider.txt |grep linkfinder\] | awk '{print $3}' | sort -u  >> $DOMAIN/waybackurls.txt
    cat gospider.txt |grep robots\] | awk '{print $3}' | sort -u >> $DOMAIN/waybackurls.txt
    cat gospider.txt |grep  sitemap\] | awk '{print $3}' | sort -u >> $DOMAIN/waybackurls.txt

    cat gospider.txt | grep "url\]" | grep "\[code-2"  | awk '{print $5}'  | grep -v "\.js"|  grep -v "\.html" | grep -v "\.php" | grep -v "\.asp" | sort -u >  $DOMAIN/urls/2xx.txt
    cat gospider.txt | grep "url\]" | grep "\[code-4" | grep -v "code-404" | awk '{print $5}' | sort -u >  $DOMAIN/urls/4xx.txt
    cat gospider.txt | grep "url\]" | grep "\[code-5" | awk '{print $5}' | sort -u >  $DOMAIN/urls/5xx.txt
    cat gospider.txt | grep "form\]" | sort -u >  $DOMAIN/urls/form	
    cat gospider.txt | grep "aws-s3\]" | sort -u | tee  $DOMAIN/urls/aws_s3
    cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'| grep "\.html" >>  $DOMAIN/urls/html.txt
    cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'| grep "\.php" >>  $DOMAIN/urls/php.txt
    cat gospider.txt | grep "url\]"| grep "\[code-2"  | awk '{print $5}'  | grep -v "\.js" >>  $DOMAIN/urls/js.txt
    cat gospider.txt | grep "javascript\]" | awk '{print $3}'|sort -u >>  $DOMAIN/urls/js.txt
    cat gospider.txt | grep -v "form\]" | grep -v "javascript\]" | grep -v "linkfinder\]" | grep -v "robots\]" | grep -v "sitemap\]" | grep -v subdomains | grep -v url | grep -v "aws\-s3" |sort -u | tee  $DOMAIN/urls/checkurl

    cat $DOMAIN/waybackurls.txt | grep "\.html" | sort -u >>  $DOMAIN/urls/html.txt
    cat $DOMAIN/waybackurls.txt | grep -v "\.json" | grep "\.js" >>  $DOMAIN/urls/js.txt
    cat $DOMAIN/waybackurls.txt | grep "\.php" >>  $DOMAIN/urls/php.txt
    cat $DOMAIN/waybackurls.txt  | egrep -v ".(zip|jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|xml|json|yaml|pdf|svg|txt|asp|net|js|php|html)" | sort -u > tmp
    cat tmp | httpx -threads 200 -status-code -silent -follow-redirects > allurls
    cat tmp | httpx -threads 200 -status-code -silent  >> allurls
    cat allurls | sort -u > allurls.txt
    rm allurls tmp
    cat allurls.txt | grep 2m20[0-9] | awk '{print $1}' >> $DOMAIN/urls/2xx.txt 
    cat allurls.txt | grep 1m40[1-3] | awk '{print $1}' >> $DOMAIN/urls/4xx.txt 
    cat allurls.txt | grep 3m5.. | awk '{print $1}' >> $DOMAIN/urls/5xx.txt
    cat allurls.txt | grep 3m3.. | awk '{print $1}' > $DOMAIN/urls/3xx
    cat allurls.txt | awk '{print $1}' > $DOMAIN/urls/allurls
  
  # sorting and deleting old files
    cat $DOMAIN/urls/2xx.txt | sort -u > $DOMAIN/urls/2xx 
    cat $DOMAIN/urls/4xx.txt | sort -u > $DOMAIN/urls/4xx 
    cat $DOMAIN/urls/5xx.txt | sort -u > $DOMAIN/urls/5xx 
    cat $DOMAIN/urls/html.txt | sort -u > $DOMAIN/urls/html 
    cat $DOMAIN/urls/php.txt | sort -u  > $DOMAIN/urls/php 
    cat $DOMAIN/waybackurls.txt| sort -u > $DOMAIN/waybackurls
    rm $DOMAIN/urls/php.txt $DOMAIN/urls/html.txt $DOMAIN/waybackurls.txt $DOMAIN/urls/4xx.txt $DOMAIN/urls/2xx.txt  $DOMAIN/urls/5xx.txt  $DOMAIN/urls/javascript;done
    cat $DOMAIN/urls/js |sort -u| subjs -c 140 >  $DOMAIN/urls/javascript
    cat $DOMAIN/urls/javascript | sort -u >  $DOMAIN/urls/js 
    cat $DOMAIN/urls/2xx  | egrep  "\?|\=" | qsreplace   >  $DOMAIN/urls/params
  #cleaning the output folder
    rm  tmp.txt all.txt allurls.txt wayback.txt gospider.txt op.csv tmp 

# Scan nuclei
  mkdir $DOMAIN/nuclei_op
	nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/cves/*.yaml -c 60 -o $DOMAIN/nuclei_op/cves
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/default-credentials/*.yaml -c 60 -o $DOMAIN/nuclei_op/default-credentials
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/dns/*.yaml -c 60 -o $DOMAIN/nuclei_op/dns
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/files/*.yaml -c 60 -o $DOMAIN/nuclei_op/files
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/basic-detections/*.yaml -c 60 -o $DOMAIN/nuclei_op/basic
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/fuzzing/*.yaml -c 60 -o $DOMAIN/nuclei_op/fuzzing
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/generic-detections/*.yaml -c 60 -o $DOMAIN/nuclei_op/generic-detections
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/misc/*.yaml -c 60 -o $DOMAIN/nuclei_op/misc
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/panels/*.yaml -c 60 -o $DOMAIN/nuclei_op/panels
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/security-misconfiguration/*.yaml -c 60 -o $DOMAIN/nuclei_op/security-misconfiguration
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/subdomain-takeover/*.yaml -c 60 -o $DOMAIN/nuclei_op/subdomain-takeover
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/technologies/*.yaml -c 60 -o $DOMAIN/nuclei_op/technologies
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/tokens/*.yaml -c 60 -o $DOMAIN/nuclei_op/tokens
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/vulnerabilities/*.yaml -c 60 -o $DOMAIN/nuclei_op/vulnerabilities
  nuclei -l $DOMAIN/subdomain/allsubdmain -t /root/nuclei-templates/workflows/*.yaml -c 60 -o $DOMAIN/nuclei_op/workflows 

# gf vulnerable_files 
  mkdir $DOMAIN/vulnerable_files
	cat  $DOMAIN/urls/allurls  | grep = | gf ssrf > $DOMAIN/vulnerable_files/ ssrf
	cat  $DOMAIN/urls/allurls  | grep = | gf sqli > $DOMAIN/vulnerable_files/ sqli
	cat  $DOMAIN/urls/allurls  | grep = | gf ssti > $DOMAIN/vulnerable_files/ ssti
	cat  $DOMAIN/urls/allurls  | grep = | gf xss > $DOMAIN/vulnerable_files/ xss
	cat  $DOMAIN/urls/allurls  | grep = | gf lfi > $DOMAIN/vulnerable_files/ lfi
	cat  $DOMAIN/urls/allurls  | grep = | gf idor > $DOMAIN/vulnerable_files/ idor
	cat  $DOMAIN/urls/allurls  | grep = | gf redirect > $DOMAIN/vulnerable_files/ redirect
	cat  $DOMAIN/urls/allurls  | grep = | gf rce > $DOMAIN/vulnerable_files/ rce
	cat  $DOMAIN/urls/allurls  | grep = | gf debug_logic > $DOMAIN/vulnerable_files/ debug_logic
	cat  $DOMAIN/urls/allurls  | grep = | gf interestingEXT > $DOMAIN/vulnerable_files/ interestingEXT
	cat  $DOMAIN/urls/allurls  | grep = | gf interestingparams > $DOMAIN/vulnerable_files/ interestingparams
	cat  $DOMAIN/urls/allurls  | grep = | gf interestingsubs > $DOMAIN/vulnerable_files/ interestingsubs
	cat  $DOMAIN/urls/allurls  | grep = | gf jsvar > $DOMAIN/vulnerable_files/ jsvar ;done

#+++===+++==============++++++++====PENDING================+++++++++++++++++++++++++++++++++++===================#

# attacks 
  cat urls/params | qsreplace |  kxss > attack/xss  
  jaeles config update --repo https://github.com/ghsec/ghsec-jaeles-signatures 
  cat list_target.txt | jaeles scan -c 100  -p 'dest=xxx.burpcollaborator.net' -L2
  jaeles server



# Content Discovery
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/tools/SecLists/Discovery/Web-Content/common-api-endpoints-mazen160.txt -r
  /root/go/bin/./ffuf -u $1/FUZZ -w /root/wordlist/apiwordlist.txt -r -t 200
  cat /root/targets/$1/*.ffuf | sort -u | tee -a /root/newtargets/$1/content_discovered.txt
  ffuf -u $1/FUZZ -mc 200,301,302,403,401 -t 150 -w ~/tools/dirsearch/db/ffuf_extension.txt

  python3 dirsearch.py -e . -u $1
  /root/tools/dirsearch/./dirsearch.py -u $1/fuzz -e php,asp,aspx,jsp,html,zip,jar  -w /root/tools/dirsearch/dicc.txt -t 50 | tee -a /root/targets/$1/dirsearchresults.txt
  /root/tools/dirsearch/./dirsearch.py -e php,jsp,html,zip -L /root/targets/$1/interesting.txt -w /root/wordlist/dicc.txt — recursive -R 2 --plain-text-report=/root/newtargets/$1/dirsearchresults_inputfile1.txt
  /root/tools/dirsearch/./dirsearch.py -e php,jsp,html,zip -L /root/targets/$1/interesting.txt -w /root/wordlist/apiwordlist.txt — recursive -R 2 --plain-text-report=/root/targets/$1/dirsearchresults_inputfile.txt

# Port Scan 



#  egrep -v ".(jpg|jpeg|gif|css|tif|tiff|png|ttf|woff|woff2|ico|xml|json|yaml|pdf|svg|txt|php|js)" 
# for cname 
  # cat all.txt | awk '{print $4}' | sort -u |  sed 's/\[//g' | sed 's/\]//g'| httpx -threads 200 -status-code |  grep 1m40[0-4]| grep -v 1m401 | grep -v 1m403 | awk '{print $1}' | sed 's#http.://##g' > subdomain/sub_take_cname.txt
  # for i in $(cat subdomain/sub_take_cname.txt);do cat all.txt | grep  $i ;done > tmp.txt
  # cat tmp.txt | awk '{print $1}'| sort -u > subtakeover.txt

# amass old   
  # amass enum -active -dir /opt/bug_hunter/tools/amass -config /opt/bug_hunter/tools/amass/config.ini -d $DOMAIN >> tmp.txt
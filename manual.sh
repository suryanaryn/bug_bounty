Acquisitions	crunchbase
python2 asn_aquisitions.py -t  + word +  > asn_aquisitions.txt
https://domaineye.com/
./testssl.sh -g -U --ssl-native  https://www.fireeye.com
https://www.ssllabs.com/ssltest/index.html 

python3 reconT.py http://www.fireeye.com

amass intel -org <company name here>
amass intel -asn <ASN Number Here>
amass intel -cidr <CIDR Range Here>
amass intel -whois -d <Domain Name Here>

amass intel -org <org> => asn
echo “org”|Metabigor net --org -o test => ip range 
echo "ASN" | metabigor net --asn => ip range
for i in $(cat test); do prips $i| hakrevdns ;done

amass intel -active -asn <asn> => root domains
Whois <domain> => email and other info
./Knockknock -n <email>, <domain> | grep ‘^<org>\.’ => root domains
echo "162.159.46.125" | ./metabigor ip -s 'shodan' -v => info about ip

site:<Third Party Vendor> <Company Name>
site:pastebin.com “Company Name”
site:*.atlassian.net “Company Name”
site:bitbucket.org “Company Name”
Inurl:gitlab “Company Name”

https://pentest-tools.com/information-gathering/google-hacking#

s3bucket dorks - site:.s3.amazonaws.com "Starbucks"
site:digitaloceanspaces.com <Domain Here>
port "9200" elastic [;shodan query]
product:docker [;shodan query]

hsecscan -i -u https://google.com


python3 degoogle.py "fireeye.com"
gitdorks.sh domain
goohak.sh domain
# search single repo
python github-dork.py -r techgaun/github-dorks                          
python github-dork.py -u techgaun                                    
gitleaks --repo-url=https://github.com/my-insecure/repo -v --report=my-report.json
gittyleaks -link https://github.com/kootenpv/gittyleaks  --find-anything 
trufflehog URL

./ssh-audit.py fireeye.com
python3 wig.py -q -m -t 50 -w wig.json -l subdomain.txt

# Burp Regex for Scope Control
  .*\.domain\.com$
  https://github.com/root4loot/rescope.git 

# import files in Burp

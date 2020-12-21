## Under Development => setting up a workflow


## things to do 
1. merge allcommands with changes/bug_hunter.sh  
2. merge install with changes/install.sh 
3. improvements

#### Install required tools

`chmod +x install.sh`

`./install.sh`

1. In the main directory you should have `/root` directory and `/usr/local/bin`
2. In the `/root` directory you must have `/go/bin` directory
3. In the tool's directory you will find `tools` directory after install tools_script

#### Running tool

`./bug_hunter.sh -t target.com`

<!-- ## Notes

[+] If you face any problem in the running process, check that:

    1. You logged in as ROOT user not normal user
    2. Check that you installed the GO language and this path is exist /root/go/bin -->

## Tools useds

1. domain profiler https://github.com/jpf/domain-profiler
2. VHostScan https://github.com/codingo/VHostScan
3. Subfinder https://github.com/projectdiscovery/subfinder
4. Assetfinder https://github.com/tomnomnom/assetfinder
5. Altdns https://github.com/infosec-au/altdns
6. Dirsearch https://github.com/maurosoria/dirsearch
7. Httpx https://github.com/projectdiscovery/httpx
8. Waybackurls https://github.com/tomnomnom/waybackurls
9. Gau https://github.com/lc/gau
10. Git-hound https://github.com/tillson/git-hound
11. Gf https://github.com/tomnomnom/gf
12. Gf-pattern https://github.com/1ndianl33t/Gf-Patterns
13. Nuclei https://github.com/projectdiscovery/nuclei
14. Nuclei-templets https://github.com/projectdiscovery/nuclei-templates
15. Chomp Scan https://github.com/SolomonSklash/chomp-scan.git

## workflow

1. Collect all Acquisitions and ASN
2. Collect Live subdomains
3. Collect Live sub-subdomains
4. Spider & wayback subdomains
5. Extract JS files
6. Content Discovery
7. Port Scan
8. GitHub Secrets
9. GitHub dork links
10. Extract possible vulnerable links
11. Scan for Subdomain vulnerabilities Takeover & S3buckets
12. Scan Links for CVE's
13. Scan Security Headers
14. Scan Misconfiguration
15. Scan Vulnerabilities
16. Scan for website technologies and services\n

## Initial Setup

1. add credentials for CloudUnflare
2. add burpcollaborator for jaeles






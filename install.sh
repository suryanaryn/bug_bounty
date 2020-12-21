#!/bin/bash

RED=$(tput setaf 1)
GREEN=$(tput setaf 2)
BLUE=$(tput setaf 4)
RESET=$(tput sgr0)

echo "${BLUE} installing Manual tools ${RESET}"
git clone https://github.com/greycatz/CloudUnflare.git /opt/manual/CloudUnflare
git clone https://github.com/dock3rX/ReconT.git /opt/manual/ReconT
cd /opt/manual/ReconT
pip3 install -r requirements.txt
git clone https://github.com/deepseagirl/degoogle.git /opt/manual/degoogle
git clone https://github.com/techgaun/github-dorks.git /opt/manual/github-dorks
cd /opt/manual/github-dorks
pip install -r requirements.txt
git clone --depth 1 https://github.com/drwetter/testssl.sh.git /opt/manual/testssl.sh
git clone https://github.com/jekyc/wig.git /opt/manual/wig
cd /opt/manual/wig
sudo python3 setup.py install
echo "${BLUE} done${RESET}" 

#install domain_analyzers
echo "${BLUE} domain_analyzer ${RESET}"
git clone https://github.com/eldraco/domain_analyzer.git /opt/tools/domain_analyzer
git clone https://github.com/BishopFox/spoofcheck.git /opt/tools/spoofcheck
cd /opt/tools/spoofcheck
pip install -r requirements.txt
echo "${BLUE} done ${RESET}"

git clone https://github.com/EnableSecurity/wafw00f.git /opt/tools/wafw00f
cd /opt/tools/wafw00f
python setup.py install
python3 main.py -i subdomain.txt


#install buckets-finder
echo "${BLUE} buckets-finder${RESET}"
git clone https://github.com/nahamsec/lazys3.git /opt/tools/lazys3
git clone https://github.com/sa7mon/S3Scanner.git /opt/tools/S3Scanner 
cd /opt/tools/S3Scanner
sudo pip3 install -r requirements.txt 
echo "${BLUE} done${RESET}" 

echo "${BLUE} git-scanner${RESET}"
git clone https://github.com/hisxo/gitGraber.git /opt/tools/gitGraber
cd /opt/tools/gitGraber && chmod +x gitGraber.py
sudo pip3 install -r requirements.txt
git clone https://github.com/tillson/git-hound.git /opt/tools/git-hound
cd /opt/tools/git-hound
sudo go build main.go && mv main githound
echo "${BLUE} Create a ./config.yml or ~/.githound/config.yml${RESET}"

echo "${BLUE} installing crawlers ${RESET}"
    git clone https://github.com/GerbenJavado/LinkFinder.git /opt/tools/LinkFinder
    cd /opt/tools/LinkFinder
    sudo pip3 install -r requirements.txt
    sudo python3 setup.py install
    sar 1 1 >/dev/null

#install DumpsterDiver
    echo "${BLUE} DumpsterDiver${RESET}"
    git clone https://github.com/securing/DumpsterDiver.git /opt/tools/DumpsterDiver
    cd /opt/tools/DumpsterDiver && chmod +x DumpsterDiver.py
    sudo pip3 install -r requirements.txt
    git clone https://github.com/m4ll0k/SecretFinder.git /opt/tools/SecretFinder
    cd /opt/tools/SecretFinder && chmod +x secretfinder
    sudo pip3 install -r requirements.txt
    echo "${BLUE} done${RESET}"

    git clone https://github.com/1ndianl33t/Gf-Patterns.git  /opt/tools/Gf-Patterns/
    cp /opt/tools/Gf-Patterns/*.json ~/.gf
    rm -rf /opt/tools/Gf-Patterns
    git clone https://github.com/s0md3v/Arjun.git /opt/tools/Arjun

#install massdns and masscan
    echo "${BLUE} Installing massdns ${RESET}"
    git clone https://github.com/blechschmidt/massdns.git /opt/tools/massdns
    cd /opt/tools/massdns
    make
    cp bin/massdns /usr/bin/
    rm -rf /opt/tools/massdns && cd
    git clone https://github.com/robertdavidgraham/masscan.git /opt/tools/masscan
    cd /opt/tools/masscan
    make
    cp bin/masscan /usr/bin/
    rm -rf /opt/tools/masscan && cd 
    echo "${BLUE} done ${RESET}"
    sar 1 1 >/dev/null


echo "${GREEN} #### Installing CORS Tools #### ${RESET}"
git clone https://github.com/s0md3v/Corsy.git /opt/tools/corsy
sudo pip3 install -r requirements.txt
git clone https://github.com/RUB-NDS/CORStest.git /opt/tools/CORStest
sar 1 1 >/dev/null

echo "${GREEN} #### Installing XSS Tools#### ${RESET}"
git clone https://github.com/hahwul/dalfox /opt/tools/dalfox
cd /opt/tools/dalfox/ && go build dalfox.go
sudo cp dalfox /usr/bin/
git clone https://github.com/s0md3v/XSStrike.git /opt/tools/XSStrike 
cd /opt/tools/XSStrike
sudo pip3 install -r requirements.txt
git clone https://github.com/M4cs/traxss.git /opt/tools/traxss
cd /opt/tools/traxss
sudo pip3 install -r requirements.txt
sar 1 1 >/dev/null

echo "${BLUE} installing SSRFMap ${RESET}"
git clone https://github.com/swisskyrepo/SSRFmap /opt/tools/SSRFMap
cd /opt/tools/SSRFMap/
sudo pip3 install -r requirements.txt
echo "${BLUE} installing XSRFProbe${RESET}"
sudo pip3 install xsrfprobe
echo "${BLUE} done${RESET}"





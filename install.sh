#!/bin/bash

# Colors
BLINK='\e[5m'
BOLD='\e[1m'
LIGHT_GREEN='\e[92m'
LIGHT_YELLOW='\e[93m'
LIGHT_CYAN='\e[96m'
NORMAL='\e[0m'
RED='\e[31m'
UNDERLINE='\e[4m'

UBUNTU=;
DEBIAN=;
KALI=;
TOOLS="/opt/tools";

function testcmd () {
    command -v "$1" >/dev/null
}

function install_kali() {
	echo -e "$LIGHT_GREEN[+] Installing for Kali.$NORMAL";
	install_library;
	install_envlib;
	install_tools;
}

function install_ubuntu() {
	echo -e "$LIGHT_GREEN[+] Installing for Ubuntu.$NORMAL";
	install_library;
	install_envlib;
	install_tools;
}

function install_library(){
	sudo apt update 
	sudo apt -y upgrade 
	sudo apt dist-upgrade -y
	sudo apt install -y  libxml2 libxml2-dev libxslt1-dev libgmp-dev zlib1g-dev libgdbm-dev libncurses5-dev automake libtool bison 
	sudo apt install -y libffi-dev python-dev libcurl4-openssl-dev apt-transport-https libssl-dev jq  whois python-setuptools libldns-dev libpcap-dev
	sudo apt install -y npm gem perl parallel psmisc host dnsutils  snapd git gcc make python3-pip libgeoip-dev 
	sudo apt install -y git wget curl nmap masscan whatweb gobuster nikto wafw00f openssl libnet-ssleay-perl p7zip-full build-essential unzip 
}

function install_envlib() {	
	if ! testcmd code; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing vs-code ...${NORMAL}"
		sudo wget https://go.microsoft.com/fwlink/?LinkID=760868 -O code.deb
		sudo dpkg -i code.deb
		sudo rm code.deb
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing vs-code ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd pip2; then 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pip2 ...${NORMAL}"
		sudo wget https://bootstrap.pypa.io/get-pip.py
		sudo python2 get-pip.py
		sudo rm get-pip.py
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pip2 ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd pip3; then 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pip3 ...${NORMAL}"
		sudo apt-get purge python3-pip
		sudo apt-get install python3-pip -y
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing pip3 ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd go ;then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing go ...${NORMAL}"
		sudo wget -nv https://golang.org/dl/go1.15.6.linux-amd64.tar.gz
		sudo tar -C /usr/local -xzf go1.15.6.linux-amd64.tar.gz;
		sudo rm -rf go1.15.6.linux-amd64.tar.gz;
		echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
		echo 'export GOPATH=/root/go'   >> ~/.bashrc
		echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc
		source ~/.bashrc
	 else 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing go ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd docker ;then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing docker ...${NORMAL}"
		curl -fsSL https://download.docker.com/linux/debian/gpg | sudo apt-key add -
		echo 'deb [arch=amd64] https://download.docker.com/linux/debian buster stable' | sudo tee /etc/apt/sources.list.d/docker.list
		sudo apt-get update
		sudo apt-get install docker-ce -y
	 else 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing docker ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd ruby ; then 
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ruby ...${NORMAL}"
		gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
		curl -sSL https://get.rvm.io | bash -s stable
		source /etc/profile.d/rvm.sh
		type rvm | head -n 1
		rvm install "ruby-2.7.1"
		rvm use "ruby-2.7.1" --default
		ruby -v
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ruby ...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"

	fi
	echo -e "${BOLD}${LIGHT_GREEN}[+] Installing requirements for Python 2 and Python 3.${NORMAL}"
	sudo pip2 install -r requirements2.txt;
	sudo pip3 install -r requirements3.txt; 
	install_go_tools;
} 

function install_tools	() {
	mkdir "$TOOLS"/manual
	if [[ -d "$TOOLS"/manual/CloudUnflare ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudUnflare.""$NORMAL";
			cd "$TOOLS"/manual/CloudUnflare;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudUnflare from Github.""$NORMAL";
		git clone https://github.com/greycatz/CloudUnflare.git "$TOOLS"/manual/CloudUnflare;
	fi
	if [[ -d "$TOOLS"/manual/ReconT ]]; then
			echo -e "$LIGHT_GREEN[+] Updating ReconT.""$NORMAL";
			cd "$TOOLS"/manual/ReconT;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing ReconT from Github.""$NORMAL";
		git clone https://github.com/dock3rX/ReconT.git "$TOOLS"/manual/ReconT;
		cd "$TOOLS"/manual/ReconT;
		pip3 install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/manual/CloudFail ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudFail.""$NORMAL";
			cd "$TOOLS"/manual/CloudFail;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudFail from Github.""$NORMAL";
		git clone https://github.com/m0rtem/CloudFail.git "$TOOLS"/manual/CloudFail;
		cd "$TOOLS"/manual/CloudFail
		pip3 install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/manual/github-dorks ]]; then
			echo -e "$LIGHT_GREEN[+] Updating github-dorks.""$NORMAL";
			cd "$TOOLS"/manual/github-dorks;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing github-dorks from Github.""$NORMAL";
		git clone https://github.com/techgaun/github-dorks.git "$TOOLS"/manual/github-dorks;
		cd "$TOOLS"/manual/github-dorks;
		pip install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/manual/testssl.sh ]]; then
			echo -e "$LIGHT_GREEN[+] Updating testssl.sh.""$NORMAL";
			cd "$TOOLS"/manual/testssl.sh;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing testssl.sh from Github.""$NORMAL";
		git clone https://github.com/drwetter/testssl.sh.git "$TOOLS"/manual/testssl.sh;
	fi
	if [[ -d "$TOOLS"/manual/wig ]]; then
			echo -e "$LIGHT_GREEN[+] Updating wig.""$NORMAL";
			cd "$TOOLS"/manual/wig;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing wig from Github.""$NORMAL";
		git clone https://github.com/jekyc/wig.git "$TOOLS"/manual/wig;
		cd "$TOOLS"/manual/wig;
		sudo python3 setup.py install
	fi
	if [[ -d "$TOOLS"/manual/git-hound ]]; then
			echo -e "$LIGHT_GREEN[+] Updating git-hound.""$NORMAL";
			cd "$TOOLS"/manual/git-hound;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing git-hound from Github.""$NORMAL";
		git clone https://github.com/tillson/git-hound.git "$TOOLS"/manual/git-hound 
		cd "$TOOLS"/manual/git-hound;
		sudo go build main.go && mv main githound
	fi
	if [[ -d "$TOOLS"/domain_analyzer ]]; then
			echo -e "$LIGHT_GREEN[+] Updating domain_analyzer.""$NORMAL";
			cd "$TOOLS"/domain_analyzer;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing domain_analyzer from Github.""$NORMAL";
		git clone https://github.com/eldraco/domain_analyzer.git "$TOOLS"/domain_analyzer;
	fi
	if [[ -d "$TOOLS"/spoofcheck ]]; then
			echo -e "$LIGHT_GREEN[+] Updating spoofcheck.""$NORMAL";
			cd "$TOOLS"/spoofcheck;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing spoofcheck from Github.""$NORMAL";
		git clone https://github.com/BishopFox/spoofcheck.git "$TOOLS"/spoofcheck;
		cd "$TOOLS"/spoofcheck;
		pip install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/lazys3 ]]; then
			echo -e "$LIGHT_GREEN[+] Updating lazys3.""$NORMAL";
			cd "$TOOLS"/lazys3;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing lazys3 from Github.""$NORMAL";
		git clone https://github.com/nahamsec/lazys3.git "$TOOLS"/lazys3;
	fi
	if [[ -d "$TOOLS"/S3Scanner ]]; then
			echo -e "$LIGHT_GREEN[+] Updating S3Scanner.""$NORMAL";
			cd "$TOOLS"/S3Scanner;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing S3Scanner from Github.""$NORMAL";
		git clone https://github.com/sa7mon/S3Scanner.git "$TOOLS"/S3Scanner;
		cd "$TOOLS"/S3Scanner;
		sudo pip3 install -r requirements.txt 
	fi
	if [[ -d "$TOOLS"/DumpsterDiver ]]; then
			echo -e "$LIGHT_GREEN[+] Updating DumpsterDiver.""$NORMAL";
			cd "$TOOLS"/DumpsterDiver;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing DumpsterDiver from Github.""$NORMAL";
		git clone https://github.com/securing/DumpsterDiver.git "$TOOLS"/DumpsterDiver;
		cd "$TOOLS"/DumpsterDiver;
		chmod +x DumpsterDiver.py
		sudo pip3 install -r requirements.txt
	fi
	if [[ -d "$TOOLS"/JSFScan.sh ]]; then
			echo -e "$LIGHT_GREEN[+] Updating JSFScan.sh.""$NORMAL";
			cd "$TOOLS"/JSFScan.sh;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing JSFScan.sh from Github.""$NORMAL";
 		git clone https://github.com/KathanP19/JSFScan.sh.git "$TOOLS"/JSFScan.sh;
		cd "$TOOLS"/JSFScan.sh;
		chmod +x JSFScan.sh install.sh
	  	./install.sh
	fi
	if [[ -d "$TOOLS"/Corsy ]]; then
			echo -e "$LIGHT_GREEN[+] Updating Corsy.""$NORMAL";
			cd "$TOOLS"/Corsy;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing Corsy from Github.""$NORMAL";
		git clone https://github.com/s0md3v/Corsy.git "$TOOLS"/Corsy;
	fi
	if [[ -d "$TOOLS"/CORStest ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CORStest.""$NORMAL";
			cd "$TOOLS"/CORStest;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CORStest from Github.""$NORMAL";
		git clone https://github.com/RUB-NDS/CORStest.git "$TOOLS"/CORStest;
	fi
	if [[ -d "$TOOLS"/bypass-403 ]]; then
			echo -e "$LIGHT_GREEN[+] Updating bypass-403.""$NORMAL";
			cd "$TOOLS"/bypass-403;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing bypass-403 from Github.""$NORMAL";
		git clone https://github.com/iamj0ker/bypass-403 "$TOOLS"/bypass-403;
		cd "$TOOLS"/bypass-403
		chmod +x bypass-403.sh
	fi
	if [[ -d "$TOOLS"/CloudBrute ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudBrute.""$NORMAL";
			cd "$TOOLS"/CloudBrute;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudBrute from Github.""$NORMAL";
		git clone https://github.com/0xsha/CloudBrute "$TOOLS"/CloudBrute;
	fi
	if [[ -d "$TOOLS"/CloudBrute ]]; then
			echo -e "$LIGHT_GREEN[+] Updating CloudBrute.""$NORMAL";
			cd "$TOOLS"/CloudBrute;
			git pull;
			cd ;
	  else
		echo -e "$LIGHT_GREEN[+] Installing CloudBrute from Github.""$NORMAL";
		git clone https://github.com/0xsha/CloudBrute "$TOOLS"/CloudBrute;
		cd "$TOOLS"/CloudBrute
		chmod +x CloudBrute.sh
	fi
}
function install_go_tools() {
	echo -e "${BOLD}${LIGHT_GREEN}[+] Installing Go tools from Github.${NORMAL}";
	sleep 1;
  export GO111MODULE=on
	if ! testcmd gitleaks; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gitleaks...${NORMAL}"
		wget https://github.com/zricethezav/gitleaks/releases/download/v7.0.2/gitleaks-linux-amd64 -O gitleaks
		chmod +x gitleaks
		mv gitleaks /usr/bin/
      else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gitleaks...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd findomain; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing findomain...${NORMAL}"
		wget https://github.com/Findomain/Findomain/releases/download/2.1.5/findomain-linux -O findomain
		chmod +x findomain
		mv findomain /usr/bin/
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing findomain...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd subfinder; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subfinder...${NORMAL}"
		go get github.com/projectdiscovery/subfinder/v2/cmd/subfinder
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subfinder...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd assetfinder; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing assetfinder...${NORMAL}"
		go get -u github.com/tomnomnom/assetfinder
	 else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing assetfinder...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd ffuf; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ffuf...${NORMAL}"
		go get -u github.com/ffuf/ffuf;
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing ffuf...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gobuster; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gobuster...${NORMAL}"
		go get -u github.com/OJ/gobuster;
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gobuster...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd inception; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing inception...${NORMAL}"
		go get -u github.com/proabiral/inception;
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing inception...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd waybackurls; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing waybackurls...${NORMAL}"
		go get -u github.com/tomnomnom/waybackurls;
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing waybackurls...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd goaltdns; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing goaltdns...${NORMAL}"
		go get -u github.com/subfinder/goaltdns;
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing goaltdns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd rescope; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing rescope...${NORMAL}"
		go get -u github.com/root4loot/rescope
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing rescope...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd httpx; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing httpx...${NORMAL}"
		go get -u github.com/projectdiscovery/httpx/cmd/httpx
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing httpx...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd httprobe; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing httprobe...${NORMAL}"
		go get -u github.com/tomnomnom/httprobe;
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing httprobe...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd metabigor; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing metabigor...${NORMAL}"
		go get -u github.com/j3ssie/metabigor
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing metabigor...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd kxss; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing kxss...${NORMAL}"
		go get github.com/Emoe/kxss
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing kxss...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd nuclei; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing nuclei...${NORMAL}"
		go get -u github.com/projectdiscovery/nuclei/v2/cmd/nuclei
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing nuclei...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd qsreplace; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing qsreplace...${NORMAL}"
		go get -u github.com/tomnomnom/qsreplace
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing qsreplace...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd subzy; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subzy...${NORMAL}"
		go get -u github.com/lukasikic/subzy
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subzy...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd tko-subs; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing tko-subs...${NORMAL}"
		go get github.com/anshumanbh/tko-subs
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing tko-subs...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd shuffledns; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing shuffledns...${NORMAL}"
		go get -u github.com/projectdiscovery/shuffledns/cmd/shuffledns
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing shuffledns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gospider; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gospider...${NORMAL}"
		go get -u github.com/jaeles-project/gospider
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gospider...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gau; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gau...${NORMAL}"
		go get -u github.com/lc/gau
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gau...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd unfurl; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing unfurl...${NORMAL}"
		go get -u github.com/tomnomnom/unfurl
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing unfurl...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd subjs; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subjs...${NORMAL}"
		go get -u github.com/lc/subjs
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing subjs...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd gf; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gf...${NORMAL}"
		go get -u github.com/tomnomnom/gf
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing gf...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	if ! testcmd github-subdomains; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing github-subdomains...${NORMAL}"
		go get -u github.com/gwen001/github-subdomains
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing github-subdomains...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi	
	if [ ! -d ~/.gf ]; then
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing GF patterns...${NORMAL}"
		git clone https://github.com/1ndianl33t/Gf-Patterns ~/Gf-Patterns
		mv ~/Gf-Patterns/*.json ~/.gf
		rm -rf ~/Gf-Patterns
		echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
		cp -r /root/go/src/github.com/tomnomnom/gf/examples ~/.gf
	  else
		echo -e "${BOLD}${LIGHT_GREEN}[+] Installing GF patterns...${LIGHT_YELLOW}[ALREADY INSTALLED]${NORMAL}"
	fi
	cp -r ~/go/bin/* /usr/bin/
}

function wordlist(){
	git clone https://github.com/aashay4123/bounty_wordlist.git /opt/tools/wordlist
	git clone https://github.com/aashay4123/bounty_cheatsheet.git /opt/tools/cheatsheet
}

# Check for custom path
CUSTOM_PATH=$1;
if [[ "$CUSTOM_PATH" != "" ]]; then
		if [[ -e "$1" ]]; then
				TOOLS="$CUSTOM_PATH";
		  else
				echo -e "$RED""The path provided does not exist or can't be opened""$NORMAL";
				exit 1;
		fi
fi

# Create install directory
mkdir -pv $TOOLS;

grep 'Ubuntu' /etc/issue 1>/dev/null;
UBUNTU="$?";
grep 'Kali' /etc/issue 1>/dev/null;
KALI="$?";

if [[ "$UBUNTU" == 0 ]]; then 
	cp .bashrc ~/.bashrc
	install_ubuntu;
  elif [[ "$KALI" == 0 ]]; then
	cp .bashrc ~/.bashrc
	install_kali
  else
	echo -e "$RED""Unsupported distro detected. Exiting...""$NORMAL";
	exit 1;
fi

jaeles config update --repo https://github.com/ghsec/ghsec-jaeles-signatures 
# sudo apt update
# sudo apt install snapd
# sudo systemctl unmask snapd.service
# systemctl enable snapd.service
# systemctl start snapd.service

echo -e "$ORANGE""[i] Note: In order to use S3Scanner, you must configure your personal AWS credentials in the aws CLI tool.""$NORMAL";
echo -e "$ORANGE""[i] See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html for details.""$NORMAL";
echo "${BLUE} Create a ./config.yml or ~/.githound/config.yml${NORMAL}"

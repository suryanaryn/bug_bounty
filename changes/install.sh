#!/bin/bash

# Colors
NC='\033[0m';
RED='\033[0;31m';
GREEN='\033[0;32m';
BLUE='\033[0;34m';
ORANGE='\033[0;33m';

UBUNTU=;
DEBIAN=;
KALI=;
TOOLS="/opt/tools";

function install_kali() {
		echo -e "$GREEN""[+] Installing for Kali.""$NC";
		install_library;
		install_envlib;
		install_dnscan;
		install_bfac;
		install_massdns;
		install_aquatone;
		install_sublist3r;
		install_corstest;
		install_s3scanner;
		install_amass;
		install_dirsearch;
		install_go_tools;
}
function install_ubuntu() {
		echo -e "$GREEN""[+] Installing for Ubuntu.""$NC";
		install_library;
		install_envlib;
		install_dnscan;
		install_bfac;
		install_massdns;
		install_aquatone;
		install_sublist3r;
		install_corstest;
		install_s3scanner;
		install_amass;
		install_dirsearch;
		install_go_tools;
}

function install_library(){
	sudo apt update 
	sudo apt -y upgrade 
	sudo apt dist-upgrade -y
	sudo apt install -y libcurl4-openssl-dev libxml2 libxml2-dev libxslt1-dev ruby-dev build-essential libgmp-dev zlib1g-dev libgdbm-dev libncurses5-dev automake libtool bison libffi-dev 
	sudo apt install -y build-essential libssl-dev libffi-dev python-dev libcurl4-openssl-dev apt-transport-https libssl-dev ruby-full jq curl whois python-setuptools libldns-dev libpcap-dev
	sudo apt install -y npm gem perl parallel psmisc host dnsutils rename snapd git gcc make python3-pip libgeoip-dev 
	sudo apt install -y git wget curl nmap masscan whatweb sublist3r gobuster nikto wafw00f openssl libnet-ssleay-perl p7zip-full build-essential unzip 
	sar 1 1 >/dev/null
}

function install_envlib() {	
	# Run both pip installs
	code 1>/dev/null;
	CODE="$?";

	if [[ "$CODE" != 1 ]]; then 
		sudo wget https://go.microsoft.com/fwlink/?LinkID=760868 -O code.deb
		sudo dpkg -i code.deb
		sudo rm code.deb
	else
		echo -e "$RED""code already installed""$NC";
	fi

	if [[ ! -e /usr/local/bin/pip2 ]]; then 
		sudo wget https://bootstrap.pypa.io/get-pip.py
		sudo python2 get-pip.py
		sudo rm get-pip.py
	else
		echo -e "$RED"" pip2 already installed""$NC";
	fi

	if [[ ! -e /usr/bin/pip3 ]]; then 
		sudo apt-get purge python3-pip
		sudo apt-get install python3-pip -y
	else
		echo -e "$RED"" pip3 already installed""$NC";
	fi
	echo -e "$GREEN""[+] Installing requirements for Python 2 and Python 3.""$NC";
	sudo pip2 install -r requirements2.txt;
	sudo pip3 install -r requirements3.txt;
	sar 1 1 >/dev/null
	if [[ ! -e /usr/local/go/bin/go ]];then
	echo "Installing Golang"
		sudo wget -nv https://golang.org/dl/go1.15.6.linux-amd64.tar.gz
		sudo tar -C /usr/local -xzf go1.15.6.linux-amd64.tar.gz;
		sudo rm -rf go1.15.6.linux-amd64.tar.gz;
		echo 'export GOROOT=/usr/local/go' >> ~/.bashrc
		echo 'export GOPATH=/root/go'   >> ~/.bashrc
		echo 'export PATH=$GOPATH/bin:$GOROOT/bin:$PATH' >> ~/.bashrc
		source ~/.bashrc
	else 
		echo -e "$RED"" golang already installed""$NC";
	fi

	if [[ ! -e /usr/bin/ruby ]]; then 
		echo "${GREEN} [+] Installing ruby ${RESET}"
		gpg --keyserver hkp://pool.sks-keyservers.net --recv-keys 409B6B1796C275462A1703113804BB82D39DC0E3 7D2BAF1CF37B13E2069D6956105BD0E739499BDB
		curl -sSL https://get.rvm.io | bash -s stable
		source /etc/profile.d/rvm.sh
		type rvm | head -n 1
		rvm install "ruby-2.7.1"
		rvm use "ruby-2.7.1" --default
		ruby -v
	else
		echo -e "$RED"" ruby already installed""$NC";
	fi

	sar 1 1 >/dev/null

} 

function install_tmp1() {
		if [[ -d "$TOOLS"/amass ]]; then
				rm -rf "$TOOLS"/amass;
		fi
		echo -e "$GREEN""[+] Installing amass 3.5.4 from Github.""$NC";
		wget -nv https://github.com/OWASP/Amass/releases/download/v3.5.4/amass_v3.5.4_linux_amd64.zip -O "$TOOLS"/amass.zip;
		unzip -j "$TOOLS"/amass.zip -d "$TOOLS"/amass;
		rm "$TOOLS"/amass.zip;
}

function install_tmp2() {
		if [[ -d "$TOOLS"/dnscan ]]; then
				echo -e "$GREEN""[+] Updating dnscan.""$NC";
				cd "$TOOLS"/dnscan;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing dnscan from Github.""$NC";
		git clone https://github.com/rbsec/dnscan.git "$TOOLS"/dnscan;
		fi
}

function install_dnscan() {
		if [[ -d "$TOOLS"/dnscan ]]; then
				echo -e "$GREEN""[+] Updating dnscan.""$NC";
				cd "$TOOLS"/dnscan;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing dnscan from Github.""$NC";
		git clone https://github.com/rbsec/dnscan.git "$TOOLS"/dnscan;
		fi
}
function install_amass() {
		if [[ -d "$TOOLS"/amass ]]; then
				rm -rf "$TOOLS"/amass;
		fi
		echo -e "$GREEN""[+] Installing amass 3.5.4 from Github.""$NC";
		wget -nv https://github.com/OWASP/Amass/releases/download/v3.5.4/amass_v3.5.4_linux_amd64.zip -O "$TOOLS"/amass.zip;
		unzip -j "$TOOLS"/amass.zip -d "$TOOLS"/amass;
		rm "$TOOLS"/amass.zip;
}
function install_bfac() {
		if [[ -d "$TOOLS"/bfac ]]; then
				echo -e "$GREEN""[+] Updating bfac.""$NC";
				cd "$TOOLS"/bfac;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing bfac from Github.""$NC";
		git clone https://github.com/mazen160/bfac.git "$TOOLS"/bfac;
		fi
}
function install_massdns() {
		if [[ -d "$TOOLS"/massdns ]]; then
				echo -e "$GREEN""[+] Updating massdns.""$NC";
				cd "$TOOLS"/massdns;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing massdns from Github.""$NC";
		git clone https://github.com/blechschmidt/massdns.git "$TOOLS"/massdns;
		fi
		
		# Compile massdns
		echo -e "$GREEN""[+] Compiling massdns from source.""$NC";
		cd "$TOOLS"/massdns;
		make;
		cd -;
}
function install_aquatone() {
		echo -e "$GREEN""[+] Installing aquatone 1.7.0 from Github.""$NC";
		mkdir -pv "$TOOLS"/aquatone;
		wget -nv https://github.com/michenriksen/aquatone/releases/download/v1.7.0/aquatone_linux_amd64_1.7.0.zip -O "$TOOLS"/aquatone.zip;
		unzip -o "$TOOLS"/aquatone.zip -d "$TOOLS"/aquatone;
		rm "$TOOLS"/aquatone.zip;
}
function install_nikto() {
		if [[ -d "$TOOLS"/nikto ]]; then
				echo -e "$GREEN""[+] Updating nikto.""$NC";
				cd "$TOOLS"/nikto;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing nikto from Github.""$NC";
		git clone https://github.com/sullo/nikto.git "$TOOLS"/nikto;
		fi
}
function install_dirsearch() {
		if [[ -d "$TOOLS"/dirsearch ]]; then
				echo -e "$GREEN""[+] Updating dirsearch.""$NC";
				cd "$TOOLS"/dirsearch;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing dirsearch from Github.""$NC";
		git clone https://github.com/maurosoria/dirsearch.git "$TOOLS"/dirsearch;
		fi
}
function install_corstest() {
		if [[ -d "$TOOLS"/CORStest ]]; then
				echo -e "$GREEN""[+] Updating CORStest.""$NC";
				cd "$TOOLS"/CORStest;
				git pull;
				cd -;
		else
		echo -e "$GREEN""[+] Installing CORStest from Github.""$NC";
		git clone https://github.com/RUB-NDS/CORStest.git "$TOOLS"/CORStest;
		fi
}
function install_s3scanner() {
		if [[ -d "$TOOLS"/S3Scanner ]]; then
				echo -e "$GREEN""[+] Updating S3Scanner.""$NC";
				cd "$TOOLS"/S3Scanner;
				git pull;
		else
				cd -;
		echo -e "$GREEN""[+] Installing S3Scanner from Github.""$NC";
		git clone https://github.com/sa7mon/S3Scanner.git "$TOOLS"/S3Scanner;
		fi
}
function install_go_tools() {
	echo -e "$GREEN""[+] Installing Go tools from Github.""$NC";
	sleep 1;
	wget https://github.com/zricethezav/gitleaks/releases/download/v7.0.2/gitleaks-linux-amd64 -O gitleaks
	wget https://github.com/Findomain/Findomain/releases/download/2.1.5/findomain-linux -O findomain
  	chmod +x gitleaks findomain
	mv gitleaks findomain /usr/bin/

	export GO111MODULE=on
	echo -e "$GREEN""[+] Installing subfinder from Github.""$NC";
	go get -u -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder
	go get -u github.com/tomnomnom/assetfinder
	echo -e "$GREEN""[+] Installing ffuf from Github.""$NC";
	go get -u github.com/ffuf/ffuf;
	echo -e "$GREEN""[+] Installing gobuster from Github.""$NC";
	go get -u github.com/OJ/gobuster;
	echo -e "$GREEN""[+] Installing inception from Github.""$NC";
	go get -u github.com/proabiral/inception;
	echo -e "$GREEN""[+] Installing waybackurls from Github.""$NC";
	go get -u github.com/tomnomnom/waybackurls;
	echo -e "$GREEN""[+] Installing goaltdns from Github.""$NC";
	go get -u github.com/subfinder/goaltdns;
	echo -e "$GREEN""[+] Installing rescope from Github.""$NC";
	go get -u github.com/root4loot/rescope;
	echo -e "$GREEN""[+] Installing httpx from Github.""$NC";
	go get -u -v github.com/projectdiscovery/httpx/cmd/httpx
	echo -e "$GREEN""[+] Installing httprobe from Github.""$NC";
	go get -u github.com/tomnomnom/httprobe;
	echo -e "$GREEN""[+] Installing metabigor from Github.""$NC";
	go get -u github.com/j3ssie/metabigor
	echo -e "$GREEN""[+] Installing kxss from Github.""$NC";
	go get github.com/Emoe/kxss
	echo -e "$GREEN""[+] Installing qsreplace from Github.""$NC";
	go get -u github.com/tomnomnom/qsreplace
	echo -e "$GREEN""[+] Installing nuclei from Github.""$NC";
	go get -u github.com/projectdiscovery/nuclei/v2/cmd/nuclei
	echo -e "$GREEN""[+] Installing subzy from Github.""$NC";
	go get -u github.com/lukasikic/subzy
	go get github.com/anshumanbh/tko-subs
	echo -e "$GREEN""[+] Installing ffuf from Github.""$NC";
	go get -u github.com/ffuf/ffuf
	echo -e "$GREEN""[+] Installing waybackurls from Github.""$NC";
	go get -u github.com/tomnomnom/waybackurls
	echo -e "$GREEN""[+] Installing gospider from Github.""$NC";
	go get -u github.com/jaeles-project/gospider
	echo -e "$GREEN""[+] Installing gau from Github.""$NC";
	go get -u github.com/lc/gau
	echo -e "$GREEN""[+] Installing unfurl from Github.""$NC";
	go get -u github.com/tomnomnom/unfurl
	echo -e "$GREEN""[+] Installing subjs from Github.""$NC";
	go get -u github.com/lc/subjs
	echo -e "$GREEN""[+] Installing gf from Github.""$NC";
	go get -u github.com/tomnomnom/gf
	echo 'source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash' >> ~/.bashrc
	cp -r /root/go/src/github.com/tomnomnom/gf/examples ~/.gf
	cp -r ~/go/bin/* /usr/bin/
	echo "${BLUE} done${RESET}"
	sar 1 1 >/dev/null
}
function wordlist(){
	git clone https://github.com/assetnote/commonspeak2-wordlists /opt/tools/Wordlists/commonspeak2-wordlists
	git clone https://github.com/fuzzdb-project/fuzzdb /opt/tools/Wordlists/fuzzdb
	git clone https://github.com/1N3/IntruderPayloads /opt/tools/Wordlists/IntruderPayloads
	git clone https://github.com/internetwache/CT_subdomains.git /opt/tools/Wordlists/CT_subdomains
	git clone https://github.com/swisskyrepo/PayloadsAllTheThings /opt/tools/Wordlists/PayloadsAllTheThings
}



# Check for custom path
CUSTOM_PATH=$1;
if [[ "$CUSTOM_PATH" != "" ]]; then
		if [[ -e "$1" ]]; then
				TOOLS="$CUSTOM_PATH";
		else
				echo -e "$RED""The path provided does not exist or can't be opened""$NC";
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
	echo -e "$RED""Unsupported distro detected. Exiting...""$NC";
	exit 1;
fi

echo -e "$BLUE""[i] Please run 'source ~/.bashrc' to add the Go binary path to your \$PATH variable.""$NC";
echo -e "$ORANGE""[i] Note: In order to use S3Scanner, you must configure your personal AWS credentials in the aws CLI tool.""$NC";
echo -e "$ORANGE""[i] See https://docs.aws.amazon.com/cli/latest/userguide/cli-chap-configure.html for details.""$NC";

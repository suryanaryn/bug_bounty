#!/bin/bash

# Colors
NC='\033[0m';
RED='\033[0;31m';
GREEN='\033[0;32m';
BLUE='\033[0;34m';
ORANGE='\033[0;33m';

# Wordlists
  SUBDOMAIN_WORDLIST=wordlists/top_subdomains.txt;

# Config file variables
  ENABLE_DNSCAN=0;
  ENABLE_GOALTDNS=0;
  ENABLE_MASSDNS=1; 
  ENABLE_INCEPTION=0;
  ENABLE_FFUF=0;
  ENABLE_GOBUSTER=0;
  ENABLE_DIRSEARCH=0;
  ENABLE_BFAC=0;
  ENABLE_NIKTO=0;
  ENABLE_MASSCAN=0;
  ENABLE_NMAP=0;
  ENABLE_SCREENSHOTS=0;
  ENABLE_RESCOPE=0;

# Other variables
  ALL_IP=all_discovered_ips.txt;
  ALL_DOMAIN=all_discovered_domains.txt;
  ALL_RESOLVED=all_resolved_domains.txt;

# set tool path
function set_tool_paths() {
		# If tool paths have not been set, set them
		if [[ "$TOOL_PATH_SET" -eq 0 ]]; then
				TOOL_PATH_SET=1;
				SUBFINDER=$(which subfinder);
				SUBJACK=$(which subjack);
				FFUF=$(which ffuf);
				WHATWEB=$(which whatweb);
				WAFW00F=$(which wafw00f);
				GOBUSTER=$(which gobuster);
				CHROMIUM=$(which chromium);
				NMAP=$(which nmap);
				MASSCAN=$(which masscan);
				NIKTO=$(which nikto);
				INCEPTION=$(which inception);
				WAYBACKURLS=$(which waybackurls);
				GOALTDNS=$(which goaltdns);
				RESCOPE=$(which rescope);
				KNOCK=$(which knockpy);
				HTTPROBE=$(which httprobe);
				SUBLIST3R=$TOOL_PATH/Sublist3r/sublist3r.py;
				DNSCAN=$TOOL_PATH/dnscan/dnscan.py;
				MASSDNS_BIN=$TOOL_PATH/massdns/bin/massdns;
				MASSDNS_RESOLVERS=resolvers.txt;
				AQUATONE=$TOOL_PATH/aquatone/aquatone;
				BFAC=$TOOL_PATH/bfac/bfac;
				DIRSEARCH=$TOOL_PATH/dirsearch/dirsearch.py;
				SNALLY=$TOOL_PATH/snallygaster/snallygaster;
				CORSTEST=$TOOL_PATH/CORStest/corstest.py;
				S3SCANNER=$TOOL_PATH/S3Scanner/s3scanner.py;
				AMASS=$TOOL_PATH/amass/amass;
		else
				return;
		fi
}
# Check that a file path exists and is not empty
function exists() {
		if [[ -e "$1" ]]; then
				if [[ -s "$1" ]]; then
						return 1;
				else
						return 0;
				fi
		else
				return 0;
		fi
}
function list_found() {
		unique;
		echo -e "$GREEN""[+] Found $(wc -l "$WORKING_DIR"/$ALL_IP | awk '{print $1}') unique IPs so far.""$NC"
		echo -e "$GREEN""[+] Found $(wc -l "$WORKING_DIR"/$ALL_DOMAIN | awk '{print $1}') unique discovered domains so far.""$NC"
		echo -e "$GREEN""[+] Found $(wc -l "$WORKING_DIR"/$ALL_RESOLVED | awk '{print $1}') unique resolvable domains so far.""$NC"
}
# Check for root for runs using masscan
function check_root() {
		if [[ $EUID -ne 0 ]]; then
		   while true; do
				   echo -e "$ORANGE""[!] Please note: Script is not being run as root."
				   echo -e "$ORANGE""[!] Provided script options include masscan, which must run as root."
				   echo -e "$ORANGE""[!] The script will hang while waiting for the sudo password."
				   echo -e "$ORANGE""[!] If you are using Notica notifications, you will be notified when the sudo password is needed."
				   read -rp "Do you want to exit and [R]e-run as root, [E]nter sudo password? " CHOICE;
						   case $CHOICE in
								   [rR]* )
										   echo -e "$RED""[!] Exiting script.""$NC";
										   exit 1;
										   ;;
								   [eE]* )
										   echo -e "$ORANGE""Script will wait for sudo password.""$NC";
										   break;
										   ;;
								   * )
										   echo -e "$ORANGE""Please enter [R]e-run,  [E]nter sudo password.""$NC";
										   ;;
						   esac
		   done
		fi
}
# Parse configuration file
  # function parse_config() {
  # 		DOMAIN=$(grep '^DOMAIN' "$CONFIG_FILE" | cut -d '=' -f 2);
  # 		if [[ "$DOMAIN" == "" ]]; then
  # 				echo -e "$RED""[!] No domain was provided in the configuration file.""$NC";
  # 				exit 1;
  # 		else
  # 				DOMAIN_COUNT=$(echo "$DOMAIN" | awk -F "," "{ print NF }")
  # 				if [[ "$DOMAIN_COUNT" -gt 1 ]]; then
  # 						DOMAIN_ARRAY=();
  # 						for (( i=1; i<=$DOMAIN_COUNT; i++ )); do
  # 								DOMAIN_ARRAY+=($(echo $DOMAIN | cut -d ',' -f $i | tr -d " "));
  # 						done
  # 				fi
  # 		fi

  # 		if [[ $(grep '^USE_ALL' "$CONFIG_FILE" | cut -d '=' -f 2) == "YES" ]]; then	
  # 				USE_ALL=1;
  # 		fi
  # }

# Handle CLI arguments
while getopts ":hu:d:L:C:sicb:IaADX:po:Hn:P:r" opt; do
		case ${opt} in
				h ) # -h help
						usage;
						exit;
						;;
				u ) # -u URL/domain
						DOMAIN=$OPTARG;
						;;
				L ) # -L configuration file
						exists "$OPTARG";
						RESULT=$?;
						if [[ "$RESULT" -eq 1 ]]; then
								CONFIG_FILE="$OPTARG";
								parse_config;
						else
								echo -e "$RED""[!] Provided configuration file $OPTARG is empty or doesn't exist.""$NC";
								usage;
								exit 1;
						fi
						# Exit early if config file is found
						break;
						;;
				r ) # -r run rescope
						ENABLE_RESCOPE=1;
						;;
				\? ) # Invalid option
						echo -e "$RED""[!] Invalid Option: -$OPTARG" 1>&2;
						usage;
						exit 1;
						;;
				: ) # Invalid option
						echo -e "$RED""[!] Invalid Option: -$OPTARG requires an argument" 1>&2;
						usage;
						exit 1;
						;;
				* ) # Invalid option
						echo -e "$RED""[!] Invalid Option: -$OPTARG" 1>&2;
						usage;
						exit 1;
						;;
		esac
done
shift $((OPTIND -1));
function check_paths() {
		# Check if paths haven't been set and set them
		set_tool_paths;

		# Check that all paths are set
		if [[ "$SUBFINDER" == "" ]] || [[ ! -f "$SUBFINDER" ]]; then
				echo -e "$RED""[!] The path or the file specified by the path for subfinder does not exit.";
				exit 1;
		fi
		if [[ "$SUBLIST3R" == "" ]] || [[ ! -f "$SUBLIST3R" ]]; then
				grep 'Kali' /etc/issue 1>/dev/null; 
				KALI=$?;
				if [[ "$KALI" -eq 0 ]]; then
						SUBLIST3R=$(command -v sublist3r);
				else
						echo -e "$RED""[!] The path or the file specified by the path for sublist3r does not exit.";
						exit 1;
				fi
		fi
}
function run_dnscan() {
		echo -e "$GREEN""[i]$ORANGE Command: $DNSCAN -d $1 -t 25 -o $WORKING_DIR/dnscan_out.txt -w $2.""$NC";
		START=$(date +%s);
		$DNSCAN -d "$1" -t 25 -o "$WORKING_DIR"/dnscan_out.txt -w "$2";
		END=$(date +%s);
		DIFF=$(( END - START ));

		# Remove headers and leading spaces
		sed '1,/A records/d' "$WORKING_DIR"/dnscan_out.txt | tr -d ' ' > "$WORKING_DIR"/trimmed;
		cut "$WORKING_DIR"/trimmed -d '-' -f 1 > "$WORKING_DIR"/dnscan-ips.txt;
		cut "$WORKING_DIR"/trimmed -d '-' -f 2 > "$WORKING_DIR"/dnscan-domains.txt;
		rm "$WORKING_DIR"/trimmed;

		# Cat output into main lists
		cat "$WORKING_DIR"/dnscan-ips.txt >> "$WORKING_DIR"/$ALL_IP;
		cat "$WORKING_DIR"/dnscan-domains.txt >> "$WORKING_DIR"/"$ALL_DOMAIN";

		echo -e "$GREEN""[i]$BLUE dnsscan took $DIFF seconds to run.""$NC";
		echo -e "$GREEN""[!]$ORANGE dnscan found $(wc -l "$WORKING_DIR"/dnscan-ips.txt | awk '{print $1}') IP/domain pairs.""$NC";
		list_found;
		sleep 1;
}
function run_sublist3r() {
		# Trap SIGINT so broken sublist3r runs can be cancelled
		trap cancel SIGINT; 

		echo -e "$GREEN""[i]$BLUE Scanning $1 with sublist3r.""$NC";
		echo -e "$GREEN""[i]$ORANGE Command: $SUBLIST3R -d $1 -v -t 50 -o $WORKING_DIR/sublist3r-output.txt.""$NC";
		START=$(date +%s);
		"$SUBLIST3R" -d "$1" -v -t 50 -o "$WORKING_DIR"/sublist3r-output.txt
		END=$(date +%s);
		DIFF=$(( END - START ));

		# Check that output file exists
		if [[ -f "$WORKING_DIR"/sublist3r-output.txt ]]; then
				# Cat output into main lists
				cat "$WORKING_DIR"/sublist3r-output.txt >> "$WORKING_DIR"/$ALL_DOMAIN;
				echo -e "$GREEN""[i]$BLUE sublist3r took $DIFF seconds to run.""$NC";
				echo -e "$GREEN""[!]$ORANGE sublist3r found $(wc -l "$WORKING_DIR"/sublist3r-output.txt | awk '{print $1}') domains.""$NC";
		fi

		list_found;
		sleep 1;
}
function run_knock() {
		# Call with domain as $1 and wordlist as $2

		# Trap SIGINT so broken knock runs can be cancelled
		trap cancel SIGINT;

		echo -e "$GREEN""[i]$BLUE Scanning $1 with knock.""$NC";
		echo -e "$GREEN""[i]$ORANGE Command: knockpy $DOMAIN -w $2 -o $WORKING_DIR/knock-output.txt""$NC";

		START=$(date +%s);
		"$KNOCK" "$1" -w "$2" -o "$WORKING_DIR"/knock-output.txt;
		END=$(date +%s);
		DIFF=$(( END - START ));

		# Parse output and add to all domain and IP lists
		awk -F ',' '{print $2" "$3}' "$WORKING_DIR"/knock-output.txt | grep -e "$DOMAIN$" > "$WORKING_DIR"/knock-tmp.txt;
		cut -d ' ' -f 1 "$WORKING_DIR"/knock-tmp.txt >> "$WORKING_DIR"/"$ALL_IP";
		cut -d ' ' -f 2 "$WORKING_DIR"/knock-tmp.txt >> "$WORKING_DIR"/"$ALL_DOMAIN";

		echo -e "$GREEN""[i]$BLUE knock took $DIFF seconds to run.""$NC";
		echo -e "$GREEN""[!]$ORANGE knock found $(wc -l "$WORKING_DIR"/knock-tmp.txt | awk '{print $1}') domains.""$NC";

		list_found;
		sleep 1;
		rm "$WORKING_DIR"/knock-tmp.txt;
}
function run_amass() {
		# Call with domain as $1 and wordlist as $2

		echo -e "$GREEN""[i]$BLUE Scanning $1 with amass.""$NC";
		echo -e "$GREEN""[i]$ORANGE Command: amass enum -d $1 -w $2 -ip -rf resolvers.txt -active -o $WORKING_DIR/amass-output.txt -min-for-recursive 3 -bl $BLACKLIST""$NC";
		START=$(date +%s);
		"$AMASS" enum -d "$1" -brute -w "$2" -ipv4 -rf resolvers.txt -active -o "$WORKING_DIR"/amass-output.txt -min-for-recursive 3 -bl "$BLACKLIST";
		END=$(date +%s);
		DIFF=$(( END - START ));

		# Check that output file exists amd parse output
		if [[ -f "$WORKING_DIR"/amass-output.txt ]]; then
				# Cat output into main lists
				cut -d ' ' -f 1 "$WORKING_DIR"/amass-output.txt >> "$WORKING_DIR"/"$ALL_DOMAIN";
				cut -d ' ' -f 2 "$WORKING_DIR"/amass-output.txt >> "$WORKING_DIR"/"$ALL_IP";
				echo -e "$GREEN""[i]$BLUE amass took $DIFF seconds to run.""$NC";
				echo -e "$GREEN""[!]$ORANGE amass found $(wc -l "$WORKING_DIR"/amass-output.txt | awk '{print $1}') domains.""$NC";
		fi

		list_found;
		sleep 1;
}
function run_goaltdns() {
		# Run goaltdns with found subdomains combined with altdns-wordlist.txt

		echo -e "$GREEN""[i]$BLUE Running goaltdns against all $(wc -l "$WORKING_DIR"/$ALL_DOMAIN | awk '{print $1}') unique discovered subdomains to generate domains for masscan to resolve.""$NC";
		echo -e "$GREEN""[i]$ORANGE Command: goaltdns -l $WORKING_DIR/$ALL_DOMAIN -w wordlists/altdns-words.txt -o $WORKING_DIR/goaltdns-output.txt.""$NC";
		START=$(date +%s);
		"$GOALTDNS" -l "$WORKING_DIR"/$ALL_DOMAIN -w wordlists/altdns-words.txt -o "$WORKING_DIR"/goaltdns-output.txt;
		END=$(date +%s);
		DIFF=$(( END - START ));

		echo -e "$GREEN""[i]$BLUE Goaltdns took $DIFF seconds to run.""$NC";
		echo -e "$GREEN""[i]$BLUE Goaltdns generated $(wc -l "$WORKING_DIR"/goaltdns-output.txt | awk '{print $1}') subdomains.""$NC";
		sleep 1;
}
#check this out
function run_massdns() {
		# Call with domain as $1, wordlist as $2, and alone as $3

		# Check if being called without goaltdns
		if [[ "$3" == "alone" ]]; then
				# Create wordlist with appended domain for massdns
				sed "/.*/ s/$/\.$1/" $2 > "$WORKING_DIR"/massdns-appended.txt;

				echo -e "$GREEN""[i]$BLUE Scanning $(cat "$WORKING_DIR"/$ALL_DOMAIN "$WORKING_DIR"/$ALL_IP "$WORKING_DIR"/massdns-appended.txt | sort | uniq | wc -l) current unique $1 domains with massdns (in quiet mode).""$NC";
				echo -e "$GREEN""[i]$ORANGE Command: cat (all found domains and IPs) | $MASSDNS_BIN -r $MASSDNS_RESOLVERS -q -t A -o S -w $WORKING_DIR/massdns-result.txt.""$NC";
				START=$(date +%s);
				cat "$WORKING_DIR"/$ALL_DOMAIN "$WORKING_DIR"/$ALL_IP "$WORKING_DIR"/massdns-appended.txt | sort | uniq | $MASSDNS_BIN -r $MASSDNS_RESOLVERS -q -t A -o S -w "$WORKING_DIR"/massdns-result.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
		else
				# Run goaltdns to get altered domains to resolve along with other discovered domains
				run_goaltdns;

				# Create wordlist with appended domain for massdns
				sed "/.*/ s/$/\.$1/" $2 > "$WORKING_DIR"/massdns-appended.txt;

				echo -e "$GREEN""[i]$BLUE Scanning $(cat "$WORKING_DIR"/$ALL_DOMAIN "$WORKING_DIR"/$ALL_IP "$WORKING_DIR"/goaltdns-output.txt "$WORKING_DIR"/massdns-appended.txt | sort | uniq | wc -l) current unique $1 domains and IPs, goaltdns generated domains, and domain-appended wordlist with massdns (in quiet mode).""$NC";
				echo -e "$GREEN""[i]$ORANGE Command: cat (all found domains and IPs) | $MASSDNS_BIN -r $MASSDNS_RESOLVERS -q -t A -o S -w $WORKING_DIR/massdns-result.txt.""$NC";
				START=$(date +%s);
				cat "$WORKING_DIR"/$ALL_DOMAIN "$WORKING_DIR"/$ALL_IP "$WORKING_DIR"/goaltdns-output.txt "$WORKING_DIR"/massdns-appended.txt | sort | uniq | $MASSDNS_BIN -r $MASSDNS_RESOLVERS -q -t A -o S -w "$WORKING_DIR"/massdns-result.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
		fi

		# Parse results
		grep CNAME "$WORKING_DIR"/massdns-result.txt > "$WORKING_DIR"/massdns-CNAMEs.txt;
		grep -v CNAME "$WORKING_DIR"/massdns-result.txt | cut -d ' ' -f 3 >> "$WORKING_DIR"/$ALL_IP;

		# Add any new in-scope CNAMEs to main list
		cut -d ' ' -f 3 "$WORKING_DIR"/massdns-CNAMEs.txt | grep "$DOMAIN.$" >> "$WORKING_DIR"/$ALL_DOMAIN;

		# Add newly discovered domains to all domains list
		grep -v CNAME "$WORKING_DIR"/massdns-result.txt | cut -d ' ' -f 1 >> "$WORKING_DIR"/"$ALL_DOMAIN";
		# Remove trailing periods from results
		sed -i 's/\.$//' "$WORKING_DIR"/"$ALL_DOMAIN";

		# Add all resolved domains to resolved domain list
		grep -v CNAME "$WORKING_DIR"/massdns-result.txt | cut -d ' ' -f 1 >> "$WORKING_DIR"/"$ALL_RESOLVED";
		# Remove trailing periods from results
		sed -i 's/\.$//' "$WORKING_DIR"/"$ALL_RESOLVED";

		echo -e "$GREEN""[i]$BLUE Massdns took $DIFF seconds to run.""$NC";
		echo -e "$GREEN""[!]$ORANGE Check $WORKING_DIR/massdns-CNAMEs.txt for a list of CNAMEs found.""$NC";
		sleep 1;

		list_found;
		sleep 1;
}
function run_httprobe() {
		# Run httprobe to filter $ALL_RESOLVED for running server on port 443,80
		echo -e "$GREEN""[i]$BLUE Running httprobe against $(cat "$WORKING_DIR"/"$ALL_RESOLVED" | sort -u | wc -l) resolved domains.";
		echo -e "$GREEN""[i]$ORANGE Command: cat "$WORKING_DIR"/"$ALL_RESOLVED" | httprobe -c 40 -t 3000 -p http:8443 -p https:8443 -p http:8080 -p https:8080 -p http:8008 -p https:8008 -p http:591 -p https:591 -p http:593 -p https:593 -p http:981 -p https:981 -p http:2480 -p https:2480 -p http:4567 -p https:4567 -p http:5000 -p https:5000 -p http:5800 -p https:5800 -p http:7001 -p https:7001 -p http:7002 -p https:7002 -p http:9080 -p https:9080 -p http:9090 -p https:9090 -p https:9443 -p https:18091 -p https:18092 | tee "$WORKING_DIR"/httprobe-out.txt.""$NC";
		START=$(date +%s);
		cat "$WORKING_DIR"/$ALL_RESOLVED | httprobe -c 40 -t 3000 -p http:8443 -p https:8443 -p http:8080 -p https:8080 -p http:8008 -p https:8008 -p http:591 -p https:591 -p http:593 -p https:593 -p http:981 -p https:981 -p http:2480 -p https:2480 -p http:4567 -p https:4567 -p http:5000 -p https:5000 -p http:5800 -p https:5800 -p http:7001 -p https:7001 -p http:7002 -p https:7002 -p http:9080 -p https:9080 -p http:9090 -p https:9090 -p https:9443 -p https:18091 -p https:18092 | tee "$WORKING_DIR"/httprobe-out.txt;
		END=$(date +%s);
		DIFF=$(( END - START ));
		
		echo -e "$GREEN""[i]$BLUE httprobe took $DIFF seconds to run.""$NC";
		sleep 1;
}
function run_aquatone () {
  mkdir "$WORKING_DIR"/aquatone;
  echo -e "$BLUE""[i] Running aquatone against all $(wc -l "$WORKING_DIR"/$ALL_RESOLVED | awk '{print $1}') unique discovered subdomains.""$NC";
  START=$(date +%s);
  $AQUATONE -threads 10 -chrome-path "$CHROMIUM" -ports medium -out "$WORKING_DIR"/aquatone < "$WORKING_DIR"/$ALL_RESOLVED;
  END=$(date +%s);
  DIFF=$(( END - START ));
  echo -e "$GREEN""[i]$BLUE Aquatone took $DIFF seconds to run.""$NC";
}
function run_masscan() {
  # Run masscan against all IPs found on all ports
  echo -e "$GREEN""[i]$BLUE Running masscan against all $(wc -l "$WORKING_DIR"/$ALL_IP | awk '{print $1}') unique discovered IP addresses.""$NC";

  # Check that IP list is not empty
  IP_COUNT=$(wc -l "$WORKING_DIR"/$ALL_IP | awk '{print $1}');
  if [[ "$IP_COUNT" -lt 1 ]]; then
      echo -e "$RED""[i] No IP addresses have been found. Skipping masscan scan.""$NC";
      return;
  fi

  START=$(date +%s);
  if [[ "$NOTICA" != "" ]]; then
      run_notica_sudo;
  fi
  sudo "$MASSCAN" -p1-65535 -iL "$WORKING_DIR"/$ALL_IP --rate=7000 -oL "$WORKING_DIR"/root-masscan-output.txt;
  END=$(date +%s);
  DIFF=$(( END - START ));
  echo -e "$GREEN""[i]$BLUE Masscan took $DIFF seconds to run.""$NC";

  # Trim # from first and last lines of output
  grep -v '#' "$WORKING_DIR"/root-masscan-output.txt > "$WORKING_DIR"/masscan-output.txt;
}
function run_nmap() {
		# Check that IP list is not empty
		IP_COUNT=$(wc -l "$WORKING_DIR"/$ALL_IP | awk '{print $1}');
		if [[ "$IP_COUNT" -lt 1 ]]; then
				echo -e "$RED""[i] No IP addresses have been found. Skipping nmap scan.""$NC";
				return;
		fi

		# Run nmap against all-ip.txt against ports found by masscan, unless alone arg is passed as $1
		if [[ ! -s "$WORKING_DIR"/masscan-output.txt ]]; then
				echo -e "$GREEN""[i]$BLUE Running nmap against all $(wc -l "$WORKING_DIR"/"$ALL_IP" | awk '{print $1}') unique discovered IP addresses.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: nmap -n -v -sV -iL $WORKING_DIR/all_discovered_ips.txt -oA $WORKING_DIR/nmap-output --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl.""$NC";
				START=$(date +%s);
				"$NMAP" -n -v -sV -iL "$WORKING_DIR"/"$ALL_IP" -oA "$WORKING_DIR"/nmap-output --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Nmap took $DIFF seconds to run.""$NC";
		else
				# Process masscan output for ports found
				cut -d ' ' -f 3  "$WORKING_DIR"/masscan-output.txt >> "$WORKING_DIR"/temp;
				sort "$WORKING_DIR"/temp | uniq > "$WORKING_DIR"/ports;
				rm "$WORKING_DIR"/temp;

				# Count ports in case it's over nmap's ~22k parameter limit, then run multiple scans
				PORT_NUMBER=$(wc -l "$WORKING_DIR"/ports | awk '{print $1}');

				if [[ $PORT_NUMBER -gt 22000 ]]; then
						echo -e "$GREEN""[!]$RED WARNING: Masscan found more than 22k open ports. This is more than nmap's port argument length limit, and likely indicates lots of false positives. Consider running nmap with -p- to scan all ports.""$NC";
						sleep 2;
						return;
				fi

				# Get live IPs from masscan
				cut -d ' ' -f 4 "$WORKING_DIR"/masscan-output.txt >> "$WORKING_DIR"/"$ALL_IP";
				
				echo -e "$GREEN""[i]$BLUE Running nmap against $(wc -l "$WORKING_DIR"/"$ALL_IP" | awk '{print $1}') unique discovered IP addresses and $(wc -l "$WORKING_DIR"/ports | awk '{print $1}') ports identified by masscan.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: nmap -n -v -sV -iL $WORKING_DIR/all_discovered_ips.txt -p $(tr '\n' , < "$WORKING_DIR"/ports) -oA $WORKING_DIR/nmap-output.""$NC";
				START=$(date +%s);
				nmap -n -v -sV -iL "$WORKING_DIR"/"$ALL_IP" -p "$(tr '\n' , < "$WORKING_DIR"/ports)" -oA "$WORKING_DIR"/nmap-output --stylesheet https://raw.githubusercontent.com/honze-net/nmap-bootstrap-xsl/master/nmap-bootstrap.xsl;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Nmap took $DIFF seconds to run.""$NC";
		fi
		echo -e "$GREEN""[i]$BLUE Nmap took $DIFF seconds to run.""$NC";
}
function run_portscan() {
  run_masscan;
  run_nmap;
  # add brutespray
}
function parse_gobuster() {
		# Call with file name as $1
        FILE=$1;
   
        # Get total line count
        TOTAL=$(wc -l "$1" | awk '{print $1}');
		if [[ "$TOTAL" -eq 0 ]]; then
				return
		fi
   
        # Get counts of different return codes
	    COUNT_200=$(grep -c 'Status: 200' "$FILE");
        COUNT_201=$(grep -c 'Status: 201' "$FILE");
        COUNT_202=$(grep -c 'Status: 202' "$FILE");
        COUNT_204=$(grep -c 'Status: 204' "$FILE");
        COUNT_307=$(grep -c 'Status: 307' "$FILE");
        COUNT_308=$(grep -c 'Status: 308' "$FILE");
        COUNT_400=$(grep -c 'Status: 400' "$FILE");
        COUNT_401=$(grep -c 'Status: 401' "$FILE");
        COUNT_403=$(grep -c 'Status: 403' "$FILE");
        COUNT_405=$(grep -c 'Status: 405' "$FILE");
        COUNT_500=$(grep -c 'Status: 500' "$FILE");
        COUNT_501=$(grep -c 'Status: 501' "$FILE");
        COUNT_502=$(grep -c 'Status: 502' "$FILE");
        COUNT_503=$(grep -c 'Status: 503' "$FILE");
   
        # Write return code counts to top of file
	    echo -e "$GREEN""Number of 200 responses:\\t$BLUE $COUNT_200" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 201 responses:\\t$BLUE $COUNT_201" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 202 responses:\\t$BLUE $COUNT_202" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 204 responses:\\t$BLUE $COUNT_204" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 307 responses:\\t$BLUE $COUNT_307" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 308 responses:\\t$BLUE $COUNT_308" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 400 responses:\\t$BLUE $COUNT_400" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 401 responses:\\t$BLUE $COUNT_401" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 403 responses:\\t$BLUE $COUNT_403" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 405 responses:\\t$BLUE $COUNT_405" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 500 responses:\\t$BLUE $COUNT_500" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 501 responses:\\t$BLUE $COUNT_501" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 502 responses:\\t$BLUE $COUNT_502" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 503 responses:\\t$BLUE $COUNT_503" >> "$FILE"-parsed;
   
        if [[ "$TOTAL" -gt 1000 ]]; then
                echo -e "$GREEN""False positives:\\t\\t$RED Likely! Total count is $TOTAL.""$NC" >> "$FILE"-parsed;
        else
                echo -e $"$GREEN""False positives:\\t\\t$BLUE Unlikely. Total count is $TOTAL.""$NC" >> "$FILE"-parsed;
        fi  
        echo -e "\\n\\n\\n" >> "$FILE"-parsed;
   
        # Echo all parse d output to file
		cat "$FILE" >> "$FILE"-parsed;
}
function run_gobuster() {
		# Call with domain as $1, wordlist size as $2, and domain list as $3
		if [[ $3 == $WORKING_DIR/$ALL_RESOLVED ]]; then # Run against all resolvable domains
				echo -e "$GREEN""[i]$BLUE Running gobuster against all $(wc -l "$3" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: gobuster dir -u https://$DOMAIN -s '200,201,202,204,307,308,400,401,403,405,500,501,502,503' --timeout 3s -e -k -t 20 -w $2 -o gobuster.""$NC";
				# Run gobuster
				mkdir "$WORKING_DIR"/gobuster;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$GOBUSTER" dir -u "$HTTP"://"$ADOMAIN" -s '200,201,202,204,307,308,400,401,403,405,500,501,502,503' --timeout 3s -e -k -t 20 -w "$2" -o "$WORKING_DIR"/gobuster/"$ADOMAIN".txt;
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Gobuster took $DIFF seconds to run.""$NC";
		else # Run against all interesting domains
				echo -e "$GREEN""[i]$BLUE Running gobuster against all $(wc -l "$3" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: gobuster dir -u $HTTP://$DOMAIN -s '200,201,202,204,307,308,400,401,403,405,500,501,502,503' --timeout 3s -e -k -t 20 -w $2 -o $WORKING_DIR/gobuster""$NC";
				# Run gobuster
				mkdir "$WORKING_DIR"/gobuster;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$GOBUSTER" dir -u "$HTTP"://"$ADOMAIN" -s '200,201,202,204,307,308,400,401,403,405,500,501,502,503' --timeout 3s -e -k -t 20 -w "$2" -o "$WORKING_DIR"/gobuster/"$ADOMAIN".txt;
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Gobuster took $DIFF seconds to run.""$NC";
		fi

		# Parse results for better readability of the output
		for file in "$WORKING_DIR"/gobuster/*; do
				COUNT=$(wc -l "$file" | awk '{print $1}');
				# No output files have 17 lines
				if [[ $COUNT -gt 17 ]]; then
						parse_gobuster "$file";
				fi
		done
}
function parse_ffuf() {
		# Call with file name as $1
        FILE=$1;
   
        # Get total line count
        TOTAL=$(wc -l "$1" | awk '{print $1}');
   
        # Get counts of different return codes
        COUNT_200=$(grep 'Status' "$1" | grep -c 200);
        COUNT_201=$(grep 'Status' "$1" | grep -c 201);
        COUNT_202=$(grep 'Status' "$1" | grep -c 202);
        COUNT_204=$(grep 'Status' "$1" | grep -c 204);
        COUNT_307=$(grep 'Status' "$1" | grep -c 307);
        COUNT_308=$(grep 'Status' "$1" | grep -c 308);
        COUNT_400=$(grep 'Status' "$1" | grep -c 400);
        COUNT_401=$(grep 'Status' "$1" | grep -c 401);
        COUNT_403=$(grep 'Status' "$1" | grep -c 403);
        COUNT_405=$(grep 'Status' "$1" | grep -c 405);
        COUNT_500=$(grep 'Status' "$1" | grep -c 500);
        COUNT_501=$(grep 'Status' "$1" | grep -c 501);
        COUNT_502=$(grep 'Status' "$1" | grep -c 502);
        COUNT_503=$(grep 'Status' "$1" | grep -c 503);
   
        # Write return code counts to top of file
        echo -e "$GREEN""Number of 200 responses:\\t$BLUE $COUNT_200" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 201 responses:\\t$BLUE $COUNT_201" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 202 responses:\\t$BLUE $COUNT_202" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 204 responses:\\t$BLUE $COUNT_204" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 307 responses:\\t$BLUE $COUNT_307" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 308 responses:\\t$BLUE $COUNT_308" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 400 responses:\\t$BLUE $COUNT_400" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 401 responses:\\t$BLUE $COUNT_401" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 403 responses:\\t$BLUE $COUNT_403" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 405 responses:\\t$BLUE $COUNT_405" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 500 responses:\\t$BLUE $COUNT_500" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 501 responses:\\t$BLUE $COUNT_501" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 502 responses:\\t$BLUE $COUNT_502" >> "$FILE"-parsed;
        echo -e "$GREEN""Number of 503 responses:\\t$BLUE $COUNT_503" >> "$FILE"-parsed;
   
        if [[ "$TOTAL" -gt 1000 ]]; then
                echo -e "$GREEN""False positives:\\t\\t$RED Likely! Total count is $TOTAL.""$NC" >> "$FILE"-parsed;
        else
                echo -e $"$GREEN""False positives:\\t\\t$BLUE Unlikely. Total count is $TOTAL.""$NC" >> "$FILE"-parsed;
        fi  
        echo -e "\\n\\n\\n" >> "$FILE"-parsed;
   
        # Echo all parsed output to file
        grep -v '::' "$1" | grep 'Status' >> "$FILE"-parsed;
}
function run_ffuf() {
		# Trap SIGINT so broken ffuf runs can be cancelled
		trap cancel SIGINT;

		# Call with domain as $1, wordlist size as $2, and domain list as $3
		if [[ $3 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running ffuf against all $(wc -l "$3" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: ffuf -u $HTTP://$DOMAIN/FUZZ -w $2 -sf -se -fc 301,302,404,400,500 -k | tee $WORKING_DIR/ffuf.""$NC";
				# Run ffuf
				mkdir "$WORKING_DIR"/ffuf;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$FFUF" -u "$HTTP"://"$ADOMAIN"/FUZZ -w "$2" -timeout 3 -sf -se -fc 301,302,404,400,500 -k -mc all | tee "$WORKING_DIR"/ffuf/"$ADOMAIN".txt;
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE ffuf took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running ffuf against all $(wc -l "$3" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: ffuf -u $HTTP://$DOMAIN/FUZZ -w $2 -sf -se -fc 301,302,404,400,500 -k | tee $WORKING_DIR/ffuf.""$NC";
				# Run ffuf
				mkdir "$WORKING_DIR"/ffuf;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$FFUF" -u "$HTTP"://"$ADOMAIN"/FUZZ -w "$2" -timeout 3 -sf -se -fc 301,302,404,400,500 -k -mc all | tee "$WORKING_DIR"/ffuf/"$ADOMAIN".txt;
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE ffuf took $DIFF seconds to run.""$NC";
		fi

		# Parse results for better readability of the output
		for file in "$WORKING_DIR"/ffuf/*; do
				COUNT=$(wc -l "$file" | awk '{print $1}');
				# No output files have 17 lines
				if [[ $COUNT -gt 17 ]]; then
						parse_ffuf "$file";
				fi
		done
}
function run_dirsearch() {
		# Trap SIGINT so broken dirsearch runs can be cancelled
		trap cancel SIGINT;

		# Call with domain as $1, wordlist size as $2, and domain list as $3
		if [[ $3 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running dirsearch against all $(wc -l "$3" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: dirsearch -u $DOMAIN -e php,aspx,asp -t 20 -x 310,302,404 -F --plain-text-report=$WORKING_DIR/dirsearch/$DOMAIN.txt -w $2""$NC";
				# Run dirsearch
				mkdir "$WORKING_DIR"/dirsearch;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$DIRSEARCH" -u "$HTTP"://"$ADOMAIN" -e php,aspx,asp -t 20 -x 301,302,404 -F --plain-text-report="$WORKING_DIR"/dirsearch/"$ADOMAIN".txt -w "$2";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Dirsearch took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running dirsearch against all $(wc -l "$3" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: dirsearch -u $DOMAIN -e php,aspx,asp -t 20 -x 301,302,404 -F --plain-text-report=$WORKING_DIR/dirsearch/$DOMAIN.txt -w $2""$NC";
				# Run dirsearch
				mkdir "$WORKING_DIR"/dirsearch;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$DIRSEARCH" -u "$HTTP"://"$ADOMAIN" -e php,aspx,asp -t 20 -x 301,302,404 -F --plain-text-report="$WORKING_DIR"/dirsearch/"$ADOMAIN".txt -w "$2";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Dirsearch took $DIFF seconds to run.""$NC";
		fi
}
function run_snallygaster() {
		# Call with domain as $1, wordlist size as $2, and domain list as $3
		if [[ $3 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running snallygaster against all $(wc -l "$3" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: snallygaster $DOMAIN -d --nowww | tee $WORKING_DIR/snallygaster/$ADOMAIN""$NC";
				# Run snallygaster
				mkdir "$WORKING_DIR"/snallygaster;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$SNALLY" "$ADOMAIN" -d --nowww # | tee "$WORKING_DIR"/snallygaster/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Snallygaster took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running dirsearch against all $(wc -l "$3" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: snallygaster $DOMAIN -d --nowww | tee $WORKING_DIR/snallygaster/$ADOMAIN""$NC";
				# Run snallygaster
				mkdir "$WORKING_DIR"/snallygaster;
				COUNT=$(wc -l "$3" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$SNALLY" "$ADOMAIN" -d --nowww  #| tee "$WORKING_DIR"/snallygaster/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$3"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Snallygaster took $DIFF seconds to run.""$NC";
		fi
}
function run_inception() {
		# Trap SIGINT so broken inception runs can be cancelled
		trap cancel SIGINT;

		# Call with domain as $1, wordlist size as $2, and domain list as $3
		if [[ $3 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running inception against all $(wc -l "$3" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: inception -d all_discovered_domains -v | tee $WORKING_DIR/inception""$NC";
				# Run inception
				mkdir "$WORKING_DIR"/inception;
				START=$(date +%s);
				"$INCEPTION" -d "$3" -v -provider wordlists/provider.json | tee "$WORKING_DIR"/inception/inception-output.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Inception took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running inception against all $(wc -l "$3" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: inception -d interesting_domains.txt -v | tee $WORKING_DIR/inception""$NC";
				# Run inception
				mkdir "$WORKING_DIR"/inception;
				START=$(date +%s);
				"$INCEPTION" -d "$3" -v -provider wordlists/provider.json | tee "$WORKING_DIR"/inception/inception-output.txt;

				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Inception took $DIFF seconds to run.""$NC";
		fi
}
function run_waybackurls() {
		# Call with domain as $1
		echo -e "$GREEN""[i]$BLUE Running waybackurls against $DOMAIN.""$NC";
		echo -e "$GREEN""[i]$BLUE Command: waybackurls $DOMAIN | tee $WORKING_DIR/waybackurls-output.txt""$NC";
		# Run waybackurls
		START=$(date +%s);
		"$WAYBACKURLS" "$DOMAIN" | tee "$WORKING_DIR"/waybackurls-output.txt;
		END=$(date +%s);
		DIFF=$(( END - START ));
		echo -e "$GREEN""[i]$BLUE Waybackurls took $DIFF seconds to run.""$NC";
}
function run_content_discovery() {
  run_inception "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_waybackurls "$DOMAIN";
  run_ffuf "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_gobuster "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_dirsearch "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";            
}
function run_bfac() {
		# Call with domain list as $1
		if [[ $1 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running bfac against all $(wc -l "$1" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: bfac -u $DOMAIN -xsc 301,302,404 --threads 30 -o $WORKING_DIR/bfac.""$NC";
				# Run bfac
				mkdir "$WORKING_DIR"/bfac;
				COUNT=$(wc -l "$1" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						$BFAC -u "$ADOMAIN" -xsc 301,302,404 --threads 30 -o "$WORKING_DIR"/bfac/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$1"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE bfac took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running bfac against all $(wc -l "$1" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: bfac -u $DOMAIN -xsc 301,302,404 --threads 30 -o $WORKING_DIR/bfac.""$NC";
				# Run bfac
				mkdir "$WORKING_DIR"/bfac;
				COUNT=$(wc -l "$1" | awk '{print $1}')
				START=$(date +%s);
				while read -r ADOMAIN; do
						$BFAC -u "$ADOMAIN" -xsc 301,302,404 --threads 30 -o "$WORKING_DIR"/bfac/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$1"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE bfac took $DIFF seconds to run.""$NC";
		fi
}
function run_nikto() {
		# Call with domain list as $1
		# If httprobe was enabled, use its results instead
		if [[ "$ENABLE_HTTPROBE" == 1 ]]; then
				if [[ -e "$WORKING_DIR"/httprobe-out.txt ]]; then
						echo -e "$GREEN""[i]$BLUE Running nikto against all $(wc -l "$WORKING_DIR"/httprobe-out.txt | awk '{print $1}') httprobe discovered domains.""$NC";
						echo -e "$GREEN""[i]$BLUE Command: nikto -h $HTTP://$DOMAIN -Format html -output $WORKING_DIR/nikto.""$NC";
						# Run nikto
						COUNT=$(wc -l "$WORKING_DIR"/httprobe-out.txt | awk '{print $1}')
						mkdir "$WORKING_DIR"/nikto;
						START=$(date +%s);
						while read -r ADOMAIN; do
								TRIMMED=$(echo "$ADOMAIN" | tr -d '/');
								"$NIKTO" -h "$ADOMAIN" -Format html -output "$WORKING_DIR"/nikto/"$TRIMMED".html;
								COUNT=$((COUNT - 1));
								if [[ "$COUNT" != 0 ]]; then
										echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
								fi
						done < "$WORKING_DIR"/httprobe-out.txt
						END=$(date +%s);
						DIFF=$(( END - START ));
						echo -e "$GREEN""[i]$BLUE Nikto took $DIFF seconds to run.""$NC";
						return;
				fi
		elif [[ $1 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running nikto against all $(wc -l "$1" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: nikto -h $HTTP://$DOMAIN -Format html -output $WORKING_DIR/nikto.""$NC";
				# Run nikto
				COUNT=$(wc -l "$1" | awk '{print $1}')
				mkdir "$WORKING_DIR"/nikto;
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$NIKTO" -h "$HTTP"://"$ADOMAIN" -Format html -output "$WORKING_DIR"/nikto/"$ADOMAIN".html;
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$1"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Nikto took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running nikto against all $(wc -l "$1" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: nikto -h $HTTP://$DOMAIN -Format html -output $WORKING_DIR/nikto.""$NC";
				# Run nikto
				COUNT=$(wc -l "$1" | awk '{print $1}')
				mkdir "$WORKING_DIR"/nikto;
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$NIKTO" -h "$HTTP"://"$ADOMAIN" -Format html -output "$WORKING_DIR"/nikto/"$ADOMAIN".html;
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$1"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE Nikto took $DIFF seconds to run.""$NC";
		fi
}
function run_whatweb() {
		# Call with domain as $1 and domain list as $2
		if [[ $2 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running whatweb against all $(wc -l "$2" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: whatweb -v -a 3 -h $HTTP://$DOMAIN | tee $WORKING_DIR/whatweb.""$NC";
				# Run whatweb
				COUNT=$(wc -l "$2" | awk '{print $1}')
				mkdir "$WORKING_DIR"/whatweb;
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$WHATWEB" -v -a 3 "$HTTP"://"$ADOMAIN" | tee "$WORKING_DIR"/whatweb/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$2"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE whatweb took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running whatweb against all $(wc -l "$2" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: whatweb -v -a 3 -h $HTTP://$DOMAIN | tee $WORKING_DIR/whatweb.""$NC";
				# Run whatweb
				COUNT=$(wc -l "$2" | awk '{print $1}')
				mkdir "$WORKING_DIR"/whatweb;
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$WHATWEB" -v -a 3 "$HTTP"://"$ADOMAIN" | tee "$WORKING_DIR"/whatweb/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$2"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE whatweb took $DIFF seconds to run.""$NC";
		fi
}
function run_wafw00f() {
		# Call with domain as $1 and domain list as $2
		if [[ $2 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running wafw00f against all $(wc -l "$2" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: wafw00f $HTTP://$1 -a | tee $WORKING_DIR/wafw00f.""$NC";
				# Run wafw00f
				COUNT=$(wc -l "$2" | awk '{print $1}')
				mkdir "$WORKING_DIR"/wafw00f;
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$WAFW00F" "$HTTP"://"$ADOMAIN" -a | tee "$WORKING_DIR"/wafw00f/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$2"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE wafw00f took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running wafw00f against all $(wc -l "$2" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: wafw00f $HTTP://$1 -a | tee $WORKING_DIR/wafw00f.""$NC";
				# Run wafw00f
				COUNT=$(wc -l "$2" | awk '{print $1}')
				mkdir "$WORKING_DIR"/wafw00f;
				START=$(date +%s);
				while read -r ADOMAIN; do
						"$WAFW00F" "$HTTP"://"$ADOMAIN" -a | tee "$WORKING_DIR"/wafw00f/"$ADOMAIN";
						COUNT=$((COUNT - 1));
						if [[ "$COUNT" != 0 ]]; then
								echo -e "$GREEN""[i]$BLUE $COUNT domain(s) remaining.""$NC";
						fi
				done < "$2"
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE wafw00f took $DIFF seconds to run.""$NC";
		fi
}
function run_subjack() {
		# Call with domain as $1 and domain list as $2
		if [[ $2 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running subjack against all $(wc -l "$WORKING_DIR"/$ALL_RESOLVED | awk '{print $1}') unique discovered subdomains to check for subdomain takeover.""$NC";
				echo -e "$GREEN""[i]$ORANGE It will run twice, once against HTTPS and once against HTTP.""$NC";
				echo -e "$GREEN""[i]$ORANGE Command: subjack -d $1 -w $2 -v -t 20 -ssl -m -o $WORKING_DIR/subjack-output.txt""$NC";
				START=$(date +%s);
				"$SUBJACK" -d "$1" -w "$2" -v -t 20 -ssl -m -o "$WORKING_DIR"/subjack-https-output.txt -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json;
				"$SUBJACK" -d "$1" -w "$2" -v -t 20 -m -o "$WORKING_DIR"/subjack-http-output.txt -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json;
				END=$(date +%s);
				DIFF=$(( END - START ));
		else
				echo -e "$GREEN""[i]$BLUE Running subjack against all $(wc -l "$WORKING_DIR"/$ALL_RESOLVED | awk '{print $1}') discovered interesting subdomains to check for subdomain takeover.""$NC";
				echo -e "$GREEN""[i]$ORANGE It will run twice, once against HTTPS and once against HTTP.""$NC";
				echo -e "$GREEN""[i]$ORANGE Command: subjack -d $1 -w $2 -v -t 20 -ssl -m -o $WORKING_DIR/subjack-output.txt""$NC";
				START=$(date +%s);
				"$SUBJACK" -d "$1" -w "$2" -v -t 20 -ssl -m -o "$WORKING_DIR"/subjack-https-output.txt -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json;
				"$SUBJACK" -d "$1" -w "$2" -v -t 20 -m -o "$WORKING_DIR"/subjack-http-output.txt -c "$HOME"/go/src/github.com/haccer/subjack/fingerprints.json;
				END=$(date +%s);
				DIFF=$(( END - START ));
		fi

		echo -e "$GREEN""[i]$BLUE Subjack took $DIFF seconds to run.""$NC";
		echo -e "$GREEN""[i]$ORANGE Full Subjack results are at $WORKING_DIR/subjack-output.txt.""$NC";
		sleep 1;
}
function run_corstest() {
		# Call with domain as $1 and domain list as $2
		if [[ $2 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running CORStest against all $(wc -l "$2" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: corstest.py $2 -v -p 64 | tee $WORKING_DIR/CORStest-output.txt.""$NC";
				# Run CORStest
				START=$(date +%s);
				"$CORSTEST" "$2" -v -p 64 | tee "$WORKING_DIR"/CORStest-output.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE CORStest took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running CORStest against all $(wc -l "$2" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: corstest.py $2 -v -p 64 | tee $WORKING_DIR/CORStest-output.txt.""$NC";
				# Run CORStest
				START=$(date +%s);
				"$CORSTEST" "$2" -v -p 64 | tee "$WORKING_DIR"/CORStest-output.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE CORStest took $DIFF seconds to run.""$NC";
		fi
}
function run_s3scanner() {
		# Call with domain as $1 and domain list as $2
		if [[ $2 == $WORKING_DIR/$ALL_RESOLVED ]]; then
				echo -e "$GREEN""[i]$BLUE Running S3Scanner against all $(wc -l "$2" | awk '{print $1}') unique discovered domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: s3scanner.py ""$NC";
				# Run S3Scanner
				START=$(date +%s);
				python "$S3SCANNER" "$2" -d -l -o "$WORKING_DIR"/s3scanner-output.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE S3Scanner took $DIFF seconds to run.""$NC";
		else
				echo -e "$GREEN""[i]$BLUE Running S3Scanner against all $(wc -l "$2" | awk '{print $1}') discovered interesting domains.""$NC";
				echo -e "$GREEN""[i]$BLUE Command: s3scanner.py ""$NC";
				# Run S3Scanner
				START=$(date +%s);
				python "$S3SCANNER" "$2" -d -l -o "$WORKING_DIR"/s3scanner-output.txt;
				END=$(date +%s);
				DIFF=$(( END - START ));
				echo -e "$GREEN""[i]$BLUE S3Scanner took $DIFF seconds to run.""$NC";
		fi
}
function run_information_gathering() {
  # Ask user to do information gathering on discovered domain
  run_subjack "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_corstest "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_s3scanner "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_bfac "$WORKING_DIR"/"$ALL_RESOLVED";
  run_whatweb "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_wafw00f "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
  run_httprobe;
  run_nikto "$WORKING_DIR"/"$ALL_RESOLVED";
}
function run_notica() {
		# Call Notica to signal end of script, $1 is for the domain
		echo -e "$BLUE""Sending Notica notification.""$NC";
		curl --data "d:Chomp Scan has finished scanning $1." "https://notica.us/?$NOTICA";
}
function run_notica_sudo() {
		# Call Notica to alert that sudo is needed for masscan
		echo -e "$ORANGE""Sending Notica notification that sudo is needed.""$NC";
		# curl --data "d:Chomp Scan Notification: Your sudo password is needed for masscan." "https://notica.us/?$NOTICA";
}
function run_rescope() {
		echo -e "$BLUE""[i] Creating a Burp scope file with rescope.""$NC";
		
		# Make sure resolved domains exists
		if [[ $(wc -l "$WORKING_DIR"/"$ALL_RESOLVED" | awk '{print $1}') -gt 0 ]]; then
				"$RESCOPE" --burp -i "$WORKING_DIR"/"$ALL_RESOLVED" -o "$WORKING_DIR"/burp-scope.json -s;
		fi
}
#### Begin main script functions
# Check tool paths are set
check_paths;

# Check if -u domain was passed
if [[ "$DOMAIN" == "" ]]; then
		echo -e "$RED""[!] A domain is required: -u example.com""$NC";
		usage;
		exit 1;
fi
SCAN_START=$(date +%s);
WORKING_DIR="/opt/target/$DOMAIN"-$(date +%T);
touch "$WORKING_DIR"/"$ALL_DOMAIN";
touch "$WORKING_DIR"/"$ALL_IP";
touch "$WORKING_DIR"/"$ALL_RESOLVED";

if [[ "$DEFAULT_MODE" -eq 1 ]]; then
		# Check if we're root since we're running masscan
		check_root;

		# Run all phases with defaults
		echo -e "$GREEN""Beginning non-interactive mode scan.""$NC";
		sleep 0.5;

		run_dnscan "$DOMAIN" "$SHORT";
		run_subfinder "$DOMAIN" "$SHORT";
		run_sublist3r "$DOMAIN";
		run_knock "$DOMAIN" "$SHORT";
		run_amass "$DOMAIN" "$SHORT";
		run_massdns "$DOMAIN" "$SHORT";
		run_httprobe;

		# Call unique to make sure list is up to date for content discovery
		unique;

		run_aquatone "default";
		run_masscan;
		run_nmap;
		run_subjack "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_corstest "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_s3scanner "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_bfac "$WORKING_DIR"/"$ALL_RESOLVED";
		run_httprobe;
		run_nikto "$WORKING_DIR"/"$ALL_RESOLVED";
		run_whatweb "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_wafw00f "$DOMAIN" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_inception "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_waybackurls "$DOMAIN";
		run_ffuf "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_gobuster "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
		run_dirsearch "$DOMAIN" "$SMALL" "$WORKING_DIR"/"$ALL_RESOLVED";
		get_interesting;
		list_found;
		run_rescope;

		# Calculate scan runtime
		SCAN_END=$(date +%s);
		SCAN_DIFF=$(( SCAN_END - SCAN_START ));
		if [[ "$NOTICA" != "" ]]; then
				run_notica "$DOMAIN";
		fi
		echo -e "$BLUE""[i] Total script run time: $SCAN_DIFF seconds.""$NC";
		
		exit;
fi
# Calculate scan runtime
SCAN_END=$(date +%s);
SCAN_DIFF=$(( SCAN_END - SCAN_START ));

if [[ "$NOTICA" != "" ]]; then
		run_notica "$DOMAIN";
fi

echo -e "$BLUE""[i] Total script run time: $SCAN_DIFF seconds.""$NC";

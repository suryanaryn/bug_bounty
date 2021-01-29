# ~/.bashrc: executed by bash(1) for non-login shells.
export LS_OPTIONS='--color=auto'
alias l='ls $LS_OPTIONS -lA'
alias rm='rm -rf'
alias cp='cp -r'
alias sp='source ~/.bashrc'
alias ep='codee ~/.bashrc'

nipe(){
cd /opt/extra/nipe
sudo perl nipe.pl $1
}

codee(){
code $1 --user-data-dir=".vscode" 

}
burp(){
cd /opt/attack/Burpsuite
java --illegal-access=permit -Dfile.encoding=utf-8 -javaagent:BurpSuiteLoader_v2020.9.2.jar -noverify -jar burpsuite_pro_v2020.9.2.jar
}

hunt(){
cd /opt/bug_hunter
./bug_hunter.sh $1 $2 $3
}

ipinfo(){
curl ipinfo.io/$1
}

digit(){
dig @8.8.8.8 $1 CNAME
}
#export GOROOT=/usr/share/go
#export GOPATH=/root/go
#export PATH=$GOPATH/bin:$GOROOT/bin:$PATH
#source $GOPATH/src/github.com/tomnomnom/gf/gf-completion.bash

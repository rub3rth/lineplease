
  
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

oneliners from [PayloadAllTheThings](https://github.com/swisskyrepo/PayloadsAllTheThings)


for reverse shell line:<br>
usage: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;./lineplease [options] [interface] [port]<br>
example: &nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;	./lineplease -b eth0 1337<br>

ipv4-address on desired interface is inserted into line<br>
for public ip specify interface as 'pub'

when prompted:<br>  y to copy line to clipboard or any other key to continue (requires xsel)<br>
		y to start netcat listener or any other key to exit

for msfvenom (requires msfvenom):<br>
usage:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;./lineplease [options] [interface] [port] [name]<br>
example:&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;./lineplease -m2 tun0 1337 rev<br>

when prompted:<br> 	y to create file or any other key to exit

-h :&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;&nbsp;		options

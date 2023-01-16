#!/bin/bash
# You are NOT allowed to change the files' names!
domainNames="domainNames.txt"
domainNames2="domainNames2.txt"
IPAddressesSame="IPAddressesSame.txt"
IPAddressesDifferent="IPAddressesDifferent.txt"
adblockRules="adblockRules"
iptable="/sbin/iptables"

function adBlock() {
    
    if [ "$EUID" -ne 0 ];then
        printf "Please run as root.\n"
        exit 1
    fi
    if [ "$1" = "-domains"  ]; then
 IPT=/sbin/iptables
        # Find different and same domains in ‘domainNames.txt’ and ‘domainsNames2.txt’ files 
  grep -Fw  -f domainNames.txt domainNames2.txt > temp1.txt #make a temp file to put the same domain name inside
  grep -Fwv  -f domainNames.txt domainNames2.txt > temp2.txt
  grep -Fwv  -f domainNames2.txt domainNames.txt >> temp2.txt
#make a temp file to put the different domain name inside
	# and write them in “IPAddressesDifferent.txt and IPAddressesSame.txt" respectively
        i=0;
        while read domain1 
        do
       ((i=i+1))

        host -W 1 $domain1 | awk '/has address/ { print $4 }'&>>IPAddressesSame.txt #take only  ipv4 addresses  and store it in the IPAddressesSame.txt file the -W 1 is for run faster
       p[${i}]=$!
        
        
        done <temp1.txt 





       
       while read domain2
        do
       ((i=i+1))
        host -W 1 $domain2 | awk '/has address/ { print $4 }'&>>IPAddressesDifferent.txt #take only  ipv4 addresses  and store it in the IPAddressesDifferent.txt file The-W 1 is for run faster
        p[${i}]=$!
        
        
        done <temp2.txt &
         for pid in ${p[*]}; do
          wait $pid
           done
       if [[ "$?" -eq "0" ]]; then
             echo " DOMAIN ADDR NAME TO IP SET SUCCESSFULLY..."
          else 
            echo "SOMTHING IS WRONG..."
          fi
         rm temp1.txt #remove tempfile
         rm temp2.txt #remove  tempfile
         true
    elif [ "$1" = "-ipssame"  ]; then
        # Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.
        ip_file=$IPAddressesSame
        while read ip || [[ -n "$ip" ]];
        do
        sudo "$iptable" -A INPUT -s "$ip" -j DROP # block a connection through a specific interface
        sudo "$iptable" -A FORWARD -s "$ip" -j DROP #Blocks all forwarding traffic
        sudo "$iptable" -A OUTPUT -s "$ip" -j DROP #Prevent the connection with the server especially for the tcp and blocks outgoing traffic
      
        done < ${ip_file}&
         p=$!
        wait $p
       if [[ "$?" -eq "0" ]]; then
             echo " DROP RULES SET SUCCESSFULLY..."
          else 
            echo "SOMTHING IS WRONG..."
          fi
        true
    elif [ "$1" = "-ipsdiff"  ]; then
        # Configure the REJECT adblock rule based on the IP addresses of $IPAddressesDifferent file.
        ip_file=$IPAddressesDifferent
        while read ip || [[ -n "$ip" ]];
        do
        #You use reject when you want the other end to know the port or IP is unreachable
        sudo "$iptable" -A INPUT -s "$ip" -j REJECT 
        sudo "$iptable" -A FORWARD -s "$ip" -j REJECT 
        sudo "$iptable" -A OUTPUT -d "$ip" -j REJECT 
      
        done < ${ip_file}&
         p=$!
        wait $p
       if [[ "$?" -eq "0" ]]; then
             echo " REJECT RULES SET SUCCESSFULLY..."
          else 
            echo "SOMTHING IS WRONG..."
          fi
        true
        
    elif [ "$1" = "-save"  ]; then
        # Save rules to $adblockRules file.
          sudo iptables-save > adblockRules
        true
        
    elif [ "$1" = "-load"  ]; then
        # Load rules from $adblockRules file.
        sudo iptables-save < adblockRules
        true

        
    elif [ "$1" = "-reset"  ]; then
        # Reset rules to default settings (i.e. accept all).
         # you will set accept rule for all types of connections.
        "$iptable" -P INPUT ACCEPT
        "$iptable" -P OUTPUT ACCEPT
        "$iptable" -P FORWARD ACCEPT
        
         #delete your currently configured rules from iptables.
        "$iptable" -F INPUT 
        "$iptable" -F OUTPUT 
        "$iptable" -F FORWARD
        true

        
    elif [ "$1" = "-list"  ]; then
        # List current rules.
        sudo iptables -L -v -n 
        true
        
    elif [ "$1" = "-help"  ]; then
        printf "This script is responsible for creating a simple adblock mechanism. It rejects connections from specific domain names or IP addresses using iptables.\n\n"
        printf "Usage: $0  [OPTION]\n\n"
        printf "Options:\n\n"
        printf "  -domains\t  Configure adblock rules based on the domain names of '$domainNames' file.\n"
        printf "  -ipssame\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesSame file.\n"
	printf "  -ipsdiff\t\t  Configure the DROP adblock rule based on the IP addresses of $IPAddressesDifferent file.\n"
        printf "  -save\t\t  Save rules to '$adblockRules' file.\n"
        printf "  -load\t\t  Load rules from '$adblockRules' file.\n"
        printf "  -list\t\t  List current rules.\n"
        printf "  -reset\t  Reset rules to default settings (i.e. accept all).\n"
        printf "  -help\t\t  Display this help and exit.\n"
        exit 0
    else
        printf "Wrong argument. Exiting...\n"
        exit 1
    fi
}

adBlock $1
exit 0

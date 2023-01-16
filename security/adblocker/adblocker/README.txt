 
 Tsimpirdoni Aikaterini 2018030013 
 The first option is -domains. First of all, it uses the grep -Fw -f  to compare the 2 files (domainNames,domainNames2) this command takes the names that exist in both files and store them in temp1.txt.After I use again the command greps with -Fwv  -f and compare the 2 files and take the names that do not match in both files and store them in a file temp2.txt.
With the command, read take from the text file( temp1.txt) the domain names, and with the command host converts the domain names to IP addresses. The -W specifies how long to wait for a reply, this is to make the program run faster because don't wait too long to take a reply, and then it stores the IP addresses in the IPAddressesSame.txt file. 
host -W 1 $domain2 | awk '/has address/ { print $4 }'&>>IPAddressesDifferent.txt.
The command awk is for taking only the IP address and not all the information.
The temp2.txt do the same thing but the addresses are stored in the IPAddressesDifferent.txt .
After that, I use the command (& ) to force the command to run in the background, and then I use the wait to 
 suspend the execution until the subprocesses have finished. The process takes about two minutes to finish. Then rm the temp files (temp1.txt,temp2.txt).
 The second option is the -ipssame that configures the drop Adblock rules with commands like sudo "$iptable" -A INPUT -s "$ip" -j DROP  that it uses to block a connection through a specific interface with the ips that exist in the file IPAddressesSame.txt.The INPUT command is the main but it has to the command "sudo "$iptable" -A FORWARD -s "$ip" -j DROP" that blocks all forwarding traffic and "Sudo "$iptable" -A OUTPUT -s "$ip" -j DROP" that prevents the connection with the server. These are the three drop rules.
 Then, it exists the option -ipsdiff for the ips in the file IPAddressesDifferent.txt the program configures the reject Adblock rules which is almost the same thing as the drop rules but we use reject when you want the other end to know the port or IP is unreachable. The command is almost the same as the drop rules but they have to reject instead of drop.
 The -save and the -load uses the command sudo iptables-save with > to save in the  adblockRules.txt and < to load from file to terminal.
 -reset option, reset rules to default so use the accept command to accept the rules for all connections, and then delete all the rules that I configure above. The deletion becomes with the "$iptable" -F.
 the command list is a simple  bash command to list the rules sudo iptables -L -v -n.-L for List the rules in a chain or all chains -n numeric output of addresses and ports and -v verbose mode.

 how to run:
 sudo bash AdBlock.sh -<options>
 
 test: After configuring the AdBlock rules  I test my script by visiting some site like www.news247.gr I see that it block some of the advertisements like the advertisement of bet365 that the domain name (imstore.bet365affiliates.com ) that exist in the domainname txt file that is given.

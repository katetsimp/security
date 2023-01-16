First of all, To compile the program run:
make
to run the program:
on your device first, find the interface with: cat /proc/net/wireless
and the run: 
sudo ./pcap_ex -i <interface name>
and with the filter you can run for example:
sudo ./pcap_ex -i <interface name> -f "port 80"
to run with file:
./pcap_ex -r <filename>
and ./pcap_ex -h for help

in the main process we have two functions :
onlineMode for handling the device packets.
offline to handle the file packets.
onlineMode: firstly it asks the user to put the number of packets that wants to capture and open a file in write mode to put later the package info. After, it gets the network number and mask associated with the capture device and opens it. (if we have a filter we have a variable fltstr that contains the filter expression. if we don't have a filter this variable contains an empty string). After that, we compile the filter and apply it and call a function named pcap_loop that opens a handle the packets.

offline: It is the same thing as the previous one but we call pcap_open_offline instead of pcap_open_live that use above and it doesn't have a filter. Also, don't ask the user about the packet number and don't have an open file because the packet info is printed in the terminal. Then call also pcap_loop that opens a handle the packets.
To handle these packets I have handle_packet function that decodes each received packet and determines the traffic type(ipv4 or ipv6) and protocol type(UDP or TCP). This function contains the function is_retrasIPV4(that concerns only TCP) which checks if the packet is retransmitted. Also, it contains make_flowIPV4 that constructs flows, and then with flow_check, it sees if the flow is in the list and if not put it in the list with list_of_flows function that helps to count the flows. Finally, we have functions to print or put the packet in the file (print_characteristicIPV4,print_tcp,print_udp).
the same exact functions we have for ipv6(make_flowIPV6,print_characteristicIPV6, is_retrasIPV6).
The UDP packets don't have retransmission. The TCP package has retransmission when the data packets have been lost. That means that a packet maybe sent to the receiver, but no acknowledgment is received within that timeout period. When the timeout period expires, then the packet is resent again. Another scenario is when the packet is sent, but due to a delay in acknowledgment or timeout has occurred before the actual timeout or when the packet is received but the acknowledgment is lost.

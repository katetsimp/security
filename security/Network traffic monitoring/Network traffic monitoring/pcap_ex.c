#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <pcap.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/socket.h>
#include <string.h>
#include </usr/include/netinet/ip.h>    //ipv4 protocols
#include </usr/include/netinet/ip6.h>   //ipv6 protocols
#include <netinet/tcp.h>                //tcp header declarations
#include <netinet/udp.h>                //udp header declarations
#include <net/ethernet.h>               //ethernet fundamental onstants
#include <arpa/inet.h>
#define FLTRSZ 120
#define INTERFACESZ 30


//struct for the  flows
struct flow{
char *sourceIP;
char *destinationIP;
uint16_t source_port;
uint16_t destination_port;
uint8_t protocol;
int curr_seq_num;
int next_seq_num;
struct flow *nextf;
};
//function declaration
void print_characteristicIPV4(char*,char*);
void print_characteristicIPV6(char*,char*);
void print_tcp(u_int ,u_int ,int ,char*,int );
void print_udp(const u_char*,int*);
void  handle_packet(u_char *, const struct pcap_pkthdr *, const u_char *);
int is_retrasIPV4(struct flow *,const u_char *,const struct tcphdr* ,char *);
int is_retrasIPV6(struct flow *,const u_char *,const struct tcphdr* ,char *);
struct flow*make_flowIPV4(const struct tcphdr*,char *);
struct flow*make_flowIPV6(const struct tcphdr*,char *);
struct flow* list_of_flows(struct flow *, struct flow *);
int flow_check(struct flow *, struct flow *);
void usage();
//global variables

int headerLength = 0;       //packet header length
char  lbuff[5000]={0};
FILE *fptr=NULL;
//ipv4 source and destination
char sourceIp4[INET_ADDRSTRLEN];
char destinationIp4[INET_ADDRSTRLEN];
char sourIP6[INET6_ADDRSTRLEN];  //source address
char destIP6[INET6_ADDRSTRLEN];  //destination address
u_int sourPort, destPort;  //source and destination port number
int protocol;
u_char* filter_exp;     /* bpf filter string */
char fltstr[FLTRSZ];
struct flow *flows = NULL;
//counters

long int countertcp=0;
long int counterupd=0;
long int packet_counter = 0; //packet number
long int flowsUDPNum=0;
long int flowsTCPNum=0;
long int unknownnum=0;
long int bytesTCP=0;
long int bytesUDP=0;

//packet handler for ipversion and protocols
void  handle_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet){
const struct ether_header *ethernet_header; //ethernet header
const struct ip *ipv4_header;               //ipv4 header
const struct ip6_hdr *ipv6_header;          //ipv6 header

int is_Retransmitted=0;
headerLength=header->len;
packet_counter++;
//define ethernet header
ethernet_header=(struct ether_header*)(packet);
//get etherent header size
int size = 0;
size += sizeof(struct ether_header);
//determine the traffic and the protocol type
uint16_t s=ntohs(ethernet_header->ether_type);
//IPV4 CASE
if(s==ETHERTYPE_IP){
ipv4_header=(struct ip*)(packet+size);
//get the dest and the source as string
inet_ntop(AF_INET,&(ipv4_header->ip_src),sourceIp4,INET_ADDRSTRLEN);
inet_ntop(AF_INET,&(ipv4_header->ip_dst),destinationIp4,INET_ADDRSTRLEN);
size += sizeof(struct ip);


//Decode each received packet
//now the  protocol
//tcp
protocol=ipv4_header->ip_p;
if(ipv4_header->ip_p==IPPROTO_TCP){
countertcp++;
const struct tcphdr* tcp_header;

char *payload;           //payload
int dataLength = 0;
tcp_header = (struct tcphdr*)(packet + *&size);
//get source and destination port number
    sourPort = ntohs(tcp_header->source);
    destPort = ntohs(tcp_header->dest);
    //get payload
 *&size += tcp_header->doff*4;
 payload = (char*)(packet + *&size);
 dataLength = headerLength - *&size;
  bytesTCP+=dataLength;
  is_Retransmitted=is_retrasIPV4(flows,packet,tcp_header,payload);
 if(!is_Retransmitted)
 {

 struct flow*new_flow=make_flowIPV4(tcp_header,payload);
 //check if the flow is in the list
 if(!flow_check(flows,new_flow))
 { flowsTCPNum++;
 
 flows=list_of_flows(flows,new_flow);
 }
 }
print_characteristicIPV4(sourceIp4,destinationIp4);
print_tcp( sourPort,destPort,dataLength,payload,is_Retransmitted);


}
//udp
else if(ipv4_header->ip_p==IPPROTO_UDP){
counterupd++;
struct flow*new_flow=make_flowIPV4(NULL,"0");
//check if the flow is in the list
 if(!flow_check(flows,new_flow))
 {
 flowsUDPNum++;
 
 flows=list_of_flows(flows,new_flow);
 }
 print_characteristicIPV4(sourceIp4,destinationIp4);
 print_udp(packet,&size);
}else{
struct flow*new_flow=make_flowIPV4(NULL,"0");
//check if the flow is in the list
 if(!flow_check(flows,new_flow))
 {
 unknownnum++;
 
 flows=list_of_flows(flows,new_flow);
 }

}   //ipv6
} else if(s==ETHERTYPE_IPV6){
ipv6_header=(struct ip6_hdr*)(packet + size);
inet_ntop(AF_INET6, &(ipv6_header->ip6_src), sourIP6, INET6_ADDRSTRLEN);
inet_ntop(AF_INET6, &(ipv6_header->ip6_dst), destIP6, INET6_ADDRSTRLEN);
size += sizeof(struct ip6_hdr);

int nextheader = ipv6_header->ip6_nxt;
protocol=nextheader;
//TCP
if(nextheader==IPPROTO_TCP){
countertcp++;
const struct tcphdr* tcp_header;

char *payload;           //payload
int dataLength = 0;
tcp_header = (struct tcphdr*)(packet + *&size);
//get source and destination port number
    sourPort = ntohs(tcp_header->source);
    destPort = ntohs(tcp_header->dest);
  
 *&size += tcp_header->doff*4;
 payload = (char*)(packet + *&size);
 dataLength = headerLength - *&size;
 bytesTCP+=dataLength;
 is_Retransmitted=is_retrasIPV6(flows,packet,tcp_header,payload);
 if(!is_Retransmitted)
 {
 
 struct flow*new_flow=make_flowIPV6(tcp_header,payload);
 //check if the flow is in the list
 if(!flow_check(flows,new_flow))
 {
   flowsTCPNum++;
 flows=list_of_flows(flows,new_flow);
 }
 }
print_characteristicIPV6(sourIP6,destIP6);
print_tcp( sourPort,destPort,dataLength,payload,is_Retransmitted);

}else if(nextheader==IPPROTO_UDP){
counterupd++;
struct flow*new_flow=make_flowIPV6(NULL,"0");
//check if the flow is in the list
 if(!flow_check(flows,new_flow))
 {
 flowsUDPNum++;
 flows=list_of_flows(flows,new_flow);
 }
print_characteristicIPV6(sourIP6,destIP6);
print_udp(packet,&size);
}else{
struct flow*new_flow=make_flowIPV6(NULL,"0");
//check if the flow is in the list
 if(!flow_check(flows,new_flow))
 {
 unknownnum++;
 flows=list_of_flows(flows,new_flow);
 }
}
}
}
void print_characteristicIPV6(char*source,char*dest){
if(fptr!=NULL){

sprintf(lbuff, "\tpacket num: %ld\tIP Type: IPv6\tsourceIP: %s\tdestinationIP: %s\t",packet_counter, source, dest);
}else{
printf("\n");
printf("IP Type: IPv6 \n");
printf("source IP:%s\n",source);
printf("destination IP:%s\n",dest);
printf("packet num:%ld\n",packet_counter);
}
}
void print_characteristicIPV4(char*source,char*dest){
if(fptr!=NULL){
sprintf(lbuff, "\tpacket num: %ld\tIP Type: IPv4\tsourceIP: %s\tdestinationIP: %s\t",packet_counter, source, dest);
}else{
printf("\n");
printf("IP Type: IPv4 \n");
printf("source IP:%s\n",source);
printf("destination IP:%s\n",dest);
printf("packet num:%ld\n",packet_counter);

}


}
void print_tcp(u_int sourPort,u_int destPort,int dataLength,char* payload ,int is_Retransmitted){

if(fptr!=NULL){
sprintf(lbuff + strlen(lbuff),"\tprotocol: TCP\tis_Retransmitted: %d\tSourcePort: %d\tDst port: %d\tPayload: (%d bytes)\theader Length: %d\n",is_Retransmitted,sourPort, destPort,dataLength,headerLength);
fputs(lbuff, fptr);   
memset(lbuff, 0, 5000); 
}else{
  //print out protocol details
    printf("protocol: TCP \n");
    printf("Src port: %d\n", sourPort);
    printf("Dst port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("header Length:%d\n",headerLength);
    printf("is_Retransmitted:%d\n",is_Retransmitted);
    printf("\n");  
    }
    
    
    
   


}
void print_udp(const u_char *packet,int* size){
const struct udphdr* udp_header;
u_int sourPort, destPort;  //source and destination port number

int dataLength = 0;
udp_header = (struct udphdr*)(packet + *size);
//get source and destination port number
    sourPort = ntohs(udp_header->source);
    destPort = ntohs(udp_header->dest);
    //get payload
 *size += sizeof(struct udphdr);
 dataLength = headerLength - *size;
 bytesUDP+=dataLength;
 if(fptr!=NULL){
   sprintf(lbuff + strlen(lbuff),"\tprotocol: UDP\tSourcePort: %d\tDst port: %d\tPayload: (%d bytes)\theader Length: %d\n",sourPort, destPort,dataLength,headerLength);
   fputs(lbuff, fptr);   
   memset(lbuff, 0, 5000); 
   }else{
    //print out protocol details
    printf("protocol: UDP \n");
    printf("Src port: %d\n", sourPort);
    printf("Dst port: %d\n", destPort);
    printf("Payload: (%d bytes) \n", dataLength);
    printf("header Length:%d\n",headerLength);
    printf("\n");

}
}/*forTCP Retransmission:1)This is not a keepalive packet,2)In the forward direction, the segment length is greater than zero or the SYN or FIN flag is set 3)The next expected sequence number is greater than the current sequence number for ipv4*/
int is_retrasIPV4(struct flow *tflow,const u_char *packet,const struct tcphdr* tcp_header,char *payload){
struct flow *curr_flow = tflow;
int n = atoi(payload);
while(curr_flow != NULL)
    {
    if ((strcmp(curr_flow->sourceIP, sourceIp4) == 0) && (strcmp(curr_flow->destinationIP, destinationIp4) == 0) && (curr_flow->source_port == sourPort) && (curr_flow->destination_port == destPort) && (curr_flow->protocol == protocol))
        {
        //a keep alive packet
if ((n <= 1) && (tcp_header->th_flags & (TH_FIN||TH_SYN|| TH_RST)) && ((ntohl(tcp_header->th_seq) - curr_flow->next_seq_num) == -1))
            	return 0; 
    
if (((n > 0) || (tcp_header->th_flags & TH_SYN || TH_FIN)) && ((curr_flow->next_seq_num) > ntohl(tcp_header->th_seq)) )
{
return 1; 
}
      }
    curr_flow = curr_flow->nextf;   
  }
  return 0;
  }
  /*forTCP Retransmission:1)This is not a keepalive packet,2)In the forward direction, the segment length is greater than zero or the SYN or FIN flag is set 3)The next expected sequence number is greater than the current sequence number for ipv6*/
  int is_retrasIPV6(struct flow *tflow,const u_char *packet,const struct tcphdr* tcp_header,char *payload){
struct flow *curr_flow = tflow;
int n = atoi(payload);
while(curr_flow != NULL)
    {
    if ((strcmp(curr_flow->sourceIP, sourIP6) == 0) && (strcmp(curr_flow->destinationIP, destIP6) == 0) && (curr_flow->source_port == sourPort) && (curr_flow->destination_port == destPort) && (curr_flow->protocol == protocol))
        {
        //a keep alive packet
if ((n <= 1) && (tcp_header->th_flags & (TH_FIN||TH_SYN|| TH_RST)) && ((ntohl(tcp_header->th_seq) - curr_flow->next_seq_num) == -1))
            	return 0; 
    
if (((n > 0) || (tcp_header->th_flags & TH_SYN || TH_FIN)) && ((curr_flow->next_seq_num) > ntohl(tcp_header->th_seq)) )
{
return 1; 
}
      }
    curr_flow = curr_flow->nextf;   
  }
  return 0;
  }
  struct flow*make_flowIPV4(const struct tcphdr* tcp_header,char *payload){
  struct flow *f = (struct flow *)malloc(sizeof(struct flow));
  int n = atoi(payload);
  f->sourceIP=strdup(sourceIp4);
  f->destinationIP=strdup(destinationIp4);
  f->source_port=sourPort;
  f->destination_port=destPort;
  f->protocol=protocol;
  f->nextf=NULL;
 // marked in order to distinguish retransmissions.
  if(protocol==IPPROTO_TCP){
  f->curr_seq_num = ntohl(tcp_header->th_seq);
  f->next_seq_num = ntohl(tcp_header->th_seq) + n;
  }
  else if(protocol==IPPROTO_UDP){
  f->curr_seq_num = 0;
  f->next_seq_num = 0;
  }
  return f;
  }
  struct flow*make_flowIPV6(const struct tcphdr* tcp_header,char *payload){
  struct flow *f = (struct flow *)malloc(sizeof(struct flow));
  int n = atoi(payload);
  f->sourceIP=strdup(sourIP6);
  f->destinationIP=strdup(destIP6);
  f->source_port=sourPort;
  f->destination_port=destPort;
  f->protocol=protocol;
  f->nextf=NULL;
  if(protocol==IPPROTO_TCP){
  f->curr_seq_num = ntohl(tcp_header->th_seq);
  f->next_seq_num = ntohl(tcp_header->th_seq) + n;
  }
  else if(protocol==IPPROTO_UDP){
  f->curr_seq_num = 0;
  f->next_seq_num = 0;
  }
  return f;
  }
  //make a list of flows
  struct flow* list_of_flows(struct flow *head, struct flow *node){
  if(!head)
  return node;
  struct flow*current=head;
  while(current->nextf!=NULL)
  {
  current=current->nextf;
  }
  //tail
  current->nextf=node;
  return head;
  }
  //see if the flow is already in list 
  int flow_check(struct flow *head, struct flow *node){
  struct flow*current=head;
  while(current)
  {
  if ((strcmp(current->sourceIP, node->sourceIP) == 0) && (strcmp(current->destinationIP, node->destinationIP) == 0) && (current->source_port == node->source_port) && (current->destination_port == node->destination_port) && (current->protocol == node->protocol))
        	return 1;
       
        current = current->nextf;

	}

	
	return 0;
  
  
  }
  /*Start capturing/reading packets.*/
void onlineMode( char* ifname){
 
 pcap_t *p;               /* packet capture descriptor */
int promisc = 0;
int to_ms = 1000;
int optimize = 1;        /* passed to pcap_compile to do optimization */
u_int32_t net ;         /* network IP address */
u_int32_t mask ;        /* network address mask */
int num_packets=0;
fptr=fopen("./log.txt","w");
struct bpf_program prog; /* compiled bpf filter program */
 
char errbuf[PCAP_ERRBUF_SIZE];

	
	
     if (pcap_lookupnet(ifname, &net, &mask, errbuf) < 0) {
     fprintf(stderr, "Error looking up network: %s\n", errbuf);
       net = 0;
       mask = 0;
        }
        //printf same info
        printf("Number of packets: %d\n", num_packets);
	printf("Filter expression: %s\n", fltstr);
	printf("\nEnter number of packets you want to capture: ");
        scanf("%d",&num_packets);
        /** Open the network device for packet capture. */
   if (!(p = pcap_open_live(ifname, BUFSIZ, promisc, to_ms, errbuf))) {
        fprintf(stderr, "Error opening interface %s: %s\n",ifname, errbuf);
                exit(2);
                                                                     }
     /* make sure we're capturing on an Ethernet device */
      if (pcap_datalink(p) != DLT_EN10MB) {
       fprintf(stderr, "%s is not an Ethernet\n", ifname);
        exit(3);
 }
   
 /*
         * Compile the filter. The filter will be converted from a text
         * string to a bpf program that can be used by the Berkely Packet
         * Filtering mechanism. */
         if (pcap_compile(p,&prog,fltstr,optimize,mask) < 0) {
                /*
                 * Print out appropriate text, followed by the error message
                 * generated by the packet capture library.
                 */
                fprintf(stderr, "Error compiling bpf filter on %s: %s\n",
                        ifname, pcap_geterr(p));
                exit(4);
        }
        //apply filter
     if (pcap_setfilter(p, &prog) == -1) {
  fprintf(stderr, "Couldn't install filter %s: %s\n", fltstr, pcap_geterr(p));
  exit(5);
 }

 pcap_loop(p, num_packets, handle_packet, NULL);
  //print the rusult
 printf("Total number of  packets received:%ld\n",packet_counter);
 printf("Total number of TCP packets received:%ld\n",countertcp);
 printf("Total number of UPD packets received:%ld\n",counterupd);
 printf("Number of UDP network flows captured:%ld\n",flowsUDPNum);
 printf("Number of TCP network flows captured:%ld\n",flowsTCPNum);
 printf("Total number of network flows captured:%ld\n",flowsTCPNum+flowsUDPNum+unknownnum);
 printf("Total bytes of TCP packets received:%ld\n",bytesTCP);
 printf("Total bytes of UDP packets received:%ld\n",bytesUDP);
 
 /* cleanup */
 pcap_freecode(&prog);
 pcap_close(p);
 fclose(fptr);
 printf("DONE");
}
/*Start capturing/reading packets.*/
void offline(char*file){

 pcap_t *p; 
 char errbuf[PCAP_ERRBUF_SIZE];
 p = pcap_open_offline(file, errbuf); 
 if (p  == NULL)
    {
        printf("\nErroropening file\n");
        exit(EXIT_FAILURE);
    }
pcap_loop(p, -1, handle_packet, NULL);
printf("Total number of  packets received:%ld\n",packet_counter);
 printf("Total number of TCP packets received:%ld\n",countertcp);
 printf("Total number of UPD packets received:%ld\n",counterupd);
 printf("Number of UDP network flows captured:%ld\n",flowsUDPNum);
 printf("Number of TCP network flows captured:%ld\n",flowsTCPNum);
 printf("Total number of network flows captured:%ld\n",flowsTCPNum+flowsUDPNum+unknownnum);
 printf("Total bytes of TCP packets received:%ld\n",bytesTCP);
 printf("Total bytes of UDP packets received:%ld\n",bytesUDP);
pcap_close(p);

}
void usage(void)
{
	printf(
	       "\n"
	       "usage:\n"
	       "\t./pcap_ex \n"
		   "Options:\n"
		   "-i Network interface name (e.g., eth0)\n"
		   "-r,Packet capture file name (e.g., test.pcap)\n"
		   "-i Network interface name -f Filter expression (e.g., port 80)\n"
		   "-h, Help message\n\n"
		   );

	exit(1);
}
/*Select one interface that you wish to monitor or select the pcap file name.*/
int main(int argc, char *argv[]){
 char ifname[INTERFACESZ];  
 int ch;
 int i;
if (argc <=2){
 usage();
}
strcpy(ifname, argv[2]);
 
 while ((ch = getopt(argc, argv, "h:i:r:")) != -1)
	{

		switch (ch) {		
		case 'i':
		if (argc > 3){
		 int ch1;
		 while ((ch1 = getopt(argc, argv, "f:")) != -1){
		 switch (ch1) {
		 case'f':
		 
		 for(i=4;i<argc;i++){
		    
		 sprintf(fltstr+strlen(fltstr),"%s",argv[i]);
		  
		 }
		 
		   break;
		 default:
		  usage();
		 
		  }
		  }
		}else{
		sprintf(fltstr,"%s"," ");
		
		}
		onlineMode(ifname);	
			
			break;
		case 'r':
		offline(ifname);	
			
			break;
		
		}
	}

	argc -= optind;
	argv += optind;	
	return 0;
}
 

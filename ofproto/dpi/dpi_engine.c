#include "dpi-interface.h"
#include <dlfcn.h>
#include <stddef.h>
#include<netinet/in.h>
#include<errno.h>
#include<netdb.h>
#include<stdio.h> //For standard things
#include<stdlib.h>    //malloc
#include<string.h>    //strlen

#include<netinet/ip_icmp.h>   //Provides declarations for icmp header
#include<netinet/udp.h>   //Provides declarations for udp header
#include<netinet/tcp.h>   //Provides declarations for tcp header
#include<netinet/ip.h>    //Provides declarations for ip header
#include<netinet/if_ether.h>  //For ETH_P_ALL
#include<net/ethernet.h>  //For ether_header
#include<sys/socket.h>
#include<arpa/inet.h>
#include<sys/ioctl.h>
#include<sys/time.h>
#include<sys/types.h>
#include<unistd.h>
//Register this module
VLOG_DEFINE_THIS_MODULE(dpi_engine);

//Globals
void *dpiLib = NULL;

void ProcessPacket(unsigned char* , int);
void print_ip_header(unsigned char* , int);
void print_tcp_packet(unsigned char * , int );
void print_udp_packet(unsigned char * , int );
void print_icmp_packet(unsigned char* , int );
void PrintData (unsigned char* , int);

char* print_url(char*);
int sizeofUrl(char *);
void printRRType(int );

FILE *logfile;
struct sockaddr_in source,dest;
int tcp=0,udp=0,icmp=0,others=0,igmp=0,total=0,i,j;

void DpiWriteLog(int nlevel, char *format, ...)
{
	char buffer[256];
	va_list args;
	va_start (args, format);
	vsnprintf (buffer, 255, format, args);

	switch((enum DPILOGLEVEL)nlevel)
	{
	case DPIERR:
		VLOG_ERR(buffer);
		break;
	case DPIINFO:
		VLOG_INFO(buffer);
		break;
	case DPIDEBUG:
		VLOG_DBG(buffer);
		break;
	case DPIWARN:
		VLOG_WARN(buffer);
		break;
	default:
		break;
	}
	va_end(args);
}

int32 dpiProcessPacket(void *packet, uint32 nSize)
{
	VLOG_DBG(__FUNCTION__);
	
	logfile=fopen("/tmp/log.txt","a");
	ProcessPacket(packet, nSize);
	fclose(logfile);
	return 0;
}


char* print_url(char data[]){
	int i=0;
	int toread = data[0];
	int start = 0;
	i++;


	while(toread != 0){
		// print the (#) where a "." in the url is
		//printf("(%d)", toread);
		fprintf(logfile, ".");

		// print everything bettween the dots
		for(; i<=start+toread; i++)
			fprintf(logfile, "%c",data[i]);

		// next chunk
		toread = data[i];
		start = i;
		i++;
	}

	// return a char* to the first non-url char
	return &data[i];
}



int sizeofUrl(char data[]){
	int i = 0;
	int toskip = data[0];

	// skip each set of chars until (0) at the end
	while(toskip!=0){
		i += toskip+1;
		toskip = data[i];
	}

	// return the length of the array including the (0) at the end
	return i+1;
}

void printRRType(int i){
	switch(i){
		case 1:
			fprintf(logfile, "IPv4 address record");
			break;
		case 5:
			fprintf(logfile, "CNAME record");
			break;
		case 15:
			fprintf(logfile, "MX mail exchange record");
			break;
		case 18:
			fprintf(logfile, "AFS database record");
			break;
		case 28:
			fprintf(logfile, "IPv6 address record");
			break;
		default:
			fprintf(logfile, "unknown (%d)",i);
	}
}



void ProcessPacket(unsigned char* buffer, int size)
{
	DpiWriteLog(DPIINFO,__FUNCTION__);
    //Get the IP Header part of this packet , excluding the ethernet header
    struct iphdr *iph = (struct iphdr*)(buffer + sizeof(struct ethhdr));
    ++total;
    switch (iph->protocol) //Check the Protocol and do accordingly...
    {
        case 1:  //ICMP Protocol
            ++icmp;
            DpiWriteLog(DPIINFO, "ICMP packet arrived");
            print_icmp_packet( buffer , size);
            break;

        case 2:  //IGMP Protocol
            ++igmp;
            break;

        case 6:  //TCP Protocol
            ++tcp;
            DpiWriteLog(DPIINFO, "TCP packet arrived");
            print_tcp_packet(buffer , size);
            break;

        case 17: //UDP Protocol
            ++udp;
            DpiWriteLog(DPIINFO, "UDP packet arrived");
            print_udp_packet(buffer , size);
            break;

        default: //Some Other Protocol like ARP etc.
            ++others;
            break;
    }
    fprintf(logfile,"\n\nTCP : %d   UDP : %d   ICMP : %d   IGMP : %d   Others : %d   Total : %d\n", tcp , udp , icmp , igmp , others , total);

}



void print_ethernet_header(unsigned char* Buffer, int Size)
{
    struct ethhdr *eth = (struct ethhdr *)Buffer;

    fprintf(logfile , "\n");
    fprintf(logfile , "Ethernet Header\n");
    fprintf(logfile , "   |-Destination Address : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_dest[0] , eth->h_dest[1] , eth->h_dest[2] , eth->h_dest[3] , eth->h_dest[4] , eth->h_dest[5] );
    fprintf(logfile , "   |-Source Address      : %.2X-%.2X-%.2X-%.2X-%.2X-%.2X \n", eth->h_source[0] , eth->h_source[1] , eth->h_source[2] , eth->h_source[3] , eth->h_source[4] , eth->h_source[5] );
    fprintf(logfile , "   |-Protocol            : %u \n",(unsigned short)eth->h_proto);
}

void print_ip_header(unsigned char* Buffer, int Size)
{
    print_ethernet_header(Buffer , Size);

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr) );
    iphdrlen =iph->ihl*4;

    memset(&source, 0, sizeof(source));
    source.sin_addr.s_addr = iph->saddr;

    memset(&dest, 0, sizeof(dest));
    dest.sin_addr.s_addr = iph->daddr;

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    fprintf(logfile , "   |-IP Version        : %d\n",(unsigned int)iph->version);
    fprintf(logfile , "   |-IP Header Length  : %d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)(iph->ihl))*4);
    fprintf(logfile , "   |-Type Of Service   : %d\n",(unsigned int)iph->tos);
    fprintf(logfile , "   |-IP Total Length   : %d  Bytes(Size of Packet)\n",ntohs(iph->tot_len));
    fprintf(logfile , "   |-Identification    : %d\n",ntohs(iph->id));
    //fprintf(logfile , "   |-Reserved ZERO Field   : %d\n",(unsigned int)iphdr->ip_reserved_zero);
    //fprintf(logfile , "   |-Dont Fragment Field   : %d\n",(unsigned int)iphdr->ip_dont_fragment);
    //fprintf(logfile , "   |-More Fragment Field   : %d\n",(unsigned int)iphdr->ip_more_fragment);
    fprintf(logfile , "   |-TTL      : %d\n",(unsigned int)iph->ttl);
    fprintf(logfile , "   |-Protocol : %d\n",(unsigned int)iph->protocol);
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(iph->check));
    fprintf(logfile , "   |-Source IP        : %s\n",inet_ntoa(source.sin_addr));
    fprintf(logfile , "   |-Destination IP   : %s\n",inet_ntoa(dest.sin_addr));
}

void print_tcp_packet(unsigned char* Buffer, int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)( Buffer  + sizeof(struct ethhdr) );
    iphdrlen = iph->ihl*4;

    struct tcphdr *tcph=(struct tcphdr*)(Buffer + iphdrlen + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + tcph->doff*4;

    fprintf(logfile , "\n\n***********************TCP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile , "\n");
    fprintf(logfile , "TCP Header\n");
    fprintf(logfile , "   |-Source Port      : %u\n",ntohs(tcph->source));
    fprintf(logfile , "   |-Destination Port : %u\n",ntohs(tcph->dest));
    fprintf(logfile , "   |-Sequence Number    : %u\n",ntohl(tcph->seq));
    fprintf(logfile , "   |-Acknowledge Number : %u\n",ntohl(tcph->ack_seq));
    fprintf(logfile , "   |-Header Length      : %d DWORDS or %d BYTES\n" ,(unsigned int)tcph->doff,(unsigned int)tcph->doff*4);
    //fprintf(logfile , "   |-CWR Flag : %d\n",(unsigned int)tcph->cwr);
    //fprintf(logfile , "   |-ECN Flag : %d\n",(unsigned int)tcph->ece);
    fprintf(logfile , "   |-Urgent Flag          : %d\n",(unsigned int)tcph->urg);
    fprintf(logfile , "   |-Acknowledgement Flag : %d\n",(unsigned int)tcph->ack);
    fprintf(logfile , "   |-Push Flag            : %d\n",(unsigned int)tcph->psh);
    fprintf(logfile , "   |-Reset Flag           : %d\n",(unsigned int)tcph->rst);
    fprintf(logfile , "   |-Synchronise Flag     : %d\n",(unsigned int)tcph->syn);
    fprintf(logfile , "   |-Finish Flag          : %d\n",(unsigned int)tcph->fin);
    fprintf(logfile , "   |-Window         : %d\n",ntohs(tcph->window));
    fprintf(logfile , "   |-Checksum       : %d\n",ntohs(tcph->check));
    fprintf(logfile , "   |-Urgent Pointer : %d\n",tcph->urg_ptr);

  
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "TCP Header\n");
    PrintData(Buffer+iphdrlen,tcph->doff*4);

    fprintf(logfile , "Data Payload\n");
    PrintData(Buffer + header_size , Size - header_size );

    fprintf(logfile , "\n###########################################################");
}

struct dns_header{
        unsigned short id;
	unsigned short flags;
	unsigned short qdcount;
	unsigned short ancount;
	unsigned short nscount;
	unsigned short arcount;

};

struct dns_packet{
	struct dns_header dns;
	char data[0];
};

struct static_RR {
	uint16_t type;
	uint16_t clas;
	uint32_t ttl;
	uint16_t rdlength;
};


void print_udp_packet(unsigned char *Buffer , int Size)
{

    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer +  sizeof(struct ethhdr));
    iphdrlen = iph->ihl*4;

    struct udphdr *udph = (struct udphdr*)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof udph;

    fprintf(logfile , "\n\n***********************UDP Packet*************************\n");

    print_ip_header(Buffer,Size);

    fprintf(logfile , "\nUDP Header\n");
    fprintf(logfile , "   |-Source Port      : %d\n" , ntohs(udph->source));
    fprintf(logfile , "   |-Destination Port : %d\n" , ntohs(udph->dest));
    fprintf(logfile , "   |-UDP Length       : %d\n" , ntohs(udph->len));
    fprintf(logfile , "   |-UDP Checksum     : %d\n" , ntohs(udph->check));

    fprintf(logfile , "\n");
    fprintf(logfile , "IP Header\n");
    PrintData(Buffer , iphdrlen);

    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer+iphdrlen , sizeof udph);

    fprintf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , Size - header_size);


        char *tab = "    ";

    if(ntohs(udph->source)==53){
	struct dns_packet *pd = (struct dns_packet*)(Buffer + iphdrlen  + sizeof(struct ethhdr) + sizeof(struct udphdr));
        fprintf(logfile, "DNS HEADER\n");
	fprintf(logfile, "%sid:%d\n", tab, ntohs(pd->dns.id));
	fprintf(logfile, "%sflags:%d\n", tab, ntohs(pd->dns.flags));
	fprintf(logfile, "%s# questions:%d\n", tab, ntohs(pd->dns.qdcount));
	fprintf(logfile, "%s# answers:%d\n", tab, ntohs(pd->dns.ancount));
	fprintf(logfile, "%s# ns:%d\n", tab, ntohs(pd->dns.nscount));
	fprintf(logfile, "%s# ar:%d\n", tab, ntohs(pd->dns.arcount));
	fprintf(logfile, "RESOURCE RECORDS\n");

//	int numRRs = ntohs(pd->dns.qdcount) + ntohs(pd->dns.ancount) + ntohs(pd->dns.nscount) + ntohs(pd->dns.arcount);
	int i;
//	Query
	fprintf(logfile, "\nQuery    ");
	fprintf(logfile, "(%d)", sizeofUrl(pd->data)-2);
        print_url(pd->data);
        fprintf(logfile, "\nResponse:\n");

	int numRRs = ntohs(pd->dns.ancount);
	char *tmpptr = Buffer + header_size + sizeof(struct dns_header) + sizeofUrl(pd->data) + 4 ;

	for(i=0; i<numRRs; i++){
		unsigned char frstbyteRR = *tmpptr;
		fprintf(logfile, "name frst byte value %d",frstbyteRR);
		if(frstbyteRR<192){

			fprintf(logfile, "(%d)", sizeofUrl(tmpptr)-2);
			print_url(tmpptr);
			fprintf(logfile, "\n");
			struct static_RR* RRd = (struct static_RR*)((void*)(tmpptr + sizeofUrl(tmpptr)));
			int type = ntohs(RRd->type);
			int clas = ntohs(RRd->clas);
			int ttl = (uint32_t)ntohl(RRd->ttl);
			int rdlength = ntohs(RRd->rdlength);
			uint8_t* rd = (void*)(&RRd->rdlength + sizeof(uint16_t));

			fprintf(logfile, "%stype(%d):",tab,type); printRRType( ntohs(RRd->type) ); printf("\n");
			fprintf(logfile, "%sclass:%d TTL:%hu RDlength:%d\n", tab, clas, ttl, rdlength);
			if( (rdlength != 0) && (type == 1)  ){
				fprintf(logfile, "data:");
				fprintf(logfile, "%hu.%hu.%hu.%hu",rd[0], rd[1], rd[2], rd[3]  );
				fprintf(logfile, "\n");
			}
			tmpptr = (char *)(rd + rdlength);
		}
		else{
			fprintf(logfile,"\nDNS Compression used\n");
			struct static_RR* RRd = (struct static_RR*)( (void*)(tmpptr + 2) );
			int type = ntohs(RRd->type);
			int clas = ntohs(RRd->clas);
			int ttl = (uint32_t)ntohl(RRd->ttl);
			int rdlength = ntohs(RRd->rdlength);
			uint8_t* rd = (void*)(&RRd->rdlength + 1);


			fprintf(logfile, "%stype(%d):",tab,type); printRRType( ntohs(RRd->type) ); printf("\n");
			fprintf(logfile, "%sclass:%d TTL:%hu RDlength:%d\n", tab, clas, ttl, rdlength);
			if( rdlength != 0 && (type == 1) ){
				fprintf(logfile, "data:");
				fprintf(logfile, "%hu.%hu.%hu.%hu",rd[0], rd[1], rd[2], rd[3]  );
				fprintf(logfile, "\n");
			}
			tmpptr = (char *)(rd + rdlength);


		}

	}


    }
    fprintf(logfile , "\n###########################################################");
}

void print_icmp_packet(unsigned char* Buffer , int Size)
{
    unsigned short iphdrlen;

    struct iphdr *iph = (struct iphdr *)(Buffer  + sizeof(struct ethhdr));
    iphdrlen = iph->ihl * 4;

    struct icmphdr *icmph = (struct icmphdr *)(Buffer + iphdrlen  + sizeof(struct ethhdr));

    int header_size =  sizeof(struct ethhdr) + iphdrlen + sizeof icmph;

    fprintf(logfile , "\n\n***********************ICMP Packet*************************\n");

    print_ip_header(Buffer , Size);

    fprintf(logfile , "\n");

    fprintf(logfile , "ICMP Header\n");
    fprintf(logfile , "   |-Type : %d",(unsigned int)(icmph->type));

    if((unsigned int)(icmph->type) == 11)
    {
        fprintf(logfile , "  (TTL Expired)\n");
    }
    else if((unsigned int)(icmph->type) == 0)
    {
        fprintf(logfile , "  (ICMP Echo Reply)\n");
    }

    fprintf(logfile , "   |-Code : %d\n",(unsigned int)(icmph->code));
    fprintf(logfile , "   |-Checksum : %d\n",ntohs(icmph->checksum));
    //fprintf(logfile , "   |-ID       : %d\n",ntohs(icmph->id));
    //fprintf(logfile , "   |-Sequence : %d\n",ntohs(icmph->sequence));
    fprintf(logfile , "\n");

    fprintf(logfile , "IP Header\n");
    PrintData(Buffer,iphdrlen);

    fprintf(logfile , "UDP Header\n");
    PrintData(Buffer + iphdrlen , sizeof icmph);

    fprintf(logfile , "Data Payload\n");

    //Move the pointer ahead and reduce the size of string
    PrintData(Buffer + header_size , (Size - header_size) );

    fprintf(logfile , "\n###########################################################");
}
void PrintData (unsigned char* data , int Size)
{
    int li , lj;
    for(li=0 ; li < Size ; li++)
    {
        if( li!=0 && li%16==0)   //if one line of hex printing is complete...
        {
            fprintf(logfile , "         ");
            for(lj=li-16 ; lj<li ; lj++)
            {
                if(data[lj]>=32 && data[lj]<=128)
                    fprintf(logfile , "%c",(unsigned char)data[lj]); //if its a number or alphabet

                else fprintf(logfile , "."); //otherwise print a dot
            }
            fprintf(logfile , "\n");
        }

        if(li%16==0) fprintf(logfile , "   ");
            fprintf(logfile , " %02X",(unsigned int)data[li]);

        if( li==Size-1)  //print the last spaces
        {
            for(lj=0;lj<15-li%16;lj++)
            {
              fprintf(logfile , "   "); //extra spaces
            }

            fprintf(logfile , "         ");

            for(lj=li-li%16 ; lj<=li ; lj++)
            {
                if(data[lj]>=32 && data[lj]<=128)
                {
                  fprintf(logfile , "%c",(unsigned char)data[lj]);
                }
                else
                {
                  fprintf(logfile , ".");
                }
            }

            fprintf(logfile ,  "\n" );
        }
    }
}



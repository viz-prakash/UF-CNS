#include <libnet.h>
#include <pcap.h>
#define GNIP_FILTER "icmp[0] = 0"
void usage(char *);
int
main(int argc, char **argv)
{
libnet_t *l = NULL;
pcap_t *p = NULL;
u_int8_t *packet;
u_int32_t dst_i
p
, src_i
p
;
pp
u_int16_t id, seq, count;
int c, interval = 0, pcap_fd, timed_out;
u_int8_t loop, *payload = NULL;
u_int32_t payload_s = 0;
libnet_ptag_t icmp = 0, ip = 0;
char *device = NULL;
fd_set read_set;
struct pcap_pkthdr pc_hdr;
struct timeval timeout;
struct bpf_program filter_code;
bpf_u_int32 local_net, netmask;
struct libnet_ipv4_hdr *ip_hdr;
struct libnet_icmpv4_hdr *icmp_hdr;
char errbuf[LIBNET_ERRBUF_SIZE];
while((c = getopt(argc, argv, "I:i:c:")) !=
EOF)
{
switch (c)
{
case 'I':
di
d
ev
i
ce
=
optarg;
break;
case 'i':
interval = atoi(optarg);
break;
case 'c':
count = atoi(optarg);
break
break
;
}
}
c = argc - optind;
if (c != 1)
{
usage(argv[0]);
34
/* initialize the libnet library */
l = libnet_
init(LIBNET_RAW4,
device, errbuf);
if (l == NULL)
{
fprintf(stderr,
"libnet_i
nit()
failed: %s", errbuf);
exit(EX
IT_FAILURE);
}
if (device == NULL)
{
device = pcap_
lookupdev(errbuf);
if (device == NULL)
{
fprintf(stderr,
"pcap
_lookupdev()
failed: %s\n", errbuf);
goto bad;
}
}
}
/* handcrank pcap */
p = pcap_op
en_live(device,
256, 0, 0, errbuf);
if (p == NULL)
{
fprintf(stderr,
"pcap_ope
n_live()
failed: %s", errbuf);
goto bad;
goto bad;
}
/* get the subnet mask
of the inter
face */
if (pcap_lo
okupnet(device,
&local_net, &netmask, errbuf) == -1)
{
fprintf(stderr,
"pcap_loo
kupnet():
%s", errbuf);
goto bad;
}
}
/* compile the BPF filter code */
if (pcap_co
mpile(p,
&filter_c
ode,
GNIP_FI
LTER, 1,
netmask)
== -1)
{
fprintf(stderr,
"pcap_com
pile():
%s", pcap_
geterr(p));
goto bad;
}
/* apply the filter to the interface */
if (pcap_se
tfilter(p,
&filter
_code)
== -1)
{
fprintf(stderr,
"pcap_set
filter():
%s", pcap_
geterr(p));
goto bad;
}
dst ip
=
libnet n
ame2addr4(l,
argv[
optind],
LIBNET RE
SOLVE);
dst
_
ip libnet
_
name2addr4(l,
argv[
optind],
LIBNET
_
RESOLVE);
if (dst_ip == -1)
{
fprintf(stderr,
"Bad desti
nation IP
address
(%s).\n",
libnet_ge
terror(l));
goto bad;
}
35
src_ip = libnet_get_ipaddr4(l);
if (src_ip == -1)
{
fprintf(stderr, "Can't determine source IP address
(%s).\n",
libnet_geterror(l));
goto bad;
}
interval ? interval : interval = 1;
timeout.tv_sec = interval;
timeout tv usec = 0;
timeout
.
tv
_
usec = 0;
pcap_fd = pcap_fileno(p);
fprintf(stderr, "GNIP %s (%s): %d data bytes\n",
libnet_addr2name4(dst_ip, 1),
libnet_addr2name4(dst_ip, 0),
LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_s);
36
loop = 1;
for (id = getpid(), seq = 0, icmp = LIBNET_PTAG_INITIALIZER; loop; seq++)
{
icmp = libnet_build_icmpv4_echo(
ICMP_ECHO, /* type */
0, /* code */
0, /* checksum */
id, /* id */
seq, /* sequence number */
payload, /* payload */
payload_s, /* payload size */
l, /* libnet context */
icmp); /* ptag */
if (i
1)
if (i
cmp
==
-
1)
{
fprintf(stderr, "Can't build ICMP header: %s\n",
libnet_geterror(l));
goto bad;
}
ip = libnet build ipv4(
ip = libnet
_
build
_
ipv4(
LIBNET_IPV4_H + LIBNET_ICMPV4_ECHO_H + payload_s, /* length */
0, /* TOS */
id, /* IP ID */
0, /* IP Frag */
64, /* TTL */
IPPROTO_ICMP, /* protocol */
0 /
*
checksum
*
/
0
,
/ checksum /
src_ip, /* source IP */
dst_ip, /* destination IP */
NULL, /* payload */
0, /* payload size */
l, /* libnet context */
ip); /* ptag */
if
(
i
p
==
-1
)
(p
)
{
fprintf(stderr, "Can't build IP header: %s\n",
libnet_geterror(l));
goto bad;
}
c = libnet_write(l);
if (c == -1)
{
fprintf(stderr, "Write error: %s\n", libnet_geterror(l));
goto bad;
}
37
FD_ZERO(&read_set);
FD_SET(pcap_fd, &read_set);
for (timed_out = 0; !timed_out && loop; )
{
c = select(pcap_fd + 1, &read_set, 0, 0, &timeout);
switch (c)
switch (c)
{
case -1:
fprintf(stderr, "select() %s\n", strerror(errno));
goto bad;
case 0:
timed_out = 1;
continue;
default:
if (FD_ISSET(pcap_fd, &read_set) == 0)
{
timed_out = 1;
continue;
}
/* fall through to read the packet */
}
packet = (u_int8_t *)pcap_next(p, &pc_hdr);
if (packet == NULL)
{
continue;
}
ip_hdr = (struct libnet_ipv4_hdr *)(packet + 14);
icmp_hdr = (struct libnet_icmpv4_hdr *)(packet + 14 +
(ip_hdr->ip_hl << 2));
if (ip_hdr->ip_src.s_addr != dst_ip)
{
continue;
}
if (i hd
i id id)
if (i
cmp_
hd
r->
i
cmp_
id
==
id)
{
fprintf(stderr, "%d bytes from %s: icmp_seq=%d ttl=%d\n",
ntohs(ip_hdr->ip_len),
libnet_addr2name4(ip_hdr->ip_src.s_addr, 0),
icmp_hdr->icmp_seq, ip_hdr->ip_ttl);
}
}
}
}
libnet_destroy(l);
pcap_close(p);
return (EXIT_SUCCESS);

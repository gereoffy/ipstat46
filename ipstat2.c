
// apt install libnetfilter-log1
// gcc -Wall -Wno-pointer-sign -Os ipstat2.c  -o ipstat2 -lnetfilter_log /usr/local/lib/libmaxminddb.a

//static unsigned char prefix6[]={0x20,1, 7,0x38, 0x44,3, 0xbe,0xef}; // 2001:738:4403:beef:211d:f1af:4bd4:595b
static unsigned char prefix6[]={0x20,1, 7,0x38, 0x79,4}; // 2001:738:7904:
static unsigned char prefix4[]={10};

int mask_s6=64;
int mask_d6=48;
#define IPSTAT_MAX 1024

#include <stdio.h>
#include <string.h>
#include <strings.h>
#include <malloc.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <time.h>

#include <stdint.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/socket.h>
#include <asm/types.h>
#include <linux/netlink.h>
#include <linux/if.h>

//#include <linux/netfilter_ipv4/ipt_ULOG.h>
#include <libnetfilter_log/libnetfilter_log.h>

#include <maxminddb.h>

MMDB_s mmdb1;
MMDB_s mmdb2;

void load_geo(){
    if (MMDB_SUCCESS != MMDB_open("/var/lib/GeoIP/GeoLite2-Country.mmdb", MMDB_MODE_MMAP, &mmdb1)) printf("mmdb not found!\n");
    //if (MMDB_SUCCESS != MMDB_open("/var/lib/GeoIP/GeoLite2-ASN.mmdb", MMDB_MODE_MMAP, &mmdb2)) printf("mmdb not found!\n");
    if (MMDB_SUCCESS != MMDB_open("/var/lib/GeoIP/GeoIP2-ISP.mmdb", MMDB_MODE_MMAP, &mmdb2)) printf("mmdb not found!\n");
}

void lookup_geo(char* dst,int dstlen, struct sockaddr* sa){
    int len=0;
    
    int cl=3,ol=3;
    const char* cp="???";
    const char* op="???";
    
    int mmdb_error;
    MMDB_lookup_result_s result1=MMDB_lookup_sockaddr(&mmdb1, sa, &mmdb_error);
    MMDB_lookup_result_s result2=MMDB_lookup_sockaddr(&mmdb2, sa, &mmdb_error);
    MMDB_entry_data_s entry1;
    MMDB_entry_data_s entry2;
    if(result1.found_entry){ // ASN/Org found
	if(MMDB_SUCCESS == MMDB_get_value(&result1.entry,&entry1,"continent","names", "en", NULL))
	    if(entry1.has_data && entry1.type==MMDB_DATA_TYPE_UTF8_STRING){
		cl=entry1.data_size;
		cp=entry1.utf8_string;
	    }
	if(cl==6 && !memcmp(cp,"Europe",6))
	  if(MMDB_SUCCESS == MMDB_get_value(&result1.entry,&entry1,"country","names", "en", NULL))
	    if(entry1.has_data && entry1.type==MMDB_DATA_TYPE_UTF8_STRING){
		cl=entry1.data_size;
		cp=entry1.utf8_string;
	    }
    }
    if(result2.found_entry) // ASN/Org found
	if(MMDB_SUCCESS == MMDB_get_value(&result2.entry,&entry2,"organization", NULL))
	    if(entry2.has_data && entry2.type==MMDB_DATA_TYPE_UTF8_STRING){
		ol=entry2.data_size;
		op=entry2.utf8_string;
	    }

    len=snprintf(dst,dstlen,"%.*s   (%.*s)",ol,op,cl,cp);
//    len=snprintf(dst,dstlen,"%.*s!",ol,op);
//    printf("len=%d\n",len);
    if(len<dstlen) dst[len]=0;
}


typedef struct ipstat_s {
    unsigned char s[16];
    unsigned char d[16];
    unsigned char geoip[48];
    unsigned long long dl,ul;
    time_t t0,t;
    unsigned char kl;
} ipstat_t;

int ipstat_n=0;
static ipstat_t ipstat[IPSTAT_MAX];
unsigned int ipstat_i[IPSTAT_MAX];
unsigned int ipstat_hash[65536];
int pktcount=0;
int dropcount=0;
int goodhash=0,badhash=0;
time_t oldest=0;

void hexbyte(unsigned char x){
    unsigned char x1=x>>4;
    unsigned char x2=x&15;
    putchar(x1<10 ? 48+x1 : 97+x1-10);
    putchar(x2<10 ? 48+x2 : 97+x2-10);
}

int comp (const void * elem1, const void * elem2){
    unsigned int i1 = *((unsigned int*)elem1);
    unsigned int i2 = *((unsigned int*)elem2);
    unsigned long long x1=ipstat[i1].dl+ipstat[i1].ul;
    unsigned long long x2=ipstat[i2].dl+ipstat[i2].ul;
    if (x2 > x1) return  1;
    if (x2 < x1) return -1;
    return 0;
}

void list_stat(){
    int i;
//    printf("======== %d / %d =======\n",ipstat_n,pktcount);
    if(ipstat_n<1) return;

    qsort(ipstat_i, ipstat_n, sizeof(ipstat_i[0]), comp);

    printf("\033[2J\033[H");

    time_t t=time(NULL);
    int c=0;
    for(i=0;i<ipstat_n;i++){
	int ii=ipstat_i[i];
	ipstat_t* p=&ipstat[ii];
	int age=t-p->t;
	if(age>30) continue; // skip old stuff
	if(c++>=30) break; // csak a top 30 kell
//	printf("%3d:%10lld / %-10lld ",age,p->dl,p->ul);
//	printf("%s%3d:",age<=3?"\033[1m":(age<15?"\033[0m":"\033[2m"),age);
	printf("%s%3d:",age<=3?"\033[1m":(age<15?"":"\033[2m"),age);
	char dst[100];
	printf("%40s",inet_ntop(p->kl==16 ? AF_INET6 : AF_INET,p->s,dst,sizeof(dst)) );
	printf(" <==> %-40s",inet_ntop(p->kl==16 ? AF_INET6 : AF_INET,p->d,dst,sizeof(dst)) );
//	printf("%10lld / %-10lld %.*s\033[0m\n",p->dl,p->ul,(int)(sizeof(p->geoip)),p->geoip);
	printf("%7lld / %-7lld %.*s\033[0m\n",p->dl>>10,p->ul>>10,(int)(sizeof(p->geoip)),p->geoip);
//	printf("%.*s\n",(int)(sizeof(p->geoip)),p->geoip);
    }
    printf("conns=%d/%d (oldest:%d) pkt=%d drop=%d  hash=%d/%d\n",ipstat_n,IPSTAT_MAX,oldest?(int)(t-oldest):-1,pktcount,dropcount,badhash,goodhash);
    fflush(stdout);
}


void analyze(unsigned char *packet, int len,unsigned int proto){
//    printf("============================== len=%d\n",len);
//    hexDump(packet,len);
    unsigned char* s;
    unsigned char* d;
    int kl,ul=0,dl=0;

//    printf("* proto=0x%X\n",proto);


    if(proto==0x86dd){
	// IPv6
	s=packet+8;
	if(!memcmp(s,prefix6,sizeof(prefix6))){
	    // upload  local->remote
	    d=packet+8+16;
	    ul=packet[4]*256+packet[5]+40;
	} else {
	    // download  remote->local
	    dl=packet[4]*256+packet[5]+40;
	    d=s; s=packet+8+16; // swap src/dst
	}
	kl=16;
	
	// apply netmask
	if(mask_s6<128) memset(s+(mask_s6>>3),0,16-(mask_s6>>3));
	if(mask_d6<128) memset(d+(mask_d6>>3),0,16-(mask_d6>>3));
	
    } else
    if(proto==0x0800){
	// IPv4
	s=packet+12;
	if(!memcmp(s,prefix4,sizeof(prefix4))){
	    // upload  local->remote
	    d=packet+12+4;
	    ul=packet[2]*256+packet[3];
	} else {
	    // download  remote->local
	    dl=packet[2]*256+packet[3];
	    d=s; s=packet+12+4;
	}
	kl=4;
    } else
	return; // WTF

    ++pktcount;

//    printf("++ kl=%d l=%d\n",kl,l);

// check hash
    int i;
//    unsigned int hash=( (s[kl-2]<<8)|s[kl-1] ) ^ ( (d[kl-1]<<8)|d[kl-2] );
    unsigned int hash=0;
    for(i=0;i<kl;i+=2) hash^=( (s[i]<<8)|s[i+1] ) ^ ( (d[i+1]<<8)|d[i] );
    i=ipstat_hash[hash];
    if(i<ipstat_n){
	ipstat_t* p=&ipstat[i];
	if(p->kl==kl && !memcmp(p->d,d,kl) && !memcmp(p->s,s,kl)){
	    p->dl+=dl;
	    p->ul+=ul;
	    p->t=time(NULL);
	    ++goodhash;
	    return;
        }
    }

// search
//    int i;
    for(i=0;i<ipstat_n;i++){
	ipstat_t* p=&ipstat[i];
	if(p->kl==kl && !memcmp(p->d,d,kl) && !memcmp(p->s,s,kl)){
	    p->dl+=dl;
	    p->ul+=ul;
	    p->t=time(NULL);
	    ipstat_hash[hash]=i;++badhash;
	    return;
        }
    }

    ipstat_t* p;
    if(ipstat_n<IPSTAT_MAX){
	// add new entry
        ipstat_i[ipstat_n]=ipstat_n; // sort index
        ipstat_hash[hash]=ipstat_n;
        p=&ipstat[ipstat_n]; ++ipstat_n;
    } else {
	// reuse oldest entry
	int ii=0;
	for(i=1;i<ipstat_n;i++) if(ipstat[i].t<ipstat[ii].t) ii=i;
        ipstat_hash[hash]=ii;
	p=&ipstat[ii];
        oldest=p->t;
//	printf("reusing age %d\n",(int)(time(NULL)-ipstat[ii].t));
    }
    memcpy(p->s,s,kl);
    memcpy(p->d,d,kl);
    p->kl=kl; p->dl=dl; p->ul=ul;
    p->t=p->t0=time(NULL);
    p->geoip[0]=0; // lehet ezt itt kene kikeresni?
    if(kl==16){
	struct sockaddr_in6 sa;
	sa.sin6_family=AF_INET6;
	memcpy(&sa.sin6_addr,d,16);
	lookup_geo(p->geoip,sizeof(p->geoip), (struct sockaddr*)(&sa) );
    } else if(kl==4){
	struct sockaddr_in sa;
	sa.sin_family=AF_INET;
	memcpy(&sa.sin_addr,d,4);
	lookup_geo(p->geoip,sizeof(p->geoip), (struct sockaddr*)(&sa) );
    }
}


static int cb(struct nflog_g_handle *gh, struct nfgenmsg *nfmsg,
		struct nflog_data *ldata, void *data)
{
	struct nfulnl_msg_packet_hdr *ph = nflog_get_msg_packet_hdr(ldata);
	char *payload;
	int payload_len = nflog_get_payload(ldata, &payload);
	
	unsigned int proto=0;
	if (ph) {
		proto=ntohs(ph->hw_protocol);
//		printf("hw_protocol=0x%04x hook=%u ", proto, ph->hook);
	}

#if DEBUG2

	int hwlen=nflog_get_msg_packet_hwhdrlen(ldata);
	char* hwaddr=nflog_get_msg_packet_hwhdr(ldata);

	char *prefix = nflog_get_prefix(ldata);

	u_int32_t mark = nflog_get_nfmark(ldata);
	u_int32_t indev = nflog_get_indev(ldata);
	u_int32_t outdev = nflog_get_outdev(ldata);

	printf("hwlen=%u ", hwlen);
	printf("mark=%u ", mark);

	if (indev > 0)
		printf("indev=%u ", indev);

	if (outdev > 0)
		printf("outdev=%u ", outdev);


	if (prefix) {
		printf("prefix=\"%s\" ", prefix);
	}
	if (payload_len >= 0)
		printf("payload_len=%d ", payload_len);

	fputc('\n', stdout);

#endif

//    ulog_packet_msg_t* hdr=buffer+16;
#if DEBUG2
    int iplen=(hdr->payload[2]<<8)+hdr->payload[3];
    printf("%4d (%d/%d)  %.8s -> %.8s   %d  MAC:",nr,hdr->data_len,iplen,hdr->indev_name,hdr->outdev_name,hdr->mac_len);
    int i;
    for(i=0;i<hdr->mac_len;i++) printf(" %02X",hdr->mac[i]);    printf("\n");
//    for(i=0;i<hdr->data_len;i++) printf(" %02X",hdr->payload[i]);    printf("\n");
    printf("  %d.%d.%d.%d",hdr->payload[12],hdr->payload[13],hdr->payload[14],hdr->payload[15]);
    printf("->  %d.%d.%d.%d\n",hdr->payload[16],hdr->payload[17],hdr->payload[18],hdr->payload[19]);
//    printf("[%d]\n",sizeof(ulog_packet_msg_t));
#endif

//	memcpy(packet,hwaddr,hwlen);
//	memcpy(packet+14,payload,payload_len);
//	analyze(packet,payload_len+14);

    analyze(payload,payload_len,proto);

    return 0;
}


int main(int argc, char **argv)
{
	struct nflog_handle *h;
	struct nflog_g_handle *qh;
	int rv, fd;
	unsigned char buf[65536];

	load_geo();

	h = nflog_open();
	if (!h) {
		fprintf(stderr, "error during nflog_open()\n");
		exit(1);
	}

//	printf("unbinding existing nf_log handler for AF_INET (if any)\n");
	if (nflog_unbind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error nflog_unbind_pf()\n");
		exit(1);
	}

//	printf("binding nfnetlink_log to AF_INET\n");
	if (nflog_bind_pf(h, AF_INET) < 0) {
		fprintf(stderr, "error during nflog_bind_pf()\n");
		exit(1);
	}
//	printf("binding this socket to group\n");
	qh = nflog_bind_group(h, 123);
	if (!qh) {
		perror("wtf");
		fprintf(stderr, "no handle for group\n");
		exit(1);
	}

//	printf("setting copy_packet mode\n");
	if (nflog_set_mode(qh, NFULNL_COPY_PACKET, 0xffff) < 0) {
		fprintf(stderr, "can't set packet copy mode\n");
		exit(1);
	}

	fd = nflog_fd(h);

//	printf("registering callback for group\n");
	nflog_callback_register(qh, &cb, NULL);

	unsigned int t0=time(NULL);

//	printf("going into main loop\n");
	while (1) {
		rv=recv(fd, buf, sizeof(buf), 0);
		if(rv<0){
			perror("wtf");
			++dropcount;
		}
		
//		printf("pkt received (len=%u)\n", rv);

		/* handle messages in just-received packet */
		if(rv>0) nflog_handle_packet(h, buf, rv);

		unsigned int t=time(NULL);
		if(t>=t0+2){
		    list_stat();
		    t0=t; //ipstat_n=0; pktcount=0;
		}
	}
	

	printf("unbinding from group 100\n");
	nflog_unbind_group(qh);

#ifdef INSANE
	/* norally, applications SHOULD NOT issue this command,
	 * since it detaches other programs/sockets from AF_INET, too ! */
	printf("unbinding from AF_INET\n");
	nflog_unbind_pf(h, AF_INET);
#endif

	printf("closing handle\n");
	nflog_close(h);

	return EXIT_SUCCESS;
}



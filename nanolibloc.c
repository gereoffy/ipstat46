
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


#define DB_AS 0
#define DB_ND 1
#define DB_NT 2
#define DB_CO 3
#define DB_PO 4

static unsigned char* locdb_data[5];
static unsigned int locdb_len[5];
static unsigned int ipv4root=0;

static inline unsigned int getint(unsigned char* p){
    return (p[0]<<24) | (p[1]<<16) | (p[2]<<8) | p[3];
}

static inline unsigned char* getstr(int pos){
    if( pos<0 || pos>=locdb_len[DB_PO] ) return NULL;
    return locdb_data[DB_PO]+pos;
}

int locdb_open(char* fn){
    unsigned char magic[8];
    unsigned char header[64];
    FILE* f=fopen(fn,"r");
    if(fread(magic,sizeof(magic),1,f)<1) return 0;
    // Magic: 4C4F4344  42585801
    // printf("Magic: %08X  %08X\n",getint(magic),getint(magic+4));
    if(getint(magic)!=0x4C4F4344 || getint(magic+4)!=0x42585801) return 0; // bad format
    if(fread(header,sizeof(header),1,f)<1) return 0;
    int i;
    for(i=0;i<5;i++){
        unsigned int off=getint(header+20+i*8);
        unsigned int len=getint(header+24+i*8);
//        printf("Block #%d: %u  %u\n",i,off,len);
        fseek(f,off,SEEK_SET);
        locdb_data[i]=malloc(len);
        if(!locdb_data[i]) return 0; // malloc error
        if(len!=fread(locdb_data[i],1,len,f)) return 0; // read error
        locdb_len[i]=len;
    }
#if DEBUG
    printf("Vendor: %s\n",getstr(getint(header+8)));
    printf("Descr: %s\n",getstr(getint(header+12)));
    printf("License: %s\n",getstr(getint(header+16)));
#endif
    // find IPv4 root-node:
    unsigned int nxt=0;
    for(i=0;i<96;i++){
        if(nxt*12>=locdb_len[DB_NT]) return 0; // out of bounds indexing...
        nxt=getint( locdb_data[DB_NT]+12*nxt+(i<80?0:4) );
    }
    ipv4root=nxt;
//    printf("IPv4 root-node: %d\n",nxt);
    return 1; // OK
}

int locdb_lookup(unsigned char* address, int addrlen, int nxt){
    int ret=-1;
//    int mask;
    for(int mask=0;mask<8*addrlen;mask+=1){
        if(nxt*12>=locdb_len[DB_NT]) return -1; // out of bounds indexing...
        int bit=(address[mask>>3] >> (7-(mask&7)) )&1;
        nxt=getint( locdb_data[DB_NT] + 12*nxt + bit*4 );
        unsigned int net=getint( locdb_data[DB_NT] + 12*nxt + 8 );
        if(!(net&0x80000000)) ret=net;
        if(!nxt) break;
    }
    return ret;
}

unsigned int locdb_get_asn(unsigned int net,unsigned char* cc){
    if(net*12>=locdb_len[DB_ND]) return 0;
    if(cc) memcpy(cc,locdb_data[DB_ND]+net*12,2);
    return getint(locdb_data[DB_ND]+net*12+4);
}

unsigned char* locdb_get_org(unsigned int asn){
    int p1=0;
    int p2=locdb_len[DB_AS]/8;
    while(p1<p2){ // binary search
        int pos=(p1+p2)/2;
        unsigned int x=getint(locdb_data[DB_AS]+pos*8);
        if(asn==x) return getstr(getint(locdb_data[DB_AS]+pos*8+4)); // found!
        if(asn<x) p2=pos; else p1=pos+1;
    }
    return NULL;
}

int main(){
    locdb_open("/var/lib/location/database.db");
    unsigned char addr[]={193,224,41,5};
    //unsigned char addr[]={0x2a,1,0x6e,0xe0, 0,1, 2,1,   0,0,0,0,0xB,0xAD,0xC0,0xDE};
    int ret=locdb_lookup(addr,sizeof(addr),(sizeof(addr)<=4 ? ipv4root : 0));
    unsigned char cc[3]={0,0,0};
    int asn=locdb_get_asn(ret,cc);
    unsigned char* org=locdb_get_org(asn);
    printf("Result: net=%d  asn=%d  CC='%s'  ORG='%s'\n",ret,asn,cc,org);

}


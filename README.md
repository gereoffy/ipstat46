# Realtime IP statistics with IP / IPv6 support

Setup your internal network/masks in ipset2.c:

-       static unsigned char prefix4[]={10};  //  ={192,168};
-       static unsigned char prefix6[]={0x20,1, 7,0x38, 0x79,4}; // 2001:738:7904:
-       int mask_s6=64;
-       int mask_d6=48;


Build/compile:

- apt install libnetfilter-log1 libnetfilter-log-dev libmaxminddb-dev
- gcc -Wall -Wno-pointer-sign -Os ipstat2.c  -o ipstat2 -lnetfilter_log -lmaxminddb


GeoIP databases:  (path can be changed in ipstat2.c)

- /var/lib/GeoIP/GeoLite2-Country.mmdb
- /var/lib/GeoIP/GeoIP2-ISP.mmdb or /var/lib/GeoIP/GeoLite2-ASN.mmdb


Firewall settings:  (traffic should be logged to NFLOG group 123)

for C in INPUUT FORWARD OUTPUT; do  
    iptables -I $C -j NFLOG --nflog-group 123 --nflog-threshold 64 --nflog-size 64  
    ip6tables -I $C -j NFLOG --nflog-group 123 --nflog-threshold 64 --nflog-size 64  
done  


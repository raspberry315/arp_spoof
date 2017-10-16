#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <pthread.h>
#include <netinet/ip.h>
#include <net/if.h>

struct arp_packet{
    u_int8_t targ_hw_addr[6];
    u_int8_t src_hw_addr[6];
    u_int16_t ether_type;                     //ethernet header
    
    u_int16_t hw_type;
    u_int16_t prot_type;
    u_int8_t hw_addr_size;
    u_int8_t prot_addr_size;
    u_int16_t op;
    u_int8_t sndr_hw_addr[6];
    u_int8_t sndr_ip_addr[4];
    u_int8_t rcpt_hw_addr[6];
    u_int8_t rcpt_ip_addr[4];
};

struct ether_packet{
    u_int8_t targ_hw_addr[6];
    u_int8_t src_hw_addr[6];
    u_int16_t ether_type;
};


struct thread_args{
    int i;
    u_char *interface;
    u_char *sender_ip;
    u_char *target_ip;
};

void *thread_func(void* arg);
void make_arp(u_int8_t *packet, u_int8_t *src_mac, u_int8_t *dst_mac, u_int8_t *src_ip, u_int8_t *dst_ip, u_int16_t opcode);
void get_target_mac(u_int8_t *interface, u_int8_t *target_ip, u_int8_t *target_mac, u_int8_t *attacker_ip, u_int8_t *attcker_mac);
int attack(pcap_t *handler, u_int8_t *attacker_mac, u_int8_t *sender_mac, u_int8_t *target_mac, u_int8_t *attcker_ip, u_int8_t *sender_ip, u_int8_t *target_ip);

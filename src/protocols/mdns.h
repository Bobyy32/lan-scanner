#ifndef MDNS_H
#define MDNS_H

#define _DEFAULT_SOURCE

#include "../misc.h"

/*
    Resources to check out:
    https://developer.apple.com/bonjour/
    https://www.iana.org/assignments/service-names-port-numbers/service-names-port-numbers.xhtml
*/
                                                                                                                                                       
struct dns_header                                                                                                                                                                                                          
{                                                                                                                                                                                                                          
    uint16_t id;          // Query ID                                                                                                                                                                                
    uint16_t flags;       // Flags                                                                                                                                               
    uint16_t qdcount;     // Number of questions                                                                                                                                                                           
    uint16_t ancount;     // Number of answers                                                                                                                                                                             
    uint16_t nscount;     // Number of authority records                                                                                                                                                                   
    uint16_t arcount;     // Number of additional records                                                                                                                                                                  
};                                                                                                                                                                                                                         
                                                                                                                                                                                                                             
                                                                                                                                                 
struct dns_question                                                                                                                                                                                                        
{                                                                                                                                                                                                                          
    uint16_t qtype;       // Query type (PTR = 0x000C, A = 0x0001, AAAA = 0x001C)                                                                                                                                          
    uint16_t qclass;      // Query class (IN = 0x0001)                                                                                                                                                                       
};                                                                                                                                                                                                                         
                                                                                                                                                                                                                             
                                                                                                                                           
struct dns_rr                                                                                                                                                                                                              
{                                                                                                                                                                                                                          
    uint16_t type;        // Record type                                                                                                                                                                                   
    uint16_t class;       // Record class                                                                                                                                                                                  
    uint32_t ttl;         // Time to live                                                                                                                                                                                  
    uint16_t rdlength;    // Length of rdata                                                                                                                                                                                                                                                                                                                                                    
};

struct pcap_pktheadr;

// DNS types                                                                                                                                                                                                        
#define DNS_TYPE_A      0x0001   // IPv4 address                                                                                                                                                                           
#define DNS_TYPE_PTR    0x000C   // Ptr                                                                                                                                                 
#define DNS_TYPE_TXT    0x0010   // Text record                                                                                                                                                                            
#define DNS_TYPE_AAAA   0x001C   // IPv6 address                                                                                                                                                                           
#define DNS_TYPE_SRV    0x0021   // Service record                                                                                                                                                                         
                                                                                                                                                                                                                            
// DNS classes                                                                                                                                                                                                      
#define DNS_CLASS_IN    0x0001   // Internet                                                                                                                                                                               
                                                                                                                                                                                                                            
// DNS flags                                                                                                                                                                                                               
#define DNS_FLAG_QR     0x8000   // Query (0) or Response (1)                                                                                                                                                              
#define DNS_FLAG_AA     0x0400   // Authoritative Answer

int write_dns_label(unsigned char* buf, int offset, const char* label);

bool create_mdns_query_msg(libnet_t* context, const device_info device, const uint32_t target_ip);
bool mdns_discovery_send_m(libnet_t* context, const device_info device);
void mdns_discovery_send_u(libnet_t* context, const device_info device);
void mdns_discovery_rcv_callback(const unsigned char* packet, struct pcap_pktheadr* header, void* data);

#endif
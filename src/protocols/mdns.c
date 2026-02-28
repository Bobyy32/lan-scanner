#include "mdns.h"

// Helper to write a DNS label
int write_dns_label(unsigned char *buf, int offset, const char *label)
{
    int len = strlen(label);                                                                                                                                                                                               
    buf[offset++] = (unsigned char)len;                                                                                                                                                                                    
    memcpy(&buf[offset], label, len);                                                                                                                                                                                      
    return offset + len;
}

bool create_mdns_query_msg(libnet_t *context, const device_info device, const uint32_t target_ip, const char* query_str, uint16_t query_type)
{
    int offset = 0;
    unsigned char buffer[256];
    
    // Build dns query (_services._dns-sd._udp.local)
    char* query_str_cpy = strdup(query_str);
    char* pch = strtok(query_str_cpy, ".");
    while (pch != NULL)
    {
        offset = write_dns_label(buffer, offset, pch); 
        pch = strtok(NULL, ".");
    }                                                                                                                                                            
    buffer[offset++] = 0;

    free(query_str_cpy);

    struct dns_question question;
    question.qtype = htons(query_type);
    question.qclass = htons(DNS_CLASS_IN_QU);

    memcpy(&buffer[offset], &question, sizeof(question));
    offset += sizeof(question);

    libnet_ptag_t dns = libnet_build_dnsv4(LIBNET_DNS_H, 0, 0, 1, 0, 0, 0, (uint8_t*)buffer, (uint32_t)offset, context, 0);
    if (dns == -1)
    {
        fprintf(stderr, "Can't build DNS header: %s\n", libnet_geterror(context));
        goto bad;
    }

    libnet_ptag_t udp = libnet_build_udp(5353,5353, LIBNET_UDP_H + LIBNET_DNS_H + offset, 0, NULL, 0, context, 0);
    if (udp == -1)
    {
        fprintf(stderr, "Can't build UDP header: %s\n", libnet_geterror(context));
        goto bad;
    }

    libnet_ptag_t ipv4 = libnet_build_ipv4(LIBNET_IPV4_H + LIBNET_UDP_H + LIBNET_DNS_H + offset, 0, 0, 0, 255, IPPROTO_UDP, 0, device.ipv4_address, target_ip, NULL, 0, context, 0);
    if (ipv4 == -1)
    {
        fprintf(stderr, "Can't build IPV4 header: %s\n", libnet_geterror(context));
        goto bad;
    }
    
    uint8_t dst[6] = {0x01, 0x00, 0x5e, 0x00, 0x00, 0xfb};
    libnet_ptag_t ether = libnet_autobuild_ethernet(dst, ETHERTYPE_IP, context);
    if (ether == -1)
    {
        fprintf(stderr, "Can't build Ethernet header: %s\n", libnet_geterror(context));
        goto bad;
    }

    return true;

bad:
    return false;
}

bool mdns_discovery_send_m(libnet_t *context, const device_info device)
{

    // multicast ip
    if(!create_mdns_query_msg(context, device, inet_addr("224.0.0.251"), "_services._dns-sd._udp.local", DNS_TYPE_PTR))
    {
        fprintf(stderr, "Failed to create multicast mdns message\n");
        return false;
    }

    int c = libnet_write(context);
    if (c == -1)
    {
        fprintf(stderr, "Packet size: %s\n", libnet_geterror(context));
        return false;
    }

    fprintf(stdout, "Successfuly Sent multicast mDNS request\n");

    return true;
}

void mdns_discovery_send_u(libnet_t* context, const device_info device)
{
    uint32_t start = ntohl(device.network_id);
    uint32_t end = ntohl(device.broadcast_address);
    
    for (uint32_t host = start + 1; host < end; ++host)
    {
        
        //printf("%u.%u.%u.%u\n", (host >> 24) & 0xFF, (host >> 16) & 0xFF, (host >> 8) & 0xFF, host & 0xFF);
        uint32_t target = htonl(host);
        if(!create_mdns_query_msg(context, device, target, "_services._dns-sd._udp.local", DNS_TYPE_PTR))
        {
            fprintf(stderr, "Unable to create mdns message for %s\n", inet_ntoa((struct in_addr){target}));
            continue;
        }

        int c = libnet_write(context);
        if (c == -1)
        {
            fprintf(stderr, "Packet size: %s\n", libnet_geterror(context));
            continue;
        }
        
        libnet_clear_packet(context);
    }
}

void mdns_discovery_rcv_callback(const unsigned char* packet, struct pcap_pkthdr* header, void* data)
{

    capture_ht* ht = (capture_ht*)data;
    
    struct ip* ip_hdr = (struct ip*)(packet + sizeof(struct ether_header));
    int ip_hdr_len = ip_hdr->ip_hl * 4;
    struct udphdr* udp_hdr = (struct udphdr*)(packet + ip_hdr_len + sizeof(struct ether_header));
    struct dns_header* dns_hdr = (struct dns_header*)(packet + sizeof(struct udphdr) + ip_hdr_len + sizeof(struct ether_header));
    
    uint16_t flags = ntohs(dns_hdr->flags);
    if (!(flags & DNS_FLAG_QR))
    {
        return;
    }

    uint16_t num_answers = ntohs(dns_hdr->ancount);
    if (num_answers == 0)
    {
        return;
    }


    size_t mdns_size = ntohs(udp_hdr->len) - 8;

    bool res = parse_mdns_response(ht->ht, ht->srv_table, inet_ntoa(ip_hdr->ip_src),(void*)dns_hdr, mdns_size);

    if (res == false)
    {
        //fprintf(stderr, "Failed to parse mdns response!\n");
    }
}

bool skip_mdns_name(const void *data, size_t *offset, size_t size)
{
    while(*offset < size && (*((unsigned char*)data + (*offset))) != 0x00)
    {
        if ((*((unsigned char*)data + (*offset)) & 0xC0) == 0xC0)
        {
            ++(*offset);
            break;
        }
        size_t len = (size_t)(*((unsigned char*)data + (*offset)));
        (*offset) += 1 + len;
    }
    ++(*offset);

    if (*offset >= size)
    {
        return false;
    }

    return true;
}

size_t extract_mdns_name(const void *data, char* out_buffer, size_t offset, size_t size)
{
    bool is_compression = false;
    size_t buff_offset = 0;
    size_t save_offset = 0;
    size_t original_offset = offset;
    char buffer[256] = { 0 };

    while(offset < size && (*((unsigned char*)data + offset)) != 0x00)
    {
        if ((*((unsigned char*)data + offset) & 0xC0) == 0xC0)
        {
            size_t hi = (size_t)(*((unsigned char*)data + offset) & 0x3F);
            ++offset;
            if (offset >= size)
            {
                return 0;
            }

            if (!is_compression)
            {
                save_offset = offset + 1;
            }

            offset = (hi << 8) | (size_t)(*((unsigned char*)data + offset));
            is_compression = true;
            if (offset >= size)
            {
                return 0;
            }
        }

        size_t len = (size_t)(*((unsigned char*)data + offset));
        if (buff_offset + len + 1 >= sizeof(buffer))
        {
            return 0;
        }
        size_t old_offset = offset;
        offset += 1 + len;

        // copy text
        memcpy(buffer + buff_offset, (void*)((unsigned char*)data + old_offset + 1), len);
        buffer[buff_offset + len] = '.';
        buff_offset = buff_offset + len + 1;
    }

    if (offset >= size)
    {
        return 0;
    }
    
    if (buff_offset == 0)
    {
        buffer[buff_offset] = '\0';
    }
    else
    {
        buffer[buff_offset - 1] = '\0';
    }
    ++offset;

    strcpy(out_buffer, buffer);

    return is_compression ? save_offset - original_offset : offset - original_offset; 
}


char *record_parse_ptr(const void *data, size_t offset, size_t size, size_t r_length)
{
    char buff[256] = {0};

    if ((r_length <= size - offset) && (r_length >= 2))
    {
        if (extract_mdns_name(data, buff, offset, size) == 0)
        {
            return NULL;
        }
    }
    else
    {
        return NULL;
    }
    
    return strdup(buff);
}

bool record_parse_srv(const void *data, size_t offset, size_t size, size_t r_length, uint16_t* port, char* target_name)
{

    if ((r_length <= size - offset) && (r_length >= 2))
    {
        const uint16_t* srv_records = (const uint16_t*)((const unsigned char*)data + offset);
        srv_records++; // skip priority
        srv_records++; // skip weights
        *port = ntohs(*(srv_records++));
        if(extract_mdns_name(data, target_name, offset + 6, size) == 0)
        {
            return false;
        }
    }
    else
    {
        return false;
    }

    return true;
}

void device_entry_destroy(void* v)
{
    device_entry* entry = (device_entry*)v;
    free(entry->ssdp_server);
    free(entry->ssdp_location);
    if (entry->services)
    {
        for (uint8_t j = 0; j < entry->service_count; ++j)
        {
            free(entry->services[j].service_type);
            free(entry->services[j].instance_name);
            free(entry->services[j].host_name);
        }
        free(entry->services);
    }
    free(entry);
}

void pending_srv_destroy(void* v)
{
    mdns_service* svc = (mdns_service*)v;
    free(svc->host_name);
    free(svc->instance_name);
    free(svc);
}

bool parse_mdns_response(struct HashTable* ht, struct HashTable* pending_srv_ht, char* ip_str, const void *data, size_t size)
{
    struct dns_header* header = (struct dns_header*)data; 

    size_t offset = 12; // skip header

    // skip questions sections
    for (uint16_t i = 0; i < ntohs(header->qdcount); ++i)
    {
        skip_mdns_name(data, &offset, size);

        offset += 4;
    }

    mdns_service* services = NULL;
    uint8_t service_count = 0;

    // parse answer sections
    for (uint16_t i = 0; i < ntohs(header->ancount); ++i)
    {
        char* owner_name = calloc(256, sizeof(char)); // the instance is the record owners name
        size_t temp_offset = extract_mdns_name(data, owner_name,  offset, size);
        if (temp_offset == 0)
        {
            free(owner_name);
            break;
        }
        offset += temp_offset;

        uint16_t rtype = ntohs(*(uint16_t*)((unsigned char*)data + offset));
        uint16_t rclass  = ntohs(*(uint16_t*)((unsigned char*)data + offset + 2));
        uint32_t ttl = ntohl(*(uint32_t*)((unsigned char*)data + offset + 4));
        uint16_t rdlen = ntohs(*(uint16_t*)((unsigned char*)data + offset + 8));

        //fprintf(stderr, "[LOOP] record i=%u owner=%s rtype=0x%04X rdlen=%u offset=%zu size=%zu\n", i, owner_name, rtype, rdlen, offset, size);

        offset += 10;

        bool owner_transferred = false;
        switch (rtype)
        {
            case DNS_TYPE_PTR:
                if (!strstr(owner_name, ".local"))
                {
                    break;
                }

                {
                    char* instance_name = record_parse_ptr(data, offset, size, rdlen);
                    if (instance_name)
                    {
                        // check table with instance_name as key
                        mdns_service* pend = (mdns_service*)ht_get(pending_srv_ht, instance_name);

                        if (!pend)
                        {
                            mdns_service* temp  = (mdns_service*)realloc(services, (service_count + 1) * sizeof(mdns_service));
                            if (temp)
                            {
                                services = temp;
                                memset(&services[service_count], 0, sizeof(mdns_service));
                                services[service_count].service_type = owner_name;
                                services[service_count].instance_name = instance_name;
                                services[service_count].port = 0;
                                services[service_count++].host_name = NULL;
                                owner_transferred = true;
                            }
                            else
                            {
                                free(instance_name);
                            }                            
                        }
                        else
                        {
                            mdns_service* temp  = (mdns_service*)realloc(services, (service_count + 1) * sizeof(mdns_service));
                            if (temp)
                            {
                                services = temp;
                                memset(&services[service_count], 0, sizeof(mdns_service));
                                services[service_count].service_type = owner_name;
                                services[service_count].instance_name = instance_name;
                                services[service_count].port = pend->port;
                                services[service_count++].host_name = pend->host_name;
                                owner_transferred = true;
                                free(pend);
                            }
                            else
                            {
                                free(instance_name);
                            }      
                        }
                    }
                }
                break;
            case DNS_TYPE_SRV:
                if (!strstr(owner_name, ".local"))
                {
                    break;
                }


                {
                    char* target_name = calloc(256, sizeof(char));
                    uint16_t port_num = 0;
                    fprintf(stderr, "[SRV] owner_name: %s\n", owner_name);
                    if(record_parse_srv(data, offset, size, rdlen, &port_num, target_name))
                    {
                        fprintf(stderr, "[SRV] target: %s | port: %u\n", target_name, port_num);
                        if (target_name[0] == '\0')
                        {
                            free(target_name);
                        }
                        else
                        {

                            bool found = false;
                            for (uint8_t i = 0; i < service_count; ++i)
                            {
                                fprintf(stderr, "[SRV] comparing instance_name: %s vs owner_name: %s\n",
                                    services[i].instance_name ? services[i].instance_name : "(null)", owner_name);
                                if(services[i].instance_name && (strcmp(services[i].instance_name, owner_name) == 0))
                                {
                                    found = true;
                                    services[i].port = port_num;
                                    services[i].host_name = target_name;
                                    fprintf(stderr, "[SRV] match found for service %u\n", i);
                                    break;
                                }
                            }

                            if (!found)
                            {
                                fprintf(stderr, "[SRV] no match, storing in pending table\n");
                                mdns_service* not_found = calloc(1, sizeof(mdns_service));
                                if (not_found)
                                {
                                    not_found->port = port_num;
                                    not_found->host_name = target_name;
                                    ht_set(pending_srv_ht, owner_name, not_found);
                                }
                                else
                                {
                                    free(target_name);
                                }
                            }
                        }
                    }
                    else
                    {
                        fprintf(stderr, "[SRV] record_parse_srv failed\n");
                        free(target_name);
                    }
                }
                break;
            default:
                break;
        }

        if (!owner_transferred)
        {
            free(owner_name);
        }

        offset += rdlen;
    }

    if (service_count == 0)
    {
        if (services)
        {
            free(services);
        }
        return false;
    }

    device_entry* value = (device_entry*)ht_get(ht, ip_str);
    if (value == NULL)
    {
        value = (device_entry*)calloc(1, sizeof(device_entry));
        if (value == NULL)
        {
            free(services);
            return false;
        }
        ht_set(ht, ip_str, value);
    }

    if (value->services)
    {
        for (uint8_t i = 0; i < value->service_count; ++i)
        {

            for (uint8_t j = 0; j < service_count; ++j)
            {
                if (services[j].instance_name && value->services[i].instance_name && strcmp(services[j].instance_name, value->services[i].instance_name) == 0)
                {
                    if (!services[j].host_name && value->services[i].host_name)
                    {
                        services[j].host_name = value->services[i].host_name;
                        value->services[i].host_name = NULL;
                        services[j].port = value->services[i].port;
                    }
                    break;
                }
            }

            if (value->services[i].service_type)
            {
                free(value->services[i].service_type);
            }
            
            if (value->services[i].instance_name)
            {
                free(value->services[i].instance_name);
            }

            if (value->services[i].host_name)
            {
                free(value->services[i].host_name);
            }
        }
        free(value->services);
    }
    
    value->services = services;
    value->service_count = service_count;

    return true;
}
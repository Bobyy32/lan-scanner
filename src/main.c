#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <getopt.h>

#include "../src/debug.h"
#include "../src/hashtable.h"
#include "../src/device.h"
#include "../src/scan.h"
#include "../src/port_scan.h"


int main(int argc, char* argv[])
{
    // get options from cli
    enum 
    {
        OPT_TCP,
        OPT_ARP,
        OPT_MDNS,
        OPT_SSDP,
        OPT_FULL,
        OPT_HELP = 'h',
        OPT_PORT = 'p'
    };

    enum
    {
        FLAG_TCP = 1 << 0,
        FLAG_ARP = 1 << 1,
        FLAG_MDNS = 1 << 2,
        FLAG_SSDP = 1 << 3,
        FLAG_FULL = FLAG_TCP | FLAG_ARP | FLAG_MDNS | FLAG_SSDP
    };

    static struct option long_options[] = {
        {"tcp", no_argument, NULL, OPT_TCP},
        {"arp", no_argument, NULL, OPT_ARP},
        {"mdns", no_argument, NULL, OPT_MDNS},
        {"ssdp", no_argument, NULL, OPT_SSDP},
        {"full", no_argument, NULL, OPT_FULL},
        {"help", no_argument, NULL, OPT_HELP},
        {"port", required_argument, NULL, OPT_PORT}
    };
     
    int opt;
    int option_index = 0;
    unsigned int flags = 0;
    int num_port_args = 0;
    uint16_t port_args[300] = { 0 };
    while((opt = getopt_long(argc, argv, "p:h", long_options, &option_index)) != -1)
    {
        switch (opt)
        {
            case OPT_TCP: 
                flags |= FLAG_TCP;
                break;
            case OPT_ARP:
                flags |= FLAG_ARP;
                break;
            case OPT_MDNS:
                flags |= FLAG_MDNS;
                break;
            case OPT_SSDP:
                flags |= FLAG_SSDP;
                break;
            case OPT_FULL:
                flags |= FLAG_FULL;
                break;
            case OPT_HELP:
                print_help(argv[0]);
                return 0;
            case OPT_PORT:
                {
                    char* port_num_str = strtok(optarg, ",");
                    while (port_num_str != NULL && num_port_args < 300)
                    {
                        uint16_t port_num = (uint16_t)strtoul(port_num_str, NULL, 10);
                        port_args[num_port_args++] = port_num;
                        port_num_str = strtok(NULL, ",");
                    }

                    break;
                }
            default:
                break;
        }
    }

    if (num_port_args > 0)
    {
        flags |= FLAG_TCP;
    }

    if (flags & FLAG_TCP)
    {
        flags |= FLAG_ARP;
    }


    struct HashTable* ht = ht_create();
    struct HashTable* ht_ports = ht_create();
    struct DeviceInfo my_device = { 0 };
    scan_args args= {.device = &my_device, .ht = ht};

    int rc1, rc2, rc3, rc4;
    pthread_t thread1, thread2, thread3, thread4;

    if (ht == NULL || ht_ports == NULL)
    {
        debug_printf("Unable to create hash table!\n");

        if (ht)
        {
            ht_destroy(ht, device_entry_destroy);
        }

        if (ht_ports)
        {
            ht_destroy(ht_ports, port_info_destroy);
        }

        return EXIT_FAILURE;
    }

    if(!get_device_info(&my_device))
    {
        debug_printf("Unable to get device info!\n");
        ht_destroy(ht, device_entry_destroy);
        ht_destroy(ht_ports, port_info_destroy);
        return (EXIT_FAILURE);
    }

    parse_service_info(ht_ports);

    // execute options
    if (flags & FLAG_ARP)
    {
        if ((rc1 = pthread_create(&thread1, NULL, arp_scan_thread, &args)))
        {
            debug_printf("Thread creation failed %d\n", rc1);
        }
    }

    if (flags & FLAG_MDNS)
    {
        if ((rc2 = pthread_create(&thread2, NULL, mdns_scan_thread, &args)))
        {
            debug_printf("Thread creation failed %d\n", rc2);
        }
    }

    if (flags & FLAG_SSDP)
    {
        if ((rc3 = pthread_create(&thread3, NULL, ssdp_scan_thread, &args)))
        {
            debug_printf("Thread creation failed %d\n", rc3);
        }
    }

    if (rc1 == 0)
    {
        pthread_join(thread1, NULL);
    }

    if (rc2 == 0)
    {
        pthread_join(thread2, NULL);
    }

    if (rc3 == 0)
    {
        pthread_join(thread3, NULL);
    }    

    if (flags & FLAG_TCP)
    {
        if (num_port_args > 0)
        {
            printf("Scanning Ports: ");
            for (int i = 0; i < num_port_args; ++i)
            {
                printf("%u ", port_args[i]);
            }
            putc('\n', stdout);
        }
        else
        {
            if ((rc4 = pthread_create(&thread4, NULL, tcp_rcv_thread, &args)))
            {
                debug_printf("Thread creation failed %d\n", rc4);
            }

            if (rc4 == 0)
            {
                tcp_scan(&my_device, ht, ht_ports);
                pthread_join(thread4, NULL);
            }

        }
    }

    // print out results

    print_results(ht, ht_ports);

    // destroy hash tables
    ht_destroy(ht, device_entry_destroy);
    ht_destroy(ht_ports, port_info_destroy);

    return 0;
}
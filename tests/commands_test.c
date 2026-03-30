#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>
#include <getopt.h>
#include "../src/debug.h"


static void print_help(const char* prog_name)
{
    printf("Usage: %s [OPTIONS]\n\n", prog_name);
    printf("Options:\n");
    printf("  --tcp              Run TCP port scan (all common ports)\n");
    printf("  --arp              Run ARP discovery\n");
    printf("  --mdns             Run mDNS discovery\n");
    printf("  --ssdp             Run SSDP discovery\n");
    printf("  --full             Run all scans\n");
    printf("  -p, --port PORTS   Specify ports to scan (comma-separated, e.g. 22,80,443)\n");
    printf("  -h, --help         Show this help message\n");
}

int main(int argc, char* argv[])
{
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

    if (flags & FLAG_ARP)
    {
        printf("Running ARP scan\n");
    }

    if (flags & FLAG_MDNS)
    {
        printf("Running MDNS scan\n");
    }

    if (flags & FLAG_SSDP)
    {
        printf("Running SSDP scan\n");
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
            printf("Running full tcp probing\n");
        }
    }


    return 0;
}

#include "../src/debug.h"
#include "../src/device.h"
#include "../src/hashtable.h"
#include "../src/port_scan.h"
#include "../src/cjson/cJSON.h"

#include <stdlib.h>


/*

Experimental JSON format for now

{
  "subnet": "192.168.88.0/24",
  "hosts": [
    {
      "ip": "192.168.88.1",
      "mac": "AA:BB:CC:DD:EE:FF",
      "vendor": "MikroTik",
      
      "hostname": "router.local",

      "open_ports": [
        {"port": 22, "service": "ssh"},
        {"port": 80, "service": "http"},
        {"port": 443, "service": "https"}
      ],

      "ssdp_server": "",
      "ssdp_location": "",


      "mDNS Services": 
    },
    {
      "ip": "192.168.88.10",
      "mac": "11:22:33:44:55:66",
      "vendor": "Intel",
      "hostname": "desktop.local",
      "open_ports": [22, 3389],

    }
  ]
}
*/

int main (void)
{
  // Import Port info for the ports stuff
  hash_table* ht_ports = ht_create();
  if (ht_ports == NULL)
  {
    return 1;
  }


  // Import OUI info for the vender JSON field
  hash_table* ht_oui = ht_create();
  if (ht_oui == NULL)
  {
    ht_destroy(ht_ports, port_info_destroy);
    return 1;
  }

  import_ports("resources/ports.txt", ht_ports);
  import_oui("resources/oui.txt", ht_oui);


  // Setup JSON variables
  char* subnet_str = "192.168.1.0/24";

  char* ip_addr = "192.168.1.1";

  //device_entry list[3];
  uint16_t ports[3] = { 80, 443, 2421 };

  char* ssdp_server_str = "SSDP SERVER NAME";
  char* ssdp_location_str = "SSDP LOCATION NAME";

  device_entry dev1 = { 
    .mac = "A0:28:84:DD:EE:FF", 
    .mac_bytes = {0xA0, 0x28, 0x84, 0xDD, 0xEE, 0xFF},
    .ssdp_server = ssdp_server_str, 
    .ssdp_location = ssdp_location_str, 
    .services = NULL,
    .service_count = 0,
    .open_port_count = 3, 
    .open_ports = ports, 
  };


  char* string = NULL;

  cJSON* object = NULL;

  cJSON* subnet = NULL;
  cJSON* hosts = NULL;

  cJSON* host = NULL;
  cJSON* ip = NULL;
  cJSON* mac = NULL;
  cJSON* vendor = NULL;
  //cJSON* hostname = NULL;
  cJSON* open_ports = NULL;
  cJSON* port_entry = NULL;
  cJSON* port = NULL;
  cJSON* service = NULL;

  cJSON* ssdp_server = NULL;
  cJSON* ssdp_location = NULL;

  // Create JSON objects and add

  object = cJSON_CreateObject();
  if (object == NULL)
  {
    goto end;
  }

  subnet = cJSON_CreateString(subnet_str);
  if (subnet == NULL)
  {
    goto end;
  }
  cJSON_AddItemToObject(object, "subnet", subnet);

  hosts = cJSON_CreateArray();
  if (hosts == NULL)
  {
    goto end;
  }
  cJSON_AddItemToObject(object, "hosts", hosts);

  {
    host = cJSON_CreateObject();
    if (host == NULL)
    {
      goto end;
    }
    cJSON_AddItemToArray(hosts, host);

    ip = cJSON_CreateString(ip_addr);
    if (ip == NULL)
    {
      goto end;
    }
    cJSON_AddItemToObject(host, "ip", ip);

    mac = cJSON_CreateString(dev1.mac);
    if (mac == NULL)
    {
      goto end;
    }
    cJSON_AddItemToObject(host, "mac", mac);

    char oui[9] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0 };
    snprintf(oui, 9, "%02X:%02X:%02X", dev1.mac_bytes[0], dev1.mac_bytes[1], dev1.mac_bytes[2]);
    oui_info* entry_info = ht_get(ht_oui, oui);
    if (entry_info == NULL)
    {
      vendor = cJSON_CreateString("unknown");
    }
    else
    {
      vendor = cJSON_CreateString(entry_info->organization);
    }

    if (vendor == NULL)
    {
      goto end;
    }
    cJSON_AddItemToObject(host, "vendor", vendor);
    
    open_ports = cJSON_CreateArray();
    if (open_ports == NULL)
    {
      goto end;
    }
    cJSON_AddItemToObject(host, "ports", open_ports);

    
    for (int i = 0; i < sizeof(ports)/sizeof(ports[0]); ++i)
    {
      port_entry = cJSON_CreateObject();
      if (port_entry == NULL)
      {
        continue;
      }
      cJSON_AddItemToArray(open_ports, port_entry);
      
      port = cJSON_CreateNumber((double)ports[i]);
      if (port == NULL)
      {
        continue;
      }
      cJSON_AddItemToObject(port_entry, "port", port);
      
      char buf[6];
      snprintf(buf, sizeof(buf), "%u", (unsigned)ports[i]);
      port_info* port_get = ht_get(ht_ports, buf);
      if (port_get == NULL)
      {
        service = cJSON_CreateString("unknown");
      }
      else
      {
        service = cJSON_CreateString(port_get->service);
      }

      if (service == NULL)
      {
        continue;
      }
      cJSON_AddItemToObject(port_entry, "service", service);
    }

    ssdp_server = cJSON_CreateString(dev1.ssdp_server);
    if (ssdp_server == NULL)
    {
      goto end;
    }
    cJSON_AddItemToObject(host, "ssdp_server", ssdp_server);

    ssdp_location = cJSON_CreateString(dev1.ssdp_location);
    if (ssdp_location == NULL)
    {
      goto end;
    }
    cJSON_AddItemToObject(host, "ssdp_location", ssdp_location);


    string = cJSON_Print(object);
    if (string == NULL)
    {
      fprintf(stderr, "Failed to print monitor.\n");
    }
    else
    {
      printf("%s\n", string);
      free(string);
    }
  }

  ht_destroy(ht_ports, port_info_destroy);
  ht_destroy(ht_oui, oui_info_destroy);

  return 0;

end:
  ht_destroy(ht_ports, port_info_destroy);
  ht_destroy(ht_oui, oui_info_destroy);
  cJSON_Delete(object);

  return 1;
}
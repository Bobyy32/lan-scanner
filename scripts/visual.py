import json
from pyvis.network import Network

f = open("resources/data.json")
data = json.load(f)

net = Network(height="100vh", width="100vw")

scanner_id = data.get("scanner_id", "scanner")

scanner_tooltip = f"Scanner\nIP: {scanner_id}\nSubnet: {data.get('subnet', '')}"
for host in data["hosts"]:
    if host.get("ip") == scanner_id:
        lines = ["Scanner", f"IP: {scanner_id}", f"Subnet: {data.get('subnet', '')}",
                 f"MAC: {host.get('mac', 'unknown')}", f"Vendor: {host.get('vendor', 'unknown')}"]
        for p in host.get("ports", []):
            lines.append(f"Port: {p['port']} ({p.get('service', '?')})")
        for s in host.get("mdns_services", []):
            lines.append(f"mDNS: {s.get('mdns_name', '?')}")
            lines.append(f"  Type: {s.get('mdns_type', '?')}")
        if host.get("ssdp_server"):
            lines.append(f"SSDP: {host['ssdp_server']}")
        if host.get("ssdp_location"):
            lines.append(f"  Location: {host['ssdp_location']}")
        scanner_tooltip = "\n".join(lines)
        break

net.add_node("scanner", label=scanner_id, title=scanner_tooltip, size=35)

for host in data["hosts"]:
    ip = host.get("ip", "unknown")
    mac = host.get("mac", "unknown")
    vendor = host.get("vendor", "unknown")

    lines = [f"IP: {ip}", f"MAC: {mac}", f"Vendor: {vendor}"]

    for p in host.get("ports", []):
        lines.append(f"Port: {p['port']} ({p.get('service', '?')})")

    for s in host.get("mdns_services", []):
        lines.append(f"mDNS: {s.get('mdns_name', '?')}")
        lines.append(f"  Type: {s.get('mdns_type', '?')}")

    if host.get("ssdp_server"):
        lines.append(f"SSDP: {host['ssdp_server']}")
    if host.get("ssdp_location"):
        lines.append(f"  Location: {host['ssdp_location']}")

    tooltip = "\n".join(lines)

    net.add_node(ip, label=ip, title=tooltip)
    net.add_edge("scanner", ip)

net.toggle_physics(True)
net.show("resources/mygraph.html", notebook=False)

f.close()

from scapy.all import sniff, IP
import psutil

def get_active_interface():
    addrs = psutil.net_if_addrs()
    stats = psutil.net_if_stats()

    for interface, snic_list in addrs.items():
        if stats[interface].isup and 'loopback' not in interface.lower():
            return interface
    return None

def packet_callback(packet):
    if IP in packet:
        ip_layer = packet[IP]
        src_ip = ip_layer.src
        dst_ip = ip_layer.dst
        protocol = ip_layer.proto
        payload = bytes(packet[IP].payload)

        print(f"Source IP: {src_ip}")
        print(f"Destination IP: {dst_ip}")
        print(f"Protocol: {protocol}")
        print(f"Payload: {payload}\n")

def start_sniffing(interface=None):
    if interface:
        sniff(iface=interface, prn=packet_callback, store=False)
    else:
        sniff(prn=packet_callback, store=False)

if __name__ == "__main__":
    print("Starting packet sniffer...")
    interface = get_active_interface()
    if interface:
        print(f"Detected active interface: {interface}")
    else:
        print("No active interface detected. Using default interface.")
    start_sniffing(interface=interface)

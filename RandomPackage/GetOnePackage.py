from scapy.all import sniff, TCP, UDP, IP, ICMP
from PortToService import get_service_name
from ServiceToNumeric import get_service_numeric_index

# A: ACK -> Acknowledgment
# P: PSH -> Push
# F: FIN -> Finish
# S: SYN -> Synchronize
# R: RST -> Reset
def nsl_kdd_flag_mapping(pkt):
    if TCP in pkt:
        flags = str(pkt[TCP].flags)

        if 'S' in flags:
            if 'A' in flags:
                return 'SF'
            if 'P' in flags:
                return 'SF'
            if 'F' in flags:
                return 'SF'
            return 'S0'
        elif 'R' in flags:
            return 'REJ'
        elif 'P' in flags and 'A' in flags:
            return 'SF'
        else:
            return 'SF'
    elif ICMP in pkt:
        return 'SF'
    elif UDP in pkt:
        return 'SF'
    return 'OTH'

def process_packet(pkt):
    src_ip = pkt[IP].src if IP in pkt else "N/A"
    dst_ip = pkt[IP].dst if IP in pkt else "N/A"

    src_bytes = len(pkt[IP].payload) if IP in pkt else 0
    # If source and destination IP addresses and port numbers are equal then,
    # variable 'land' takes value 1 else 0
    # source: https://docs.google.com/spreadsheets/d/1oAx320Vo9Z6HrBrL6BcfLH6sh2zIk9EKCv2OlaMGmwY/edit?gid=0#gid=0
    if src_ip == dst_ip: 
        land = 1
    else:
        land = 0

    # Classification between protocol types to get dst_bytes
    if TCP in pkt:
        protocol = 'tcp'
        service = pkt[TCP].dport
        dst_bytes = len(pkt[TCP].payload)
    elif UDP in pkt:
        protocol = 'udp'
        service = pkt[UDP].dport
        dst_bytes = len(pkt[UDP].payload)
    elif ICMP in pkt:
        protocol = 'icmp'
        service = 0
        dst_bytes = len(pkt[ICMP].payload)
    else:
        protocol = 'other'
        service = 0
        dst_bytes = 0
    #########################################################

    nsl_flag = nsl_kdd_flag_mapping(pkt)
    serviceName = get_service_name(service)
    serviceKDD = get_service_numeric_index(serviceName)

    print(f"Source IP: {src_ip}")
    print(f"Destination IP: {dst_ip}")
    print(f"Source Bytes (IP payload): {src_bytes}")
    print(f"Destination Bytes (Proto payload): {dst_bytes}")
    print(f"Protocol: {protocol}")
    print(f"Service: {serviceKDD}")
    print(f"Land: {land}")
    print(f"NSL-KDD Flag: {nsl_flag}")
    print("-" * 50)

print("Sniffing 100 packets...")
packets = sniff(count=100, filter="ip")
for pkt in packets:
    process_packet(pkt)

#https://scapy.readthedocs.io/en/latest/usage.html

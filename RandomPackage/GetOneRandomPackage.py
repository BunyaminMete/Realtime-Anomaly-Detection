from scapy.all import sniff

def paket_yakala(paket):
    print(paket.show())

sniff(count=1, prn=paket_yakala)
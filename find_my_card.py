from scapy.all import sniff, IP, get_if_list
import time

# Get all hardware IDs
interfaces = get_if_list()
print(f"--- STARTING DIAGNOSTIC ---")
print(f"Testing {len(interfaces)} interfaces. Please browse a website now to create traffic!")

def packet_monitor(pkt):
    if IP in pkt:
        print(f" ✅ [MATCH FOUND!] Data detected on: {current_iface}")

# Loop through every card automatically
for iface in interfaces:
    current_iface = iface
    print(f"Testing: {iface[:50]}...", end="\r")
    try:
        # Sniff for 2 seconds on this card
        sniff(iface=iface, prn=packet_monitor, timeout=2, store=0)
    except:
        continue

print(f"\n--- DIAGNOSTIC COMPLETE ---")
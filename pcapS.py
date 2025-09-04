#!/usr/bin/env python3
from scapy.all import rdpcap, Raw
import re, glob, os
from collections import defaultdict

# Keywords to look for
keywords = [b"password", b"login", b"Authorization", b"Cookie", b"HTB{"]

# ANSI colors for fancy output
GREEN = "\033[92m"
RED = "\033[91m"
CYAN = "\033[96m"
RESET = "\033[0m"
BOLD = "\033[1m"

def analyze_pcap(path):
    findings = defaultdict(list)
    packets = rdpcap(path)

    for pkt in packets:
        if pkt.haslayer(Raw):
            data = pkt[Raw].load
            for kw in keywords:
                if kw.lower() in data.lower():
                    snippet = data[:200].decode(errors="ignore").replace("\n", " ")
                    findings[kw.decode(errors="ignore")].append(snippet)

    return findings

def main(folder="pcaps/*.pcap"):
    pcaps = glob.glob(folder)
    if not pcaps:
        print(f"{RED}[!] No PCAP files found in {folder}{RESET}")
        return

    for pcap_file in pcaps:
        print(f"\n{BOLD}{CYAN}[*] Analyzing {pcap_file}{RESET}")
        results = analyze_pcap(pcap_file)

        if not results:
            print(f"    {RED}No sensitive keywords found.{RESET}")
        else:
            for kw, snippets in results.items():
                print(f"  {GREEN}[+] Found keyword:{RESET} {BOLD}{kw}{RESET}")
                for s in snippets[:3]:  # show max 3 snippets per keyword
                    print(f"     └─ {s[:120]}{'...' if len(s) > 120 else ''}")

if __name__ == "__main__":
    main("pcaps/*.pcap")

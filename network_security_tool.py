#!/usr/bin/env python3
import sys
import time
import threading
import queue
import asyncio
import aiohttp
import whois
import dns.resolver
from scapy.all import *
from netifaces import interfaces, ifaddresses
from colorama import init, Fore, Style
import nmap
from netaddr import IPNetwork
import argparse
import ctypes
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from bs4 import BeautifulSoup
import requests
from concurrent.futures import ThreadPoolExecutor
import json
import logging

class NetworkSecurityTool:
    def __init__(self):
        init()
        self.targets = []
        self.interface = None
        self.scan_queue = queue.Queue()
        self.results = {}
        self.setup_logging()
        
    def setup_logging(self):
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler('network_security.log'),
                logging.StreamHandler()
            ]
        )
        self.logger = logging.getLogger(__name__)

    def get_default_interface(self):
        for iface in interfaces():
            addrs = ifaddresses(iface)
            if AF_INET in addrs:
                return iface
        return None

    async def check_ssl(self, host, port):
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port)) as sock:
                with context.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert(binary_form=True)
                    x509_cert = x509.load_der_x509_certificate(cert, default_backend())
                    return {
                        'issuer': x509_cert.issuer,
                        'expiry': x509_cert.not_valid_after,
                        'version': x509_cert.version,
                        'serial': x509_cert.serial_number
                    }
        except Exception as e:
            self.logger.error(f"SSL check failed for {host}:{port} - {str(e)}")
            return None

    async def check_website(self, host):
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(f"http://{host}") as response:
                    html = await response.text()
                    soup = BeautifulSoup(html, 'html.parser')
                    return {
                        'title': soup.title.string if soup.title else None,
                        'headers': dict(response.headers),
                        'status': response.status
                    }
        except Exception as e:
            self.logger.error(f"Website check failed for {host} - {str(e)}")
            return None

    def check_dns(self, domain):
        try:
            records = {}
            for qtype in ['A', 'AAAA', 'MX', 'NS', 'TXT']:
                try:
                    answers = dns.resolver.resolve(domain, qtype)
                    records[qtype] = [str(rdata) for rdata in answers]
                except dns.resolver.NoAnswer:
                    records[qtype] = []
            return records
        except Exception as e:
            self.logger.error(f"DNS check failed for {domain} - {str(e)}")
            return None

    def check_whois(self, domain):
        try:
            w = whois.whois(domain)
            return {
                'registrar': w.registrar,
                'creation_date': w.creation_date,
                'expiration_date': w.expiration_date
            }
        except Exception as e:
            self.logger.error(f"WHOIS check failed for {domain} - {str(e)}")
            return None

    def fast_scan(self, target):
        nm = nmap.PortScanner()
        try:
            nm.scan(target, arguments='-F -T4')
            return nm[target]
        except Exception as e:
            self.logger.error(f"Fast scan failed for {target} - {str(e)}")
            return None

    def deep_scan(self, target):
        nm = nmap.PortScanner()
        try:
            nm.scan(target, arguments='-sS -sV -sC -A -O -p- -T4')
            return nm[target]
        except Exception as e:
            self.logger.error(f"Deep scan failed for {target} - {str(e)}")
            return None

    def vuln_scan(self, target):
        nm = nmap.PortScanner()
        try:
            nm.scan(target, arguments='--script vuln -sV -T4')
            return nm[target]
        except Exception as e:
            self.logger.error(f"Vulnerability scan failed for {target} - {str(e)}")
            return None

    def arp_scan(self, network):
        try:
            ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=network), timeout=2, verbose=False)
            return [rcv[1].psrc for snd, rcv in ans]
        except Exception as e:
            self.logger.error(f"ARP scan failed for {network} - {str(e)}")
            return []

    async def scan_host(self, host, scan_type='quick'):
        results = {
            'status': 'unknown',
            'open_ports': [],
            'vulnerabilities': [],
            'ssl_info': None,
            'website_info': None,
            'dns_info': None,
            'whois_info': None
        }

        try:
            # Port scanning
            if scan_type == 'quick':
                scan_result = self.fast_scan(host)
            elif scan_type == 'deep':
                scan_result = self.deep_scan(host)
            else:  # vuln
                scan_result = self.vuln_scan(host)

            if scan_result:
                results['status'] = 'up'
                for proto in scan_result.get('tcp', {}):
                    if scan_result['tcp'][proto]['state'] == 'open':
                        results['open_ports'].append({
                            'port': proto,
                            'service': scan_result['tcp'][proto].get('name', 'unknown'),
                            'version': scan_result['tcp'][proto].get('version', 'unknown')
                        })

                # Check SSL for HTTPS ports
                if 443 in results['open_ports']:
                    results['ssl_info'] = await self.check_ssl(host, 443)

                # Check website if HTTP port is open
                if 80 in results['open_ports']:
                    results['website_info'] = await self.check_website(host)

                # DNS and WHOIS checks
                results['dns_info'] = self.check_dns(host)
                results['whois_info'] = self.check_whois(host)

        except Exception as e:
            self.logger.error(f"Host scan failed for {host} - {str(e)}")
            results['status'] = 'error'

        return results

    async def run_scan(self, target, interface, scan_type='quick'):
        self.interface = interface
        self.results = {}
        
        # Get list of hosts to scan
        if '/' in target:  # Network range
            hosts = self.arp_scan(target)
        else:  # Single host
            hosts = [target]

        # Create tasks for each host
        tasks = []
        for host in hosts:
            tasks.append(self.scan_host(host, scan_type))

        # Run all scans concurrently
        results = await asyncio.gather(*tasks)
        
        # Combine results
        for host, result in zip(hosts, results):
            self.results[host] = result

        return self.results

    def monitor_traffic(self, interface):
        def packet_callback(packet):
            if IP in packet:
                src_ip = packet[IP].src
                dst_ip = packet[IP].dst
                proto = packet[IP].proto
                size = len(packet)
                self.logger.info(f"Traffic: {src_ip} -> {dst_ip} (Proto: {proto}, Size: {size} bytes)")

        sniff(iface=interface, prn=packet_callback, store=0)

def main():
    if not ctypes.windll.shell32.IsUserAnAdmin():
        print(f"{Fore.RED}[-] This script must be run as administrator{Style.RESET_ALL}")
        sys.exit(1)

    parser = argparse.ArgumentParser(description='Advanced Network Security Tool')
    parser.add_argument('-i', '--interface', help='Network interface to use')
    parser.add_argument('-t', '--target', help='Target IP or network')
    parser.add_argument('-m', '--mode', choices=['quick', 'deep', 'vuln'], default='quick',
                      help='Scan mode (quick, deep, or vuln)')
    parser.add_argument('--gui', action='store_true', help='Launch GUI interface')
    args = parser.parse_args()

    if args.gui:
        from gui import main as gui_main
        gui_main()
        return

    if not args.target:
        print(f"{Fore.RED}[-] Please specify a target using -t or --target{Style.RESET_ALL}")
        sys.exit(1)

    tool = NetworkSecurityTool()
    asyncio.run(tool.run_scan(args.target, args.interface, args.mode))

if __name__ == "__main__":
    main() 
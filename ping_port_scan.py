import os
import argparse
from ipaddress import ip_network
import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import IP, TCP, ICMP, sr1
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

RED = '\033[31m'
GREEN = '\033[32m'
BLUE = '\033[34m'
RESET = '\033[0m'


mutex = Lock()
MAX_THREADS = os.cpu_count()

def ping(ip):
    ans = sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0)
    if ans is not None:
        return str(ip)
    return None

def sweep(network, netmask,t):
    
    scanned_hosts = 0
    live_hosts = []
    hosts =  list(ip_network(network + '/' + netmask).hosts())
    total_hosts = len(hosts)
    
    with ThreadPoolExecutor(max_workers=t) as executor:
        futures = {executor.submit(ping,ip): ip for ip in hosts}
        for i, future in enumerate(as_completed(futures), start=1):
            host = futures[future]
            res = future.result()
            with mutex:
                scanned_hosts+=1
                print(f"Scanning hosts: {scanned_hosts}/{total_hosts}",end='\r')
                if res is not None:
                    print(f"{GREEN}Host found at: {host}{RESET}")
                    live_hosts.append(res)
                    
    return live_hosts 

def p_scan(ip, port):
    res = sr1(IP(dst=ip)/TCP(dport=port, flags='S'),timeout=1, verbose=0)
    if res is not None and res[TCP].flags == "SA":
        return port
    return None


def port_scan(ip,total_ports,t):
    
    scanned_ports = 0
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=t) as executor:
        futures = {executor.submit(p_scan,ip,port) : port for port in range(1,total_ports)}
        for i, future in enumerate(as_completed(futures),start=1):
            port = futures[future]
            res = future.result()
            with mutex:
                scanned_ports +=1
                print(f"Scanning ports: {scanned_ports} / {total_ports} ",end='\r')
                if res is not None:
                    open_ports.append(port)
            
    return open_ports
   

def main(args):
    thread_count = MAX_THREADS if args.threads and args.threads > MAX_THREADS else (args.threads if args.threads else 1)
    total_ports = args.port if args.port else 1024
    network = args.network
    netmask = args.mask 
    
    live_hosts = sweep(network, netmask, thread_count)
    host_port_mapping = {}
    
    for host in live_hosts: 
        open_ports = port_scan(host, total_ports, thread_count)
        host_port_mapping[host] = open_ports

    return host_port_mapping
    


if __name__ == "__main__":
    
    parser = argparse.ArgumentParser(description="Flags for scanner")
    parser.add_argument("-n", "--network", required=True, help="Target network")
    parser.add_argument("-m", "--mask", required=True, help="Network mask")
    parser.add_argument("-p", "--port", type=int, required=False, help="Target port limit")
    parser.add_argument("-t", "--threads", type=int, required=False, help="Thread count")
    args = parser.parse_args()
    
    host_ports = main(args)
    
    for host, ports in host_ports.items():
        print(f"For {host} open ports: [{ports}]")
    
    

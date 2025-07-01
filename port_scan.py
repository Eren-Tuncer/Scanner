import os
import argparse
from netaddr import IPNetwork
from scapy.all import IP, TCP, ICMP, sr1
from threading import Lock
from concurrent.futures import ThreadPoolExecutor, as_completed

print_lock = Lock()
MAX_THREADS = os.cpu_count()

def ping(ip):
    ans = sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0)
    if ans is not None:
        return str(ip)
    return None

def sweep(network, netmask,t):
    total_hosts = 0
    scanned_hosts = 0
    live_hosts = []
    ip_network = IPNetwork(network+'/'+netmask)
    
    for ip in ip_network.iter_hosts():
        total_hosts += 1
    
    for ip in ip_network.iter_hosts():
        scanned_hosts+=1
        print(f"[*] Scanning Hosts {scanned_hosts}/{total_hosts}",end="\r")
        ans = ping(str(ip))
        if ans is not None:
            live_hosts.append(ip)
        
    return live_hosts 

def p_scan(ip, port):
    res = sr1(IP(ip)/TCP(dport=port, flags='S'),timeout=1, verbose=0)
    if res is not None and res[TCP].flags == "SA":
        return port
    return None


def port_scan(ip,ports,t):
    
    scaned_ports = 0
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=t) as executor:
        futures = {executor.submit(p_scan, (ip, port)): port for port in range(1,ports)}
        for i, future in enumerate()
    
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
    
    
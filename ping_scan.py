import sys
from scapy.all import IP, ICMP, sr1
from netaddr import IPNetwork



def sweep(network, netmask):
    total_hosts = 0
    scanned_hosts = 0
    live_hosts = []
    
    ip_network = IPNetwork(network+'/'+netmask)
    
    for ip in ip_network.iter_hosts():
        total_hosts += 1
    for ip in ip_network.iter_hosts():
        scanned_hosts+=1
        print(f"[*] Scanning Hosts {scanned_hosts}/{total_hosts}",end="\r")
        ans = sr1(IP(dst=str(ip))/ICMP(),timeout=1,verbose=0)
        if ans is not None:
            live_hosts.append(ip)
        
    return live_hosts    


if __name__ == "__main__":
    
    network_addr = sys.argv[1]
    netmask = sys.argv[2]
    
    alive_hosts = sweep(network_addr, netmask)
    print("Completed\n")
    print(f"Live hosts: {alive_hosts}")
    
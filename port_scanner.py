
import socket
import nmap
import common_ports
import re
import os

def get_open_ports(target, port_range, verbose = False):
    open_ports = []

    scanner = nmap.PortScanner()

    try:
        ip_list = list({addr[-1][0] for addr in socket.getaddrinfo(target, 0, 0, 0, 0)})
    except Exception:
        if re.search('[a-zA-Z]', target):
            return("Error: Invalid hostname")
        else:
            return("Error: Invalid IP address")
    ip_addr = ip_list[0]
    
    scanner.scan(ip_addr, f'22-445', '-v -sS')
    # scanner.scan(ip_addr, f'{port_range[0]}-{port_range[1]}', '-sS', sudo=True)
    
    
    
    
    open_ports_within_range = []
    open_ports = list(scanner[ip_addr]['tcp'].keys())
    for port in open_ports:
        if port_range[0] <= port and port <= port_range[1]:
            open_ports_within_range.append(port)
    
    open_ports = open_ports_within_range

    if verbose:
        nameinfo = socket.getnameinfo((ip_addr, 0), 0)[0]
        if nameinfo != ip_addr:
            output = f"Open ports for {nameinfo} ({ip_addr})"
        else:
            output = f"Open ports for {ip_addr}"
            
        output += f"\nPORT     SERVICE"
        
        for port in open_ports:
            output += f"\n{port}      {common_ports.ports_and_services[port]}"
        return(output)
    else:
        return(open_ports)

# r = get_open_ports("192.168.0.1", [75, 80])
# r = get_open_ports("209.216.230.240", [440, 445], False)
# print('r: ', r)
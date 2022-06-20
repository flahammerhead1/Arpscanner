#!/bin/bash/python3
# Arp Scan of given subnet
# Written by Arjay with help from Google
# Adjust timeout (currently at 15sec) for large host subnets

from scapy.all import ARP, Ether, srp
import sys, ipaddress, os


#Get and Check input
def getinputandChecklength():
    # input = str(sys.argv)
    if len(sys.argv) != 2:
        print('use: arpscan.py <ip subnet>: i.e. arpscan 192.168.0.0/24')
        exit(0)
   
#Check for valid IP address and Subnet Mask   
def checkforvalid_ipaddress():
    ipandsubnet = sys.argv[1].split("/")
    ip = ipandsubnet[0]
    ipsubnet = ipandsubnet[1]
    if  int(ipsubnet) not in range(22, 33):
        print('Subnet Mask Range 22 to 32 only')
        exit(0)
        
    try:
        tryip = ipaddress.ip_network(ip)
        #print(str(sys.argv[1]) + ' is a valid address')
    
    except ValueError:
        print('address/netmask is invalid: %s' % sys.argv[1])
        print('use: arpscan.py <ip subnet>: i.e. arpscan 192.168.0.0/24')
        exit(0)
        

def getResults():
    target_ip = sys.argv[1]
    print ('Running arpscan on', target_ip) #create ARP packets
    arp = ARP(pdst=target_ip)  
    ether = Ether(dst="ff:ff:ff:ff:ff:ff") # create broadcast packet
    packet = ether/arp # stack them
    
    try:
        result = srp(packet, timeout=15, verbose=1)[0]
        
    except OSError as error:
        print(error)
        print('Try running as root')
        exit(0) 
            
    clients = [] # a list of clients filled in the following loop
        
    for sent, received in result:
        # for each response, append ip and mac address to `clients` list
        clients.append({'ip': received.psrc, 'mac': received.hwsrc})
        
    # print clients
    print("Available devices in the network:")
    print("IP" + " "*18+"MAC")

    for client in clients:
        print("{:16}    {}".format(client['ip'], client['mac']))


if __name__ == "__main__":
    getinputandChecklength()
    checkforvalid_ipaddress()
    getResults()
    

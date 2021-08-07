import scapy.all as scapy,argparse
from termcolor import colored

#use .show() for all the options
#use .summary() for the summary for scapy packets

def main():
    parser = argparse.ArgumentParser(description="This is a simple network scanning tool")
    parser.add_argument('--ip',help="IP address of the machine, xxx.xxx.xxx.xxx/x format")
    option = parser.parse_args()
    scanner(option.ip)


def scanner(ip):
    arp_request=scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst='ff:ff:ff:ff:ff:ff')
    full_packet = broadcast/arp_request # It's important to keep the order like this broadcast/arp_request
    answered_list = scapy.srp(full_packet,timeout=2,verbose=False) # srp is  for sending and receiving custom packets
    
    dict_list=[]
    for element in answered_list[0]:
        dict_list.append({'ip':element[1].psrc,'mac':element[1].hwsrc})
    print_result(dict_list)


def print_result(dict_list):        
    print(colored("IP\t\t\tMAC Address",'magenta'))
    print(colored("------------------------------------------","green"))
    for element in dict_list:
        print(f"{element['ip']}\t\t{element['mac']}")


if __name__ == '__main__':
    main()
#!/usr/bin/env python

import scapy.all as scapy
import optparse

def get_arguments():
	parser = optparse.OptionParser()
	parser.add_option('-t', '--target', dest='target', help='target IP range to scan')
	(options, arguments)= parser.parse_args()
	return options

def scan(ip):
	arp_request = scapy.ARP(pdst=ip)
	print(arp_request.summary())

	broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
	# print(broadcast.summary())

	arp_request_broadcast = broadcast/arp_request
	# print(arp_request_broadcast.summary())
	# arp_request_broadcast.show()

	## Allows us to send and recieve a packet with ether
	answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
	# print(answered_list.summary())

	## list all fields that you can set in the ARP and Ether class
	# scapy.ls(scapy.ARP())
	# scapy.ls(scapy.Ether())


	clients_list = []

	for element in answered_list:
		client_dict = {'ip': element[1].psrc, 'mac':element[1].hwsrc}
		clients_list.append(client_dict)
		
	return clients_list

def print_result(results_list):
	print('IP\t\t\tMAC Address\n')
	print('----------------------------------------')
	for client in results_list:
		print(client['ip']+'\t\t'+client['mac'])
	# print(element[1].psrc + '\t\t' + element[1].hwsrc)

options = get_arguments()
scan_result = scan(options.target)
print_result(scan_result)

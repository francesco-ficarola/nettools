# -*- coding: utf-8 -*-

# Author: Francesco Ficarola

import sys, os, platform, re, socket
from collections import OrderedDict

# Dependencies
from colorama import init
from colorama import Fore, Back, Style
from netaddr import IPNetwork, IPAddress

NET_REGEX = '^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\/([0-9]|[1-2][0-9]|3[0-2])$'
IP_REGEX = '^([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])\.([0-9]|[1-9][0-9]|1[0-9][0-9]|2[0-5][0-5])$'
PORTS_REGEX = '^(\d{1,5}(\s*,\s*\d{1,5})*)?$'

# Menu items
LOCAL = '1'
INFO = '2'
NET = '3'
PING = '4'
PORT = '5'
ARP = '6'
TRACE = '7'
EXIT = '0'
BACK = '99'

# Menu strings
OPTIONS = OrderedDict([
	(LOCAL			,	' Get information about your system'),
	(INFO			,	' DNS lookup'),
	(NET			,	' Get information about a network'),
	(PING			,	' Check if you can reach an IPv4'),
	(PORT			,	' Perform a port scan on an IPv4'),
	(ARP			,	' Check ARP cache'),
	(TRACE			,	' Perform a trace route'),
	(EXIT			,	' Exit')
])


def header():
	print Style.BRIGHT + Fore.RED + '''\
  _   _      _  _____           _     ____        
 | \ | | ___| ||_   _|__   ___ | |___|  _ \ _   _ 
 |  \| |/ _ \ __|| |/ _ \ / _ \| / __| |_) | | | |
 | |\  |  __/ |_ | | (_) | (_) | \__ \  __/| |_| |
 |_| \_|\___|\__||_|\___/ \___/|_|___/_|    \__, |
                                            |___/ 
	'''

	print Style.RESET_ALL + '''\
 Author: Francesco Ficarola
 GitHub: https://github.com/francesco-ficarola/nettools
 ------------------------------------------------------------
	'''


# http://stackoverflow.com/questions/2532053/validate-a-hostname-string
def isValidHostname(hostname):
	if len(hostname) > 255:
		return False
	if hostname[-1] == '.':
		hostname = hostname[:-1] # strip exactly one dot from the right, if present
	allowed = re.compile('(?!-)[A-Za-z\d-]{1,63}(?<!-)$')
	return all(allowed.match(x) for x in hostname.split('.'))


def menu():
	print ''
	print Style.BRIGHT + Fore.MAGENTA + ' MENU - AVAILABLE OPTIONS\n'
	for item in OPTIONS:
		print ' ' + Style.BRIGHT + Fore.YELLOW + item + ') ' + OPTIONS[item] + '\n'
	print ' ' + Style.BRIGHT + Fore.BLUE + '[' + BACK + '] ' +  'Go back to this menu\n' 
	item = raw_input('\n' + Style.BRIGHT + Fore.CYAN  + ' [*] Please enter a valid option:' + Style.RESET_ALL + ' ')
	return item


def localInfo():
	print Style.BRIGHT + Back.MAGENTA + Fore.WHITE
	print '------------------------------------------------------------'
	os.system('ipconfig' if  platform.system().lower() == 'windows' else 'ifconfig')
	print '------------------------------------------------------------' + Style.RESET_ALL
	print Style.BRIGHT + Back.BLUE + Fore.WHITE
	print '\n Hostname: ' + socket.gethostname()
	print([(s.connect(('8.8.8.8', 53)), ' IP --> Internet: ' + s.getsockname()[0], s.close()) for s in [socket.socket(socket.AF_INET, socket.SOCK_DGRAM)]][0][1])
	print Style.RESET_ALL
	raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
	print Style.RESET_ALL
	print '\n ------------------------------------------------------------\n\n'


def ipInfo():
	right_choice = False
	
	ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Enter an IPv4 or a hostname:' + Style.RESET_ALL + ' ')
	p = re.compile(IP_REGEX)
	while right_choice == False:
		if p.match(ipstr):
			try:
				ip = IPAddress(ipstr)
				print Style.BRIGHT + Back.BLUE + Fore.WHITE
				print '\n IP: ' + str(ip)
				print ' Hostname: ' + str(socket.gethostbyaddr(str(ip))[0])
				print Style.RESET_ALL
				
				raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except socket.herror:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' IP not found!'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' Manual break or fatal error!'
				print Style.NORMAL + Fore.RED + ' Please report this issue on GitHub if you think it is a bug.'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			right_choice = True
		elif isValidHostname(ipstr):
			try:
				print Style.BRIGHT + Back.BLUE + Fore.WHITE
				print '\n Hostname: ' + ipstr
				print ' IP: ' + str(socket.gethostbyname(ipstr))
				print Style.RESET_ALL
				
				raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except socket.gaierror:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' Hostname not found!'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' Manual break or fatal error!'
				print Style.NORMAL + Fore.RED +  ' Please report this issue on GitHub if you think it is a bug.'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			right_choice = True
		elif ipstr == BACK:
			right_choice = True
			print Style.BRIGHT + Fore.BLUE + '[' + BACK + '] ' +  ' Going back...\n'
		else:
			ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter a valid IPv4 or hostname:' + Style.RESET_ALL + ' ')
	

def netInfo():
	right_choice = False

	ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Enter your network in CIDR notation:' + Style.RESET_ALL + ' ')
	p = re.compile(NET_REGEX)
	while right_choice == False:
		if p.match(ipstr):
			try:
				ipcidr = IPNetwork(ipstr)
				ip = ipcidr.ip
				bits = ip.bits()
				net = ipcidr.network
				nmask = ipcidr.netmask
				bcast = ipcidr.broadcast
				hmask = ipcidr.hostmask
				num_hosts = (ipcidr.size - 2) if (ipcidr.size - 2) > 0 else 0
				print Style.BRIGHT + Back.BLUE + Fore.WHITE
				print '\n IP: ' + str(ip)
				print ' Bits: ' + str(bits)
				print ''
				print ' Network: ' + str(net)
				print ' Netmask: ' + str(nmask)
				print ' Broadcast: ' + str(bcast)
				print ''
				print ' Hostmask: ' + str(hmask)
				print ' Number of available hosts: ' + str(num_hosts)
				print Style.RESET_ALL
				
				raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' Manual break or fatal error!'
				print Style.NORMAL + Fore.RED + ' Please report this issue on GitHub if you think it is a bug.'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			right_choice = True
		elif ipstr == BACK:
			right_choice = True
			print Style.BRIGHT + Fore.BLUE + '[' + BACK + '] ' +  ' Going back...\n'
		else:
			ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter a valid network in CIDR notation (e.g., 192.168.1.5/24):' + Style.RESET_ALL + ' ')


def ping(host):
	print Style.BRIGHT + Back.MAGENTA + Fore.WHITE
	print '------------------------------------------------------------'
	ping_str = '-n 1' if  platform.system().lower() == 'windows' else '-c 1'
	result = os.system('ping ' + ping_str + ' ' + host) == 0
	print '------------------------------------------------------------' + Style.RESET_ALL
	return result


def pingIP():
	right_choice = False
	
	ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Enter your IPv4:' + Style.RESET_ALL + ' ')
	p = re.compile(IP_REGEX)
	while right_choice == False:
		if p.match(ipstr):
			try:
				ip = IPAddress(ipstr)
				reachable = ping(str(ip))
				print Style.BRIGHT + Back.BLUE + Fore.WHITE
				if reachable:
					print '\n IP ' + str(ip) + ' is reachable from your machine!'
				else:
					print '\n IP ' + str(ip) + ' is NOT reachable from your machine!'
				print Style.RESET_ALL
				
				raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' Manual break or fatal error!'
				print Style.NORMAL + Fore.RED + ' Please report this issue on GitHub if you think it is a bug.'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			right_choice = True
		elif ipstr == BACK:
			right_choice = True
			print Style.BRIGHT + Fore.BLUE + '[' + BACK + '] ' +  ' Going back...\n'
		else:
			ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter a valid IPv4 (e.g., 192.168.1.5):' + Style.RESET_ALL + ' ')


def ipPorts(ip, ports, export):
	opened = []
	closed = []
	print Style.BRIGHT + Back.MAGENTA + Fore.WHITE
	print '------------------------------------------------------------'
	sys.stdout.write('Scanning... ')
	for index, port in enumerate(ports):
		status = ''
		s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		s.settimeout(1)
		result = s.connect_ex((ip, port))
		s.close()
		if result == 0:
			opened.append(port)
			status = 'O'
		else:
			closed.append(port)
			status = 'C'

		if index < len(ports)-1:
			sys.stdout.write(str(port) + ' (' + status + '), ')
		else:
			sys.stdout.write(str(port) + ' (' + status + ')\n')
	print '------------------------------------------------------------' + Style.RESET_ALL
	print Style.BRIGHT + Back.BLUE + Fore.WHITE
	print '\n Open ports: ' + str(opened)
	print '\n Closed ports: ' + str(closed)
	if export:
		try:
			f = file(ip + '.txt', 'w')
			f.write('Open ports: ' + str(opened) + '\n')
			f.write('Closed ports: ' + str(closed) + '\n')
			f.flush()
			f.close()
			print '\n Results saved in ' + ip + '.txt'
		except:
			print Style.RESET_ALL
			print '\n' + Style.BRIGHT + Fore.RED +  ' ERROR: could not create the file!'
			print Style.RESET_ALL
	print Style.RESET_ALL
	raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
	print Style.RESET_ALL
	print '\n ------------------------------------------------------------\n\n'


def checkPorts():
	right_choice_ip = False

	export = False	
	exportstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Would you like to export the result? [y/N]' + Style.RESET_ALL + ' ')
	if exportstr == 'y' or exportstr == 'Y':
		export = True

	ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Enter your IPv4:' + Style.RESET_ALL + ' ')
	p = re.compile(IP_REGEX)
	while right_choice_ip == False:
		if p.match(ipstr):
			ip = IPAddress(ipstr)
			right_choice_ports = False
			portstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Enter ports in CSV format (e.g., 53,80,8080) or \'*\' for a full scan:' + Style.RESET_ALL + ' ')

			z = re.compile(PORTS_REGEX)
			while right_choice_ports == False:
				if z.match(portstr):
					ports = [int(port.strip()) for port in portstr.split(',')]
					if len(set(ports)) != len(ports):
						ports = list(set(ports))
					if all(i > 0 and i < 65536 for i in ports):
						ipPorts(str(ip), ports, export)
						right_choice_ports = True
					else:
						print Style.RESET_ALL
						print '\n' + Style.BRIGHT + Fore.RED +  ' ERROR: all ports must be in range 1-65535!'
						print Style.RESET_ALL
						portstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter ports in CSV format (e.g., 53,80,8080) or \'*\' for a full scan:' + Style.RESET_ALL + ' ')
				elif portstr == '*':
					ports = range(1, 65536)
					ipPorts(str(ip), ports, export)
					right_choice_ports = True
				else:
					portstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter ports in CSV format (e.g., 53,80,8080) or \'*\' for a full scan:' + Style.RESET_ALL + ' ')
			
			right_choice_ip = True
		elif ipstr == BACK:
			right_choice_ip = True
			print Style.BRIGHT + Fore.BLUE + '[' + BACK + '] ' +  ' Going back...\n'
		else:
			ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter a valid IPv4 (e.g., 192.168.1.5):' + Style.RESET_ALL + ' ')


def checkARP():
	print Style.BRIGHT + Back.MAGENTA + Fore.WHITE
	print '------------------------------------------------------------'
	
	os.system('arp -a')

	print '------------------------------------------------------------' + Style.RESET_ALL

	raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
	print Style.RESET_ALL
	print '\n ------------------------------------------------------------\n\n'


def trace(host):
	print Style.BRIGHT + Back.MAGENTA + Fore.WHITE
	print '------------------------------------------------------------'
	trace_str = 'tracert' if  platform.system().lower() == 'windows' else 'tracepath'
	os.system(trace_str + ' ' + host) == 0
	print '------------------------------------------------------------' + Style.RESET_ALL
	

def traceIP():
	right_choice = False
	
	ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Enter your IPv4:' + Style.RESET_ALL + ' ')
	while right_choice == False:
		p = re.compile(IP_REGEX)
		if p.match(ipstr):
			try:
				ip = IPAddress(ipstr)
				trace(str(ip))				
				raw_input('\n' + Style.BRIGHT + Fore.BLUE  + ' Press Enter to continue...')
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			except:
				print Style.RESET_ALL
				print '\n' + Style.BRIGHT + Fore.RED +  ' Manual break or fatal error!'
				print Style.NORMAL + Fore.RED + ' Please report this issue on GitHub if you think it is a bug.'
				print Style.RESET_ALL
				print '\n ------------------------------------------------------------\n\n'
			right_choice = True
		elif ipstr == BACK:
			right_choice = True
			print Style.BRIGHT + Fore.BLUE + '[' + BACK + '] ' +  ' Going back...\n'
		else:
			ipstr = raw_input('\n' + Style.BRIGHT + Fore.GREEN  + ' [*] Please, enter a valid IPv4 (e.g., 192.168.1.5):' + Style.RESET_ALL + ' ')
				

def main():

	init()
	header()
	
	exit = False
	while exit == False:
		item = menu()

		if item == LOCAL:
			localInfo()
		
		elif item == INFO:
			ipInfo()

		elif item == NET:
			netInfo()

		elif item == PING:
			pingIP()

		elif item == PORT:
			checkPorts()

		elif item == ARP:
			checkARP()

		elif item == TRACE:
			traceIP()
			
		elif item == EXIT:
			exit = True
			
		else:
			print '\n' + Style.BRIGHT + Fore.RED + ' ERROR: Option not valid!'
			print Style.RESET_ALL
			print '\n ------------------------------------------------------------\n\n'
			

if __name__ == '__main__':
	main()

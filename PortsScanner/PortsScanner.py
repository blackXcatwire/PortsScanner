import nmap

print("*.*.*.*.*.*.*.*.*.*.*.*.*..*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*")

print("<*W*E*L*L*C*O*M*E**T*O**N*A*M*P**S*C*A*N*N*E*R**I*N**P*Y*T*H*O*N*3*_*>")

print("*.*.*.*.*.*.*.*.*.*.*.*.*..*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*.*")

scanner = nmap.PortScanner()

ip_addr = input("< Enter The IP Address You Want TO Scan >: ")
print("This is the IP you Want to Scan:", ip_addr)
type(ip_addr)

resp = input("""\nPlease enter the type of scan you want to run
                1)SYN ACK Scan
                2)UDP Scan
                3)Comprehensive Scan
                4)Regular Scan
                5)OS Detection
                6)Multiple IP inputs
                7)Ping Scan
                8)Full Scan\n""")

print("You have selected option: ", resp)
 

if resp == '1':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr,'1-65535', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print("protocols:",scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '2':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-v -sU')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print("protocols:",scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['udp'].keys())
elif resp == '3':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-v -sS -sV -sC -A -O')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '4':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr)
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print("protocols:",scanner[ip_addr].all_protocols())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
elif resp == '5':
    print(scanner.scan[ip_addr], arguments="-O"),+['scan'][ip_addr],['osmatch']
elif resp == '6':
    ip_addr = input()
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr,'1-65535', '-v -sS')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print("protocols:",scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())     
elif resp == '7': 
    scanner.scan(hosts=ip_addr, arguments='-n -sP -PE -PA')
    hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
    for host, status in hosts_list:
        print('{0}:{1}'.format(host, status))
elif resp == '8':
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-65535', '-vvv -sV -sC -A -T4')
    print(scanner.scaninfo())
    print("Ip Status: ", scanner[ip_addr].state())
    print("protocols:",scanner[ip_addr].all_protocols())
    print(scanner[ip_addr].all_protocols())
    print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
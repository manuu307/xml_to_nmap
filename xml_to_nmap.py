import xml.etree.ElementTree as ET
import subprocess
import sys

# Function to parse Nmap XML report and extract IPs and open ports
def parse_nmap_report(xml_file):
    tree = ET.parse(xml_file)
    root = tree.getroot()
    targets = []

    for host in root.findall('host'):
        ip = host.find('address').get('addr')
        ports = []
        for port in host.findall('ports/port'):
            if port.find('state').get('state') == 'open':
                ports.append(port.get('portid'))
        if ports:
            targets.append((ip, ports))

    return targets

# Function to generate and execute Nmap commands for targeted scans
def scan_target_ports(targets, nmap_command):
    for ip, ports in targets:
        port_list = ','.join(ports)
        command = f'{nmap_command} -p {port_list} {ip} -oN {ip}.txt'
        subprocess.run(command, shell=True)

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python script.py <xml_file_path> <nmap_command>")
        sys.exit(1)
    
    xml_file_path = sys.argv[1]
    nmap_command = sys.argv[2]
    
    # Parse the Nmap XML report and get IPs and open ports
    targets = parse_nmap_report(xml_file_path)

    # Scan the open ports for each IP address
    scan_target_ports(targets, nmap_command)

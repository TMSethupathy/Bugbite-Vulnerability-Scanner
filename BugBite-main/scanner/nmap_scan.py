import nmap

def nmap_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV -sC -F -T4')
    results = []
    for host in scanner.all_hosts():
        for protocol in scanner[host].all_protocols():
            ports = scanner[host][protocol].keys()
            for port in ports:
                if port in [21, 22, 25, 53, 80, 110, 445, 3306, 389, 161] and scanner[host][protocol][port]['state'] == 'open':
                    service_name = scanner[host][protocol][port]['name']
                    product = scanner[host][protocol][port].get('product', 'Unknown')
                    version = scanner[host][protocol][port].get('version', 'Unknown')
                    scripts = scanner[host][protocol][port]['script']
                    for script_name, script_data in scripts.items():
                        if (service_name == 'ftp' and 'ftp-' not in script_name) or \
                           (service_name == 'http' and 'http-' not in script_name) or \
                           (service_name == 'ssh' and 'ssh-' not in script_name) or \
                           (service_name == 'https' and 'ssl-' not in script_name) or \
                           (service_name == 'mysql' and 'mysql-' not in script_name) or \
                           (service_name == 'smtp' and 'smtp-' not in script_name) or \
                           (service_name == 'telnet' and 'telnet-' not in script_name) or \
                           (service_name == 'smb' and 'smb-' not in script_name) or \
                           (service_name == 'dns' and 'dns-' not in script_name) or \
                           (service_name == 'ldap' and 'ldap-' not in script_name) or \
                           (service_name == 'netbios-ssn' and 'nbstat-' not in script_name) or \
                           (service_name == 'snmp' and 'snmp-' not in script_name):
                             continue
                        results.append({
                            'name': service_name,
                            'port': port,
                            'product': product,
                            'version': version,
                            'script_name': script_name,
                            'script_data': script_data,
                        })
    return results
    

def os_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-O  -T4')
    os_info=[]
    for host in scanner.all_hosts():
        os_matches = scanner[host]['osmatch']

        
        for os_match in os_matches:
            OSName= os_match['name']
            Accuracy= os_match['accuracy']
            os_classes = os_match['osclass']
            for os_class in os_classes:
                OSFamily= os_class['osfamily']
                Type= os_class['type']
                Vendor= os_class['vendor']

                result={'OSName':OSName,'Accuracy':Accuracy,'OSFamily':OSFamily,'Type':Type,'Vendor':Vendor}

            os_info.append(result)

    return os_info

    
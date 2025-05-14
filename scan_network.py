import nmap

def scan_network():
    nm = nmap.PortScanner()
    nm.scan(hosts='192.168.1.0/24', arguments='-sn')  # الـ IP range الخاص بالشبكة

    devices = []
    for host in nm.all_hosts():
        if 'mac' in nm[host]:
            devices.append((host, nm[host]['addresses']['mac']))  # حفظ الـ IP والـ MAC
    return devices

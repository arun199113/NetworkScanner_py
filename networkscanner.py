import socket
import ipaddress
import threading
import psutil
from ping3 import ping
import tkinter as tk
from tkinter.scrolledtext import ScrolledText


def scan_device(ip, network_name, output):
    response = ping(str(ip), timeout=1)
    if response:
        try:
            hostname = socket.gethostbyaddr(str(ip))[0]
        except socket.herror:
            hostname = 'Unknown Hostname'
        output.insert(tk.END, f"[+] {network_name}: Device found: {ip} ({hostname})\n")
        output.see(tk.END)


def scan_network(interface, addresses, output):
    for addr in addresses:
        if addr.family == socket.AF_INET:
            ip_interface = ipaddress.ip_interface(f"{addr.address}/{addr.netmask}")
            network = ip_interface.network
            output.insert(tk.END, f"\nScanning Network: {interface} - {network}\n")
            output.see(tk.END)

            threads = []
            for ip in network.hosts():
                thread = threading.Thread(target=scan_device, args=(ip, interface, output))
                threads.append(thread)
                thread.start()

            for thread in threads:
                thread.join()


def start_scan(output):
    output.delete(1.0, tk.END)
    interfaces = psutil.net_if_addrs()
    for interface, addresses in interfaces.items():
        threading.Thread(target=scan_network, args=(interface, addresses, output)).start()


def create_gui():
    root = tk.Tk()
    root.title("Network Scanner")

    output = ScrolledText(root, width=80, height=25)
    output.pack(padx=10, pady=10)

    scan_button = tk.Button(root, text="Scan Networks", command=lambda: start_scan(output))
    scan_button.pack(pady=5)

    root.mainloop()


if __name__ == "__main__":
    create_gui()

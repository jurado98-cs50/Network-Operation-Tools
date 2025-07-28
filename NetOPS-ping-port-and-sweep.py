import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import ipaddress
import socket
import dns.resolver
import dns.reversename
import subprocess
import platform
import threading
import concurrent.futures
import csv

def show_license_on_start():
    license_text = """
MIT License

Copyright (c) 2025 Daniel Jurado

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
"""
    messagebox.showinfo("License Agreement", license_text)

stop_scan = False

def ping(ip):
    param = "-n" if platform.system().lower() == "windows" else "-c"
    try:
        kwargs = {
            "stdout": subprocess.DEVNULL,
            "stderr": subprocess.DEVNULL,
            "timeout": 2
        }

        if platform.system().lower() == "windows":
            kwargs["creationflags"] = subprocess.CREATE_NO_WINDOW

        result = subprocess.run(["ping", param, "1", str(ip)], **kwargs)
        return result.returncode == 0
    except subprocess.TimeoutExpired:
        return False
    except:
        return False


def resolve_hostname(ip, use_local=False, custom_dns=None):
    try:
        ip_str = str(ip)
        rev_name = dns.reversename.from_address(ip_str)

        resolver = dns.resolver.Resolver()
        resolver.lifetime = 3.0

        if custom_dns:
            # Resolve hostnames to IPs if needed
            valid_dns = []
            for dns_entry in custom_dns:
                try:
                    # If it's already an IP, this just returns it
                    resolved = socket.gethostbyname(dns_entry)
                    valid_dns.append(resolved)
                except socket.gaierror:
                    continue  # skip invalid DNS entries
            if valid_dns:
                resolver.nameservers = valid_dns
        elif not use_local:
            resolver.nameservers = ['8.8.8.8', '8.8.4.4']
        # else use system defaults

        answer = resolver.resolve(rev_name, "PTR")
        return str(answer[0]).rstrip('.')

    except (dns.resolver.NXDOMAIN, dns.resolver.Timeout, dns.resolver.NoNameservers):
        return "No Hostname"
    except Exception as e:
        return f"Error: {e}"

def scan_single_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.2)
            if sock.connect_ex((str(ip), port)) == 0:
                return port
    except:
        return None
    return None

def scan_ports_multithreaded(ip, ports):
    open_ports = []
    max_threads = min(50, len(ports))
    with concurrent.futures.ThreadPoolExecutor(max_workers=max_threads) as executor:
        futures = {executor.submit(scan_single_port, ip, port): port for port in ports}
        for future in concurrent.futures.as_completed(futures):
            if stop_scan:
                break
            result = future.result()
            if result:
                open_ports.append(result)
    return open_ports

def scan_ip(ip, ports, scan_ports_enabled, listbox, results, progress_var, use_local_dns, custom_dns_str):
    global stop_scan
    if stop_scan:
        return

    alive = ping(ip)
    custom_dns = [dns.strip() for dns in custom_dns_str.split(',') if dns.strip()]
    hostname = resolve_hostname(ip, use_local=use_local_dns, custom_dns=custom_dns) if alive else "-"

    open_ports = scan_ports_multithreaded(ip, ports) if alive and scan_ports_enabled else []

    status = "live" if alive else "Not Responding"
    port_str = ', '.join(str(p) for p in open_ports) if open_ports else "No match"

    color = "green" if alive else "red"
#    output = f"{ip} | {status:<15} | {hostname:<30} | Ports: {port_str}"
#    listbox.insert(tk.END, output)
#    listbox.itemconfig(tk.END, {'fg': color})
    if scan_ports_enabled:
        output = f"{ip} | {status:<15} | {hostname:<30} | Ports: {port_str}"
    else:
        output = f"{ip} | {status:<15} | {hostname:<30}"

    # Safely update the UI from the main thread
    listbox.after(0, lambda: (
        listbox.insert(tk.END, output),
        listbox.itemconfig(tk.END, {'fg': color})
    ))

    results.append({
        "IP": str(ip),
        "Status": status,
        "Hostname": hostname,
        "Open Ports": port_str if scan_ports_enabled else "N/A"
    })

    listbox.after(0, lambda: progress_var.set(progress_var.get() + 1))


def start_scan(mode, start_ip, end_ip, cidr, ports, scan_ports_enabled, listbox, scan_button, cancel_button, export_button, progress_bar, use_local_dns, custom_dns_str):
    global stop_scan
    stop_scan = False
    scan_button.config(state=tk.DISABLED)
    cancel_button.config(state=tk.NORMAL)
    export_button.config(state=tk.DISABLED)
    listbox.delete(0, tk.END)
    #print(scan_ports_enabled)

    try:
        ports = [int(p.strip()) for p in ports.split(',') if p.strip().isdigit()]
        if not ports:
            raise ValueError
    except:
        messagebox.showerror("Invalid Port", "Enter valid port numbers separated by commas.")
        scan_button.config(state=tk.NORMAL)
        cancel_button.config(state=tk.DISABLED)
        return

    try:
        if mode == "range":
            start = ipaddress.IPv4Address(start_ip)
            end = ipaddress.IPv4Address(end_ip)
            if start > end:
                raise ValueError("Start IP must be before End IP.")
            ip_range = [ipaddress.IPv4Address(ip) for ip in range(int(start), int(end) + 1)]
        else:
            network = ipaddress.IPv4Network(cidr, strict=False)
            ip_range = list(network.hosts())
    except Exception as e:
        messagebox.showerror("Invalid IP Input", str(e))
        scan_button.config(state=tk.NORMAL)
        cancel_button.config(state=tk.DISABLED)
        return

    progress_var = tk.IntVar(value=0)
    progress_bar.config(maximum=len(ip_range), variable=progress_var)
    results = []

    def worker():
        for ip in ip_range:
            if stop_scan:
                break
            scan_ip(ip, ports, scan_ports_enabled, listbox, results, progress_var, use_local_dns, custom_dns_str)
        scan_button.config(state=tk.NORMAL)
        cancel_button.config(state=tk.DISABLED)
        export_button.config(state=tk.NORMAL)
        export_button.results = results
        listbox.insert(tk.END, "Scan canceled." if stop_scan else "Scan complete.")

    threading.Thread(target=worker, daemon=True).start()

def cancel_scan():
    global stop_scan
    stop_scan = True

def export_results(results):
    if not results:
        return
    file_path = filedialog.asksaveasfilename(defaultextension=".csv",
                                             filetypes=[("CSV files", "*.csv")])
    if file_path:
        with open(file_path, "w", newline="") as f:
            writer = csv.DictWriter(f, fieldnames=["IP", "Status", "Hostname", "Open Ports"])
            writer.writeheader()
            writer.writerows(results)
        messagebox.showinfo("Exported", f"Results saved to {file_path}")

def create_gui():
    root = tk.Tk()
    root.after(100, show_license_on_start)  # 🔹 Show MIT License on startup
    root.title("NetOPS IP Range and Port Scanner")
    root.geometry("880x500")
    root.minsize(800, 400)
    root.columnconfigure(1, weight=1)
    root.rowconfigure(8, weight=1)

    scan_mode = tk.StringVar(value="range")

    def toggle_mode():
        if scan_mode.get() == "range":
            start_ip_entry.config(state="normal")
            end_ip_entry.config(state="normal")
            cidr_entry.config(state="disabled")
        else:
            start_ip_entry.config(state="disabled")
            end_ip_entry.config(state="disabled")
            cidr_entry.config(state="normal")

    # Mode selection
    tk.Label(root, text="Scan Mode:").grid(row=0, column=0, sticky="e", padx=5, pady=5)
    mode_frame = tk.Frame(root)
    mode_frame.grid(row=0, column=1, sticky="w", padx=5, pady=5)
    tk.Radiobutton(mode_frame, text="IP Range", variable=scan_mode, value="range", command=toggle_mode).pack(side="left")
    tk.Radiobutton(mode_frame, text="CIDR", variable=scan_mode, value="cidr", command=toggle_mode).pack(side="left")

    tk.Label(root, text="Start IP:").grid(row=1, column=0, sticky="e", padx=5, pady=5)
    start_ip_entry = tk.Entry(root, width=20)
    start_ip_entry.grid(row=1, column=1, sticky="w", padx=5, pady=5)

    tk.Label(root, text="End IP:").grid(row=2, column=0, sticky="e", padx=5, pady=5)
    end_ip_entry = tk.Entry(root, width=20)
    end_ip_entry.grid(row=2, column=1, sticky="w", padx=5, pady=5)

    tk.Label(root, text="CIDR (e.g. 192.168.1.0/24):").grid(row=3, column=0, sticky="e", padx=5, pady=5)
    cidr_entry = tk.Entry(root, width=25, state="disabled")
    cidr_entry.grid(row=3, column=1, sticky="w", padx=5, pady=5)

    tk.Label(root, text="Ports (comma-separated):").grid(row=4, column=0, sticky="e", padx=5, pady=5)
    ports_entry = tk.Entry(root)
    ports_entry.insert(0, "22, 80, 443")
    ports_entry.grid(row=4, column=1, sticky="we", padx=5, pady=5)

    port_scan_enabled = tk.BooleanVar(value=True)
    port_scan_checkbox = tk.Checkbutton(root, text="Enable Port Scanning", variable=port_scan_enabled)
    port_scan_checkbox.grid(row=5, column=1, sticky="w", padx=5, pady=2)

    # DNS resolution options
    use_local_dns = tk.BooleanVar(value=False)

    dns_checkbox = tk.Checkbutton(root, text="Use Local DNS (System Default)", variable=use_local_dns)
    dns_checkbox.grid(row=6, column=1, sticky="w", padx=5, pady=2)

    # Get system DNS servers and format them as comma-separated
    default_dns_list = dns.resolver.Resolver().nameservers
    default_dns_str = ", ".join(default_dns_list)

    tk.Label(root, text="Custom DNS (comma-separated):").grid(row=7, column=0, sticky="e", padx=5, pady=5)
    dns_entry = tk.Entry(root, width=30)
    dns_entry.insert(0, default_dns_str)
    dns_entry.grid(row=7, column=1, sticky="w", padx=5, pady=5)

    listbox = tk.Listbox(root, font=("Courier", 10))
    listbox.grid(row=8, column=0, columnspan=3, sticky="nsew", padx=5, pady=5)

    scrollbar = tk.Scrollbar(root, orient="vertical", command=listbox.yview)
    scrollbar.grid(row=8, column=3, sticky="ns")
    listbox.config(yscrollcommand=scrollbar.set)

    progress_bar = ttk.Progressbar(root, orient="horizontal", mode="determinate")
    progress_bar.grid(row=9, column=0, columnspan=3, sticky="we", padx=5, pady=5)

    button_frame = tk.Frame(root)
    button_frame.grid(row=10, column=0, columnspan=3, pady=5)

    scan_button = tk.Button(button_frame, text="Start Scan", width=15,
                            command=lambda: start_scan(scan_mode.get(), start_ip_entry.get(),
                                                       end_ip_entry.get(), cidr_entry.get(),
                                                       ports_entry.get(), port_scan_enabled.get(),
                                                       listbox, scan_button, cancel_button,
                                                       export_button, progress_bar, use_local_dns.get(),dns_entry.get()))
    scan_button.pack(side="left", padx=5)

    cancel_button = tk.Button(button_frame, text="Cancel", width=15, state=tk.DISABLED,
                              command=cancel_scan)
    cancel_button.pack(side="left", padx=5)

    export_button = tk.Button(button_frame, text="Export CSV", width=15, state=tk.DISABLED,
                              command=lambda: export_results(export_button.results))
    export_button.pack(side="left", padx=5)
    export_button.results = []

    exit_button = tk.Button(button_frame, text="Exit", width=15, command=root.destroy)
    exit_button.pack(side="left", padx=5)

    root.mainloop()

if __name__ == "__main__":
    create_gui()

import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import defaultdict

# Function to parse Nmap console output
def parse_nmap_output(nmap_output):
    results = []
    port_table = defaultdict(set)
    host_blocks = re.split(r"Nmap scan report for ", nmap_output)[1:]

    for block in host_blocks:
        match = re.match(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", block)
        hostname, ip_addr = (match.group(1), match.group(2)) if match else ("unknown", "unknown")
        ports = []
        port_matches = re.findall(r"(\d+)/tcp\s+(\w+)\s+(\S+)(.*)", block)
        for port_info in port_matches:
            port_id, state, service, _ = port_info
            ports.append(f"Port {port_id}/tcp ({service.strip()}): {state}")
            port_table[(port_id, service.strip())].add(ip_addr)
        results.append((f"{hostname} ({ip_addr})", ports))
    
    table_data = [(port_id, service, ", ".join(sorted(ips))) for (port_id, service), ips in port_table.items()]
    return results, table_data

# Function to parse NetBIOS scan output
def parse_netbios_output(netbios_output):
    netbios_data = {}
    matches = re.findall(r"\[\+\] (\d+\.\d+\.\d+\.\d+) \[(.*?)\] OS:(.*?) Names:\((.*?)\) Addresses:\((.*?)\) Mac:(.*?)", netbios_output)
    for match in matches:
        ip, netbios_name, os, names, addresses, mac = match
        netbios_data[ip] = {"NetBIOS Name": netbios_name, "OS": os.strip(), "Names": names.split(", ") if names else [], "MAC": mac.strip()}
    return netbios_data

# Function to load and parse file output
def load_file():
    file_path = filedialog.askopenfilename(title="Select Nmap Output File")
    if not file_path:
        return
    with open(file_path, 'r') as file:
        content = file.read()
    parsed_data, port_table_data = parse_nmap_output(content)
    populate_ui(parsed_data, port_table_data)

# Function to load and parse user-pasted Nmap output
def paste_nmap_output():
    content = text_box.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("Warning", "No input detected!")
        return
    parsed_data, port_table_data = parse_nmap_output(content)
    populate_ui(parsed_data, port_table_data)

# Function to populate the UI with parsed data
def populate_ui(parsed_data, port_table_data):
    for item in tree.get_children():
        tree.delete(item)
    for host, ports in parsed_data:
        parent_id = tree.insert("", "end", text=host, values=(""))
        for port in ports:
            tree.insert(parent_id, "end", text=port)
    for row in table.get_children():
        table.delete(row)
    for port_id, service, ip_list in port_table_data:
        table.insert("", "end", values=(port_id, service, ip_list))

# UI Setup
app = tk.Tk()
app.title("Nmap & NetBIOS Output Viewer")
app.geometry("900x600")

tab_control = ttk.Notebook(app)
tree_tab = ttk.Frame(tab_control)
table_tab = ttk.Frame(tab_control)
paste_tab = ttk.Frame(tab_control)

tab_control.add(tree_tab, text="Tree View")
tab_control.add(table_tab, text="Table View")
tab_control.add(paste_tab, text="Paste Output")
tab_control.pack(expand=1, fill="both")

frame = ttk.Frame(tree_tab)
frame.pack(fill="both", expand=True)
tree = ttk.Treeview(frame, columns=("Ports"), show="tree")
scroll_y = ttk.Scrollbar(frame, orient="vertical", command=tree.yview)
scroll_y.pack(side="right", fill="y")
tree.configure(yscrollcommand=scroll_y.set)
tree.pack(fill="both", expand=True)

table = ttk.Treeview(table_tab, columns=("Port", "Service", "IP Address"), show="headings")
table.heading("Port", text="Port")
table.heading("Service", text="Service")
table.heading("IP Address", text="IP Address")
table.pack(fill="both", expand=True)

text_box = tk.Text(paste_tab, height=15)
text_box.pack(fill="both", expand=True, padx=5, pady=5)
paste_button = ttk.Button(paste_tab, text="Parse Input", command=paste_nmap_output)
paste_button.pack(pady=5)

load_button = ttk.Button(app, text="Load Nmap Output File", command=load_file)
load_button.pack(pady=10)

app.mainloop()

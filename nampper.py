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
        # Extract hostname and IP address
        match = re.match(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", block)
        hostname, ip_addr = (match.group(1), match.group(2)) if match else ("unknown", "unknown")
        ports = []
        # Extract port information
        port_matches = re.findall(r"(\d+)/tcp\s+(\w+)\s+([\w/-]+)", block)
        for port_info in port_matches:
            port_id, state, service = port_info
            ports.append(f"Port {port_id}/tcp ({service.strip()}): {state}")
            port_table[(port_id, service.strip())].add(ip_addr)
        results.append((f"{hostname} ({ip_addr})", ports))
    
    # Convert port_table to table data format
    table_data = [(port_id, service, ", ".join(sorted(ips))) for (port_id, service), ips in port_table.items()]
    return results, table_data

# Function to parse NetBIOS scan output
def parse_netbios_output(netbios_output):
    netbios_data = {}
    matches = re.findall(r"\[\+\] (\d+\.\d+\.\d+\.\d+) \[(.*?)\] OS:(.*?) Names:\((.*?)\) Addresses:\((.*?)\) Mac:(.*?)", netbios_output)
    for match in matches:
        ip, netbios_name, os, names, addresses, mac = match
        netbios_data[ip] = {"NetBIOS Name": netbios_name, "OS": os.strip(), "Names": names.split(", ") if names else [], "MAC": mac.strip(), "Addresses": addresses.split(", ") if addresses else []}
    return netbios_data

# Function to hide unknown entries
def hide_unknown():
    for row in table.get_children():
        values = table.item(row, 'values')
        if 'unknown' in values:
            table.detach(row)

# Function to clear all views
def clear_all_views():
    for item in tree.get_children():
        tree.delete(item)
    for row in table.get_children():
        table.delete(row)
    text_box.delete("1.0", tk.END)

# Function to sort table columns
def sort_table(column, reverse):
    data = [(table.set(child, column), child) for child in table.get_children("")]
    data.sort(reverse=reverse)
    for index, (val, child) in enumerate(data):
        table.move(child, "", index)
    table.heading(column, command=lambda: sort_table(column, not reverse))

# Function to export target file
def export_target_file():
    selected_item = table.selection()
    if not selected_item:
        messagebox.showwarning("Warning", "No row selected!")
        return
    values = table.item(selected_item, 'values')
    port = values[0]
    ips = values[2]
    filename = f"TargetFile-port{port}.txt"
    with open(filename, "w") as file:
        file.write(ips.replace(", ", ", "))
    messagebox.showinfo("Success", f"Target file {filename} created successfully!")

# Function to load and parse file output
def load_file():
    file_path = filedialog.askopenfilename(title="Select Nmap Output File")
    if not file_path:
        return
    with open(file_path, 'r') as file:
        content = file.read()
    parsed_data, port_table_data = parse_nmap_output(content)
    populate_ui(parsed_data, port_table_data)

# Function to load and parse user-pasted output
def paste_output():
    content = text_box.get("1.0", tk.END).strip()
    if not content:
        messagebox.showwarning("Warning", "No input detected!")
        return
    try:
        if "[+]" in content:
            parsed_data = parse_netbios_output(content)
        else:
            parsed_data, port_table_data = parse_nmap_output(content)
            populate_ui(parsed_data, port_table_data)
            text_box.delete("1.0", tk.END)
            return
        messagebox.showinfo("Success", "NetBIOS data parsed successfully!")
        text_box.delete("1.0", tk.END)
    except Exception as e:
        text_box.delete("1.0", tk.END)
        text_box.insert("1.0", f"Error: {str(e)}")

# Function to populate the UI with parsed data
def populate_ui(parsed_data, port_table_data):
    clear_all_views()
    for host, ports in parsed_data:
        parent_id = tree.insert("", "end", text=host, values=(""))
        for port in ports:
            tree.insert(parent_id, "end", text=port)
    for port_id, service, ip_list in port_table_data:
        table.insert("", "end", values=(port_id, service, ip_list))

# UI Setup
app = tk.Tk()
app.title("Nmap & NetBIOS Output Viewer")
app.geometry("900x600")

# Create tabbed interface
tab_control = ttk.Notebook(app)
tree_tab = ttk.Frame(tab_control)
table_tab = ttk.Frame(tab_control)
paste_tab = ttk.Frame(tab_control)

tab_control.add(tree_tab, text="Tree View")
tab_control.add(table_tab, text="Service Map")
tab_control.add(paste_tab, text="Paste Output")
tab_control.pack(expand=1, fill="both")

# Tree View
frame = ttk.Frame(tree_tab)
frame.pack(fill="both", expand=True)
tree = ttk.Treeview(frame, columns=("Ports"), show="tree")
tree.pack(fill="both", expand=True)

# Service Map Table
table = ttk.Treeview(table_tab, columns=("Port", "Service", "IP Address"), show="headings")
for col in ("Port", "Service", "IP Address"):
    table.heading(col, text=col, command=lambda c=col: sort_table(c, False))
table.pack(fill="both", expand=True)

# Paste Input Tab
text_box = tk.Text(paste_tab, height=15)
text_box.pack(fill="both", expand=True, padx=5, pady=5)
paste_button = ttk.Button(paste_tab, text="Parse Input", command=paste_output)
paste_button.pack(pady=5)

# Buttons
button_frame = ttk.Frame(app)
button_frame.pack(pady=10)

load_button = ttk.Button(button_frame, text="Load Nmap Output File", command=load_file)
load_button.grid(row=0, column=0, padx=5, pady=5)

clear_button = ttk.Button(button_frame, text="Clear All", command=clear_all_views)
clear_button.grid(row=0, column=1, padx=5, pady=5)

hide_button = ttk.Button(button_frame, text="Hide Unknown", command=hide_unknown)
hide_button.grid(row=1, column=0, padx=5, pady=5)

export_button = ttk.Button(button_frame, text="Export Target File", command=export_target_file)
export_button.grid(row=1, column=1, padx=5, pady=5)

app.mainloop()

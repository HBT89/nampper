import re
import tkinter as tk
from tkinter import ttk, filedialog, messagebox
from collections import defaultdict
version_this = "1.1.03"

# Function to extract vulners

# Function to extract vulners data
def extract_vulners_data(nmap_output):
    vulners_data = defaultdict(lambda: {"version": "", "link": "", "exploitable": False, "ips": set()})
    lines = nmap_output.split("\n")
    
    current_ip = None
    capturing = False

    for line in lines:
        line = line.rstrip()

        ip_match = re.match(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", line)
        if ip_match:
            current_ip = ip_match.group(1)
            capturing = False

        elif current_ip and line.startswith("| vulners:"):
            capturing = True

        elif capturing:
            if line.startswith("|_"):
                capturing = False
                continue

            vuln_match = re.match(r"^\|\s{5}\t([^\t]+)\t([\d\.]+)\t(https://[^\t]+)(?:\t(\*EXPLOIT\*))?", line)
            if vuln_match:
                vuln_id, score, link, exploitable = vuln_match.groups()
                exploitable = exploitable is not None
                
                if vuln_id not in vulners_data:
                    vulners_data[vuln_id]["version"] = score
                    vulners_data[vuln_id]["link"] = link
                    vulners_data[vuln_id]["exploitable"] = exploitable
                
                vulners_data[vuln_id]["ips"].add(current_ip)

    return vulners_data

# Function to parse Nmap console output
def parse_nmap_output(nmap_output):
    results = []
    port_table = defaultdict(set)
    vulners_data = extract_vulners_data(nmap_output)
    host_blocks = re.split(r"Nmap scan report for ", nmap_output)[1:]

    for block in host_blocks:
        match = re.match(r"(\S+)\s+\((\d+\.\d+\.\d+\.\d+)\)", block)
        hostname, ip_addr = (match.group(1), match.group(2)) if match else ("unknown", "unknown")
        os_match = re.search(r"OS details: (.+?)\n", block)
        os_info = os_match.group(1) if os_match else "Unknown OS"
        ports = []
        
        port_matches = re.findall(r"(\d+)/tcp\s+(\w+)\s+([\w/-]+)", block)
        for port_info in port_matches:
            port_id, state, service = port_info
            ports.append(f"Port {port_id}/tcp ({service.strip()}): {state}")
            port_table[(port_id, service.strip())].add(ip_addr)
        
        results.append((f"{hostname} ({ip_addr}) - {os_info}", ports))
    
    table_data = [(port_id, service, ", ".join(sorted(ips))) for (port_id, service), ips in port_table.items()]
    return results, table_data, vulners_data

# Function to populate the UI with parsed data
def populate_ui(parsed_data, port_table_data, vulners_data):
    clear_all_views()
    
    for host, ports in parsed_data:
        parent_id = tree.insert("", "end", text=host, values=(""))
        for port in ports:
            tree.insert(parent_id, "end", text=port)
    
    for port_id, service, ip_list in port_table_data:
        table.insert("", "end", values=(port_id, service, ip_list))
    
    for vuln_id, data in vulners_data.items():
        exploitable_icon = "✅" if data["exploitable"] else ""
        vuln_tree.insert("", "end", values=(vuln_id, data["version"], data["link"], ", ".join(data["ips"]), exploitable_icon))

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
    data = [(table.item(child, "values")[column_index], child) for child in table.get_children("")]
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
    parsed_data, port_table_data, vulners_data = parse_nmap_output(content)
    populate_ui(parsed_data, port_table_data, vulners_data)

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
            parsed_data, port_table_data, vulners_data = parse_nmap_output(content)
            populate_ui(parsed_data, port_table_data, vulners_data)
            text_box.delete("1.0", tk.END)
            return
        messagebox.showinfo("Success", "NetBIOS data parsed successfully!")
        text_box.delete("1.0", tk.END)
    except Exception as e:
        text_box.delete("1.0", tk.END)
        text_box.insert("1.0", f"Error: {str(e)}")



# UI Setup
app = tk.Tk()
app.title(f"Nmap & NetBIOS Output Viewer version {version_this}")
app.geometry("900x600")

# Create tabbed interface
tab_control = ttk.Notebook(app)
tree_tab = ttk.Frame(tab_control)
table_tab = ttk.Frame(tab_control)
vuln_tab = ttk.Frame(tab_control)
paste_tab = ttk.Frame(tab_control)

tab_control.add(tree_tab, text="Tree View")
tab_control.add(table_tab, text="Service Map")
tab_control.add(vuln_tab, text="Vulnerabilities")
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

# Vulnerabilities Tab
vuln_frame = ttk.Frame(vuln_tab)
vuln_frame.pack(fill="both", expand=True)
vuln_tree = ttk.Treeview(vuln_tab, columns=("ID", "Score", "Link", "Exploitable"), show="headings")
for col in ("ID", "Score", "Link", "Exploitable"):
    vuln_tree.heading(col, text=col)
vuln_tree.pack(fill="both", expand=True)

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


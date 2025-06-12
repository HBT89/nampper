# nampper

nampper is a simple Python GUI tool for quickly viewing and extracting information from Nmap and NetBIOS scan outputs. It is designed to make it easy to copy, paste, and export results from common enumeration tools, with a focus on usability and clarity.

## Features
- **Paste or load Nmap output**: Supports direct pasting or loading from `.txt`, `.xml`, and `.html` files (XML/HTML currently display raw content).
- **Automatic parsing**: Extracts hostnames, IP addresses, open ports, and vulnerability data from standard Nmap output.
- **Tree and table views**: Visualize scan results in a hierarchical tree or a sortable service map table.
- **Vulnerability display**: Shows detected vulnerabilities and exploitability (if present in the scan output).
- **Export targets**: Select a service row and export the associated IPs to a file of your choice.
- **Hide unknowns**: Option to hide rows with unknown hosts or IPs for cleaner views.
## How to Run
1. Open the file in a command window with 
```
python nampper.py
```
**NOTE** You might need to specify python3 if you're in a mixed environment

## How to Use
1. **Paste Output**: Copy Nmap or NetBIOS output and paste it into the 'Paste Output' tab, then click 'Parse Input'.
2. **Load File**: Use the 'Load Nmap Output File' button to open a scan result from a file.
3. **Browse Results**: Switch between the Tree View, Service Map, and Vulnerabilities tabs to explore the parsed data.
4. **Export**: Select a row in the Service Map and click 'Export Target File' to save the IPs for that service.

## Requirements
- Python 3.x
- tkinter (usually included with Python on Windows; install with your package manager if missing)

Install requirements with:
```
pip install -r requirements.txt
```

## Recent Updates (June 2025)
- Added export dialog for saving service IPs to a user-chosen file.
- Improved hostname extraction from Nmap output.
- File loader now supports .txt, .xml, and .html files.
- UI and code structure improvements for better usability.

## License
This project is licensed under the GNU GPL v3. See [LICENSE](LICENSE) for details.

# nampper
A tool in python that i am throwing together to easily copy and paste output from nmap cli and some other enumeration tools

## Updates as of June 11, 2025
- UI now includes a button to export the selected service row to a user-chosen file location.
- The export function prompts for a save location and filename, with a sensible default.
- The 'Load Nmap Output File' button now supports .txt, .xml, and .html files (XML/HTML display raw content for now).
- Hostnames are now correctly parsed and displayed from Nmap output (e.g., 'Cornelius.internal.investblue.com.au').
- Code has been reorganized for logical function grouping and improved readability.

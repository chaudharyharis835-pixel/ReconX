#!/usr/bin/env python3
"""
ReconX - All-in-One Automated Network Reconnaissance Toolkit
NCERT Academic Cybersecurity Assignment
"""

import sys
import socket
import re
import subprocess
import argparse
import threading
import json
import os
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

# Try to import optional packages gracefully, falling back to standard libraries if missing
try:
    import dns.resolver
    HAS_DNS = True
except ImportError:
    HAS_DNS = False

try:
    import whois
    HAS_WHOIS = True
except ImportError:
    HAS_WHOIS = False

try:
    from colorama import init, Fore, Style
    init(autoreset=True)
    G = Fore.GREEN
    R = Fore.RED
    Y = Fore.YELLOW
    B = Fore.BLUE
    W = Style.RESET_ALL
except ImportError:
    G = R = Y = B = W = ""

# ==========================================
# 1. CORE UTILITIES & VALIDATION
# ==========================================
def print_banner():
    # Double-escaped backslashes to permanently resolve Python SyntaxWarnings
    banner = f"""{G}
  _______                             _____  
  ___  __ \\_________________  _______ ___  |/ /  Automated Assessment Engine
  __  /_/ /_  _ \\  ___/  __ \\/ __  __ \\__    /   Production Optimization Stack
  _  _, _/ /  __/ /__ / /_/ / / / / / /_    |    NCERT Academic Framework v1.0
  /_/ |_|  \\___/\\___/ \\____/_/ /_/ /_/ /_/|_|    
    {W}"""
    print(banner)

def validate_ip_or_domain(target):
    ip_pattern = r"^([0-9]{1,3}\.){3}[0-9]{1,3}$"
    domain_pattern = r"^([a-zA-Z0-9\-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(ip_pattern, target) or re.match(domain_pattern, target))

# ==========================================
# 2. ACTIVE INFRASTRUCTURE DISCOVERY
# ==========================================
def run_host_discovery(target):
    print(f"{B}[+] Activating Host Discovery Engine...")
    clean_target = target.replace("http://", "").replace("https://", "").split("/")[0]
    
    param = "-n" if sys.platform.lower() == "win32" else "-c"
    command = ["ping", param, "1", clean_target]
    
    try:
        res = subprocess.run(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=2)
        if res.returncode == 0:
            print(f"{G}[+] Target machine responded successfully to ICMP validation verification.")
            return True
    except Exception:
        pass
        
    print(f"{Y}[!] Target machine dropped ICMP verification requests. Continuing with port scan...")
    return False

def check_port(target, port, open_ports):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(1.0)
        result = s.connect_ex((target, port))
        if result == 0:
            print(f"{G}[+] Discovered accessible connection node: Port {port}")
            open_ports.append(port)
        s.close()
    except Exception:
        pass

def parse_ports(port_input):
    port_input = port_input.strip().lower()
    
    if not port_input:
        print(f"{Y}[*] Using default port range: 1-100")
        return list(range(1, 101))
        
    if port_input in ["all", "65535", "1-65535"]:
        print(f"{B}[*] Configuration Mode: Deep Target Audit (Scanning ports 1 to 65535)...")
        return list(range(1, 65536))
        
    if port_input.isdigit():
        p = int(port_input)
        if 1 <= p <= 65535:
            print(f"{B}[*] Configuration Mode: Targeted Single Node Inspection (Port {p})...")
            return [p]
            
    if "-" in port_input:
        try:
            start_p, end_p = map(int, port_input.split("-"))
            if 1 <= start_p <= 65535 and 1 <= end_p <= 65535 and start_p <= end_p:
                print(f"{B}[*] Configuration Mode: Range Block Scan ({start_p} to {end_p})...")
                return list(range(start_p, end_p + 1))
        except ValueError:
            pass

    print(f"{Y}[!] Input format unclear. Falling back to default scanning array (1-100).")
    return list(range(1, 101))

def run_port_scan(target, ports_list, thread_count):
    open_ports = []
    
    with ThreadPoolExecutor(max_workers=thread_count) as executor:
        futures = [executor.submit(check_port, target, port, open_ports) for port in ports_list]
        for future in as_completed(futures):
            pass
            
    return sorted(open_ports)

# ==========================================
# 3. INTERROGATION ENGINE (BANNERS)
# ==========================================
def grab_banners(target, open_ports):
    banners = {}
    for port in open_ports:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1.5)
            s.connect((target, port))
            
            if port == 80:
                s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
            else:
                s.sendall(b"\r\n")
                
            response = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if response:
                # Sanitize response string to safe plaintext for clean printing and reporting
                clean_banner = response.split('\r\n')[0].replace('<', '&lt;').replace('>', '&gt;')
                banners[str(port)] = clean_banner
            else:
                banners[str(port)] = "Active Connection (No explicit banner response text collected)"
            s.close()
        except Exception:
            banners[str(port)] = "Active Connection (Interrogation read timeout)"
    return banners

# ==========================================
# 4. PASSIVE INTELLIGENCE
# ==========================================
def run_dns_lookup(target):
    dns_info = {}
    if not HAS_DNS:
        return {"Status": "dnspython package not found. Skipping extended DNS analytics."}
    
    records = ['A', 'MX', 'TXT', 'NS']
    for r_type in records:
        try:
            answers = dns.resolver.resolve(target, r_type)
            dns_info[r_type] = [str(rdata) for rdata in answers]
        except Exception:
            dns_info[r_type] = []
    return dns_info

def run_whois_lookup(target):
    if not HAS_WHOIS:
        return {"Status": "python-whois package not found. Skipping domain ownership analysis."}
    try:
        w = whois.whois(target)
        return {
            "registrar": w.registrar,
            "creation_date": str(w.creation_date),
            "expiration_date": str(w.expiration_date),
            "country": w.country
        }
    except Exception as e:
        return {"Error": f"WHOIS Query Timeout or Unreachable Resource node: {str(e)}"}

# ==========================================
# 5. DIAGNOSTIC REPORT ENGINE
# ==========================================
def export_reports(data):
    os.makedirs("reports", exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    
    # 5a. Export Text Summary
    txt_path = "reports/recon_output.txt"
    with open(txt_path, "w") as f:
        f.write(f"RECONX AUTOMATED RECONNAISSANCE ANALYSIS SUMMARY\n")
        f.write(f"Generated at: {timestamp}\n")
        f.write(f"====================================================\n")
        f.write(f"Target locked: {data['target']}\n")
        f.write(f"Host State: {'Alive' if data['is_alive'] else 'Unknown/Dropped Pings'}\n")
        f.write(f"Discovered Ports: {data['open_ports']}\n\n")
        f.write("Service Identification Signatures:\n")
        for p, b in data['banners'].items():
            f.write(f"  - Port {p}: {b}\n")
            
    # 5b. Export JSON Object Matrix
    json_path = "reports/recon_output.json"
    with open(json_path, "w") as f:
        json.dump(data, f, indent=4)
        
    # 5c. Export Visual HTML Structural Dashboard Table
    port_rows = ""
    if data['open_ports']:
        for port in data['open_ports']:
            banner_text = data['banners'].get(str(port), "Active Connection (No explicit banner)")
            port_rows += f"""
            <tr>
                <td style="font-weight: bold; color: #1e3a8a;">{port}</td>
                <td><span style="background: #dcfce7; color: #166534; padding: 2px 8px; border-radius: 4px; font-size: 0.85rem; font-weight: bold;">OPEN</span></td>
                <td style="font-family: monospace; background: #fafafa; color: #475569;">{banner_text}</td>
            </tr>
            """
    else:
        port_rows = "<tr><td colspan='3' style='text-align: center; color: #94a3b8;'>No accessible connection nodes discovered.</td></tr>"

    html_path = "reports/recon_output.html"
    html_content = f"""<!DOCTYPE html>
<html>
<head>
    <title>ReconX Structural Management Dashboard</title>
    <style>
        body {{ font-family: 'Segoe UI', Arial, sans-serif; margin: 30px; background: #f4f6f9; color: #333; }}
        .card {{ background: white; padding: 25px; border-radius: 8px; box-shadow: 0 4px 6px rgba(0,0,0,0.05); margin-bottom: 25px; }}
        h1 {{ color: #1e3a8a; border-bottom: 2px solid #e2e8f0; padding-bottom: 10px; margin-top: 0; }}
        h2 {{ color: #1e3a8a; margin-top: 0; font-size: 1.25rem; border-bottom: 1px solid #e2e8f0; padding-bottom: 8px; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ border: 1px solid #e2e8f0; padding: 12px; text-align: left; }}
        th {{ background: #f8fafc; color: #475569; font-weight: 600; }}
        tr:hover {{ background-color: #f8fafc; }}
    </style>
</head>
<body>
    <div class="card">
        <h1>ReconX Security Audit Framework Intelligence Dashboard</h1>
        <p><strong>Target Endpoint Assessment Scope:</strong> {data['target']}</p>
        <p><strong>Report Compilation Datetime:</strong> {timestamp}</p>
    </div>
    
    <div class="card">
        <h2>Discovered Network Service Mappings</h2>
        <table>
            <thead>
                <tr>
                    <th style="width: 15%;">Target Port</th>
                    <th style="width: 15%;">Node Status</th>
                    <th style="width: 70%;">Interrogated Application Header / Banner</th>
                </tr>
            </thead>
            <tbody>
                {port_rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""
    
    with open(html_path, "w") as f:
        f.write(html_content)

# ==========================================
# MAIN EXECUTION ORCHESTRATOR LOOP
# ==========================================
def main():
    print_banner()
    print("================================================================================")
    print("                      RECONX INTERACTIVE RUNTIME MANAGER                        ")
    print("================================================================================")
    
    target = input("\n[?] Enter Target (e.g., scanme.nmap.org or 192.168.127.149): ").strip()
    if not target:
        print(f"{R}[- ] Error: Target cannot be blank.")
        return
        
    print("\n--- Port Scanning Configuration Options ---")
    print(" * Type 'all' or '65535' to scan every single port (1-65535)")
    print(" * Type a single target number (e.g., '80') for a specific port")
    print(" * Type a standard range block (e.g., '20-90')")
    print(" * Press Enter to default to common ports (1-100)")
    ports_input = input("[?] Enter Port Choice: ").strip()
    
    ports_list = parse_ports(ports_input)
    
    default_threads = "100" if len(ports_list) > 1000 else "50"
    threads_input = input(f"[?] Enter Allocation Threads [Press Enter for Default {default_threads}]: ").strip()
    try:
        threads = int(threads_input) if threads_input else int(default_threads)
    except ValueError:
        print(f"{Y}[!] Invalid entry. Defaulting to thread pool layer: {default_threads}")
        threads = int(default_threads)

    print(f"\n{G}[*] Initializing Automated Scanning Sequence configuration profiles...\n")
    
    if not validate_ip_or_domain(target):
        print(f"{R}[- ] Execution Aborted: Invalid target syntax structure: {target}")
        return
        
    scan_results = {
        "target": target,
        "is_alive": False,
        "open_ports": [],
        "banners": {},
        "dns_records": {},
        "whois_data": {}
    }
    
    print("========================= Host Discovery Engine Activation =========================")
    scan_results["is_alive"] = run_host_discovery(target)
    
    print(f"\n========================= Service Identification & Mapping Pipeline =========================")
    print(f"[*] Launching scanner pool utilizing {threads} parallel allocation threads...")
    scan_results["open_ports"] = run_port_scan(target, ports_list, threads)
    
    if scan_results["open_ports"]:
        print("[*] Interrogating active ports for application headers...")
        scan_results["banners"] = grab_banners(target, scan_results["open_ports"])
        
    print(f"\n========================= Passive Intelligence Gathering Pipeline =========================")
    if not target.replace('.', '').isdigit():
        print("[*] Target detected as Domain. Running out-of-band DNS/WHOIS mapping profiles...")
        scan_results["dns_records"] = run_dns_lookup(target)
        scan_results["whois_data"] = run_whois_lookup(target)
    else:
        if target.startswith(("192.168.", "10.", "172.16.", "172.31.")):
            print("[!] Target is a Local Private IP address range. Skipping out-of-band WHOIS check...")
        else:
            print("[*] Target is a Public IP address. Performing WHOIS reverse lookups...")
            scan_results["whois_data"] = run_whois_lookup(target)

    print(f"\n========================= Compiling and Exporting Diagnostic Reports =========================")
    export_reports(scan_results)
    print(f"{G}[+] Full network reconnaissance reports written to the 'reports/' directory.\n")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{R}[- ] Scan execution interrupted by operator. Exiting safely.")
        sys.exit(0)

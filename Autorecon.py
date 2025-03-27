#!/usr/bin/env python3
import os
import json
import subprocess
import argparse
from datetime import datetime
import shodan
import requests
from bs4 import BeautifulSoup

class AutoRecon:
    def __init__(self, domain, output_dir="results", shodan_key=None):
        self.domain = domain
        self.output_dir = output_dir
        self.shodan_key = shodan_key
        self.results = {
            "domain": domain,
            "date": datetime.now().isoformat(),
            "subdomains": [],
            "ports": {},
            "vulnerabilities": []
        }
        
        # Create output directory if it doesn't exist
        os.makedirs(self.output_dir, exist_ok=True)

    def run_subdomain_enumeration(self):
        """Run multiple subdomain enumeration tools"""
        print(f"[*] Running subdomain enumeration on {self.domain}")
        
        # Using subfinder
        try:
            subfinder_cmd = f"subfinder -d {self.domain} -silent"
            subfinder_output = subprocess.check_output(subfinder_cmd, shell=True).decode().splitlines()
            self.results["subdomains"].extend(subfinder_output)
            print(f"[+] Subfinder found {len(subfinder_output)} subdomains")
        except Exception as e:
            print(f"[-] Subfinder error: {e}")
        
        # Using amass (passive mode)
        try:
            amass_cmd = f"amass enum -passive -d {self.domain}"
            amass_output = subprocess.check_output(amass_cmd, shell=True).decode().splitlines()
            new_domains = [d for d in amass_output if d not in self.results["subdomains"]]
            self.results["subdomains"].extend(new_domains)
            print(f"[+] Amass found {len(new_domains)} new subdomains")
        except Exception as e:
            print(f"[-] Amass error: {e}")
        
        # Remove duplicates
        self.results["subdomains"] = list(set(self.results["subdomains"]))
        print(f"[*] Total unique subdomains found: {len(self.results['subdomains'])}")

    def run_port_scanning(self, top_ports=100):
        """Run port scanning on discovered subdomains"""
        print("[*] Starting port scanning")
        
        for subdomain in self.results["subdomains"]:
            try:
                print(f"[*] Scanning {subdomain}")
                nmap_cmd = f"nmap -T4 --top-ports {top_ports} -sV -oX {self.output_dir}/{subdomain}_scan.xml {subdomain}"
                subprocess.run(nmap_cmd, shell=True, check=True)
                
                # Parse XML output
                self._parse_nmap_xml(f"{self.output_dir}/{subdomain}_scan.xml", subdomain)
                
            except Exception as e:
                print(f"[-] Error scanning {subdomain}: {e}")
        
        print("[+] Port scanning completed")

    def _parse_nmap_xml(self, xml_file, subdomain):
        """Parse Nmap XML output and store results"""
        try:
            from xml.etree import ElementTree as ET
            tree = ET.parse(xml_file)
            root = tree.getroot()
            
            self.results["ports"][subdomain] = []
            
            for host in root.findall('host'):
                for port in host.find('ports').findall('port'):
                    port_data = {
                        "port": port.attrib['portid'],
                        "protocol": port.attrib['protocol'],
                        "service": port.find('service').attrib['name'] if port.find('service') is not None else "unknown",
                        "product": port.find('service').attrib.get('product', '') if port.find('service') is not None else "",
                        "version": port.find('service').attrib.get('version', '') if port.find('service') is not None else ""
                    }
                    self.results["ports"][subdomain].append(port_data)
                    
        except Exception as e:
            print(f"[-] Error parsing Nmap XML for {subdomain}: {e}")

    def check_shodan(self):
        """Check for exposed services using Shodan API"""
        if not self.shodan_key:
            print("[-] Shodan API key not provided, skipping Shodan checks")
            return
            
        print("[*] Checking Shodan for exposed services")
        
        try:
            api = shodan.Shodan(self.shodan_key)
            
            # Check main domain
            self._query_shodan(api, self.domain)
            
            # Check subdomains
            for subdomain in self.results["subdomains"]:
                self._query_shodan(api, subdomain)
                
        except Exception as e:
            print(f"[-] Shodan error: {e}")

    def _query_shodan(self, api, target):
        """Query Shodan for a specific target"""
        try:
            results = api.search(target)
            print(f"[+] Shodan found {results['total']} results for {target}")
            
            for result in results['matches']:
                vuln_info = {
                    "target": target,
                    "ip": result['ip_str'],
                    "port": result['port'],
                    "service": result.get('product', 'unknown'),
                    "data": result['data'][:200] + "..." if 'data' in result else "",
                    "source": "Shodan"
                }
                self.results["vulnerabilities"].append(vuln_info)
                
        except shodan.APIError as e:
            print(f"[-] Shodan error for {target}: {e}")

    def check_common_vulns(self):
        """Check for common vulnerabilities using GF patterns"""
        print("[*] Checking for common vulnerabilities")
        
        for subdomain in self.results["subdomains"]:
            try:
                # Check for common web vulnerabilities
                if any(port['service'] in ['http', 'https'] for port in self.results["ports"].get(subdomain, [])):
                    self._check_web_vulns(subdomain)
                    
            except Exception as e:
                print(f"[-] Error checking vulnerabilities for {subdomain}: {e}")

    def _check_web_vulns(self, subdomain):
        """Check for common web vulnerabilities"""
        try:
            # Check for exposed admin interfaces
            admin_urls = ['/admin', '/wp-admin', '/administrator', '/manage']
            for admin_path in admin_urls:
                url = f"http://{subdomain}{admin_path}"
                try:
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    if response.status_code == 200:
                        self.results["vulnerabilities"].append({
                            "target": subdomain,
                            "type": "Exposed admin interface",
                            "url": url,
                            "source": "AutoRecon"
                        })
                except:
                    pass

            # Check for common files
            common_files = ['/robots.txt', '/.git/HEAD', '/.env']
            for file_path in common_files:
                url = f"http://{subdomain}{file_path}"
                try:
                    response = requests.get(url, timeout=5, allow_redirects=False)
                    if response.status_code == 200:
                        self.results["vulnerabilities"].append({
                            "target": subdomain,
                            "type": "Exposed sensitive file",
                            "url": url,
                            "source": "AutoRecon"
                        })
                except:
                    pass

        except Exception as e:
            print(f"[-] Web vulnerability check error for {subdomain}: {e}")

    def generate_report(self):
        """Generate JSON and HTML reports"""
        print("[*] Generating reports")
        
        # JSON report
        json_file = f"{self.output_dir}/report_{self.domain}.json"
        with open(json_file, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(f"[+] JSON report saved to {json_file}")
        
        # HTML report
        self._generate_html_report()
        
    def _generate_html_report(self):
        """Generate an HTML report"""
        html_file = f"{self.output_dir}/report_{self.domain}.html"
        
        html_template = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>AutoRecon Report for {self.domain}</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                h1 {{ color: #333; }}
                h2 {{ color: #444; margin-top: 30px; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                tr:nth-child(even) {{ background-color: #f9f9f9; }}
                .vulnerable {{ background-color: #ffdddd; }}
            </style>
        </head>
        <body>
            <h1>AutoRecon Report for {self.domain}</h1>
            <p>Generated on {self.results['date']}</p>
            
            <h2>Subdomains Found ({len(self.results['subdomains'])})</h2>
            <ul>
                {"".join(f"<li>{sub}</li>" for sub in self.results['subdomains'])}
            </ul>
            
            <h2>Port Scan Results</h2>
            {"".join(self._generate_port_html(sub) for sub in self.results['ports'])}
            
            <h2>Vulnerabilities Found ({len(self.results['vulnerabilities'])})</h2>
            {self._generate_vulns_html()}
        </body>
        </html>
        """
        
        with open(html_file, 'w') as f:
            f.write(html_template)
        print(f"[+] HTML report saved to {html_file}")
    
    def _generate_port_html(self, subdomain):
        """Generate HTML for port scan results"""
        ports = self.results['ports'][subdomain]
        return f"""
        <h3>{subdomain}</h3>
        <table>
            <tr><th>Port</th><th>Protocol</th><th>Service</th><th>Product</th><th>Version</th></tr>
            {"".join(
                f"<tr><td>{p['port']}</td><td>{p['protocol']}</td><td>{p['service']}</td><td>{p['product']}</td><td>{p['version']}</td></tr>"
                for p in ports
            )}
        </table>
        """
    
    def _generate_vulns_html(self):
        """Generate HTML for vulnerabilities"""
        if not self.results['vulnerabilities']:
            return "<p>No vulnerabilities found.</p>"
            
        return """
        <table>
            <tr><th>Target</th><th>Type</th><th>Details</th><th>Source</th></tr>
            """ + "".join(
                f"<tr class='vulnerable'><td>{v['target']}</td><td>{v.get('type', 'N/A')}</td><td>{v.get('url', v.get('data', 'N/A'))}</td><td>{v['source']}</td></tr>"
                for v in self.results['vulnerabilities']
            ) + """
        </table>
        """

def main():
    parser = argparse.ArgumentParser(description="AutoRecon - Automated Reconnaissance and Pentesting Tool")
    parser.add_argument("domain", help="Target domain to scan")
    parser.add_argument("-o", "--output", help="Output directory", default="results")
    parser.add_argument("--shodan-key", help="Shodan API key", default=None)
    args = parser.parse_args()
    
    print(f"""
    █████╗ ██╗   ██╗████████╗ ██████╗ ██████╗ ███████╗ ██████╗ ███╗   ██╗
   ██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗██╔══██╗██╔════╝██╔═══██╗████╗  ██║
   ███████║██║   ██║   ██║   ██║   ██║██████╔╝█████╗  ██║   ██║██╔██╗ ██║
   ██╔══██║██║   ██║   ██║   ██║   ██║██╔══██╗██╔══╝  ██║   ██║██║╚██╗██║
   ██║  ██║╚██████╔╝   ██║   ╚██████╔╝██║  ██║███████╗╚██████╔╝██║ ╚████║
   ╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝ ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═╝  ╚═══╝
   
   Automated Reconnaissance & Pentesting Tool
   Target: {args.domain}
    """)
    
    recon = AutoRecon(args.domain, args.output, args.shodan_key)
    
    # Run all steps
    recon.run_subdomain_enumeration()
    recon.run_port_scanning()
    
    if args.shodan_key:
        recon.check_shodan()
    
    recon.check_common_vulns()
    recon.generate_report()
    
    print("\n[+] AutoRecon completed successfully!")

if __name__ == "__main__":
    main()

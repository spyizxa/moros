# MOROS V1.0 - Red Team Toolkit

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
[![Telegram](https://img.shields.io/badge/Telegram-@swarehackteam-blue.svg)](https://t.me/swarehackteam)
[![Telegram](https://img.shields.io/badge/Telegram-@spyizxa-blue.svg)](https://t.me/spyizxa)

A comprehensive penetration testing framework with 25+ security tools for red team operations.

## Features

- **Information Gathering**
  - IP/Domain WHOIS & DNS lookups
  - Reverse IP lookup
  - Port scanning

- **Web Application Testing**
  - SQL Injection Scanner
  - XSS Scanner
  - LFI/RFI Scanner
  - IDOR Vulnerability Finder
  - CMS Detection (WordPress/Joomla/Drupal)
  - Backup File Finder

- **Brute Force Attacks**
  - SSH/FTP Brute Force
  - WordPress Login Bruteforce
  - Custom Wordlist Generator

- **Exploitation Tools**
  - Reverse Shell Generator (Bash/Python/PHP/PowerShell)
  - Payload Generator (MSFVenom style)
  - CSRF Exploit Generator

- **Other Utilities**
  - WAF Detection
  - Webhook Testing
  - Basic Malware Analysis
  - Report Generation (HTML/CSV/TXT/JSON)

## Installation

```bash
git clone https://github.com/yourusername/moros.git && cd moros && pip install -r requirements.txt && python3 moros.py

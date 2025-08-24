# 🕵️ Raw Address Scanner

A lightweight C++ tool that scans threads across all processes owned by the current user and flags anything sketchy.  
It’s designed to help with **threat detection, debugging, and exploring Windows internals** in a simple way.

---

## ⚡ Features
- Scans all processes owned by the current user.  
- Flags suspicious threads where the instruction pointer (RIP) doesn’t belong to any loaded module in the process’s PEB.  
- Skips trusted regions (`RIP >= 0x7FF900000000`) to reduce false positives (these usually map to **ntdll.dll**, **kernel32.dll**, etc.).  
- Ignores common developer tools and critical system processes for cleaner results.  
- Lightweight and fast — no heavy dependencies.  

---

## 🚀 Use Cases
- Detect potential **injected or remote code** in running processes.  
- Debugging thread anomalies.  
- Learning and experimenting with **Windows internals**.  

---

## 📥 Installation
1. Download the latest release from the [Releases](../../releases) page.  
2. Extract and run the executable (`RawAddressScanner.exe`).  

---

## 🖥️ Usage
Simply run from a command prompt:

```bash
RawAddressScanner.exe

## 📷 Project Structure
![Project Structure](https://your-image-url-here.png)

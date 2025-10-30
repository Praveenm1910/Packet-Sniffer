# 🕵️‍♂️ Packet Sniffer in C using libpcap

A simple yet powerful **network packet sniffer** written in **C**, built using the **libpcap** library.  
This tool captures live network packets, extracts Ethernet header information, and displays packet payloads in a human-readable format.

---

## 📘 Features

- Captures real-time network packets on a specified interface  
- Displays:
  - Packet number and timestamp  
  - Packet length (in bytes)  
  - Source and Destination MAC addresses  
  - Raw packet payload (printable characters only)
- Supports **custom BPF filters** (e.g., `port 80`, `tcp`, `udp`, `host 192.168.1.10`)  
- Promiscuous mode enabled for full packet visibility  
- Simple, lightweight, and easily extendable for cybersecurity research

---

## 🧠 How It Works

1. Opens a specified network interface (like `eth0` or `wlan0`) using **libpcap**
2. Applies a **user-defined filter expression**
3. Captures packets in real-time
4. Parses the **Ethernet header**
5. Prints packet details and payload to the terminal

---

## ⚙️ Requirements

Before building, ensure the following are installed:

### 🧩 Dependencies
- GCC compiler
- libpcap development library

### 📦 Install on Linux
```bash
sudo apt update
sudo apt install build-essential libpcap-dev

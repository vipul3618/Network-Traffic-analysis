# Network Traffic Analysis & Security Diagnostics Lab

### 🛡️ Project Overview
This project documents a series of network analysis exercises conducted to simulate, detect, and troubleshoot real-world network anomalies and security threats. Using **Wireshark**, **Nmap**, and **Tcpdump**, I analyzed packet-level data to diagnose connectivity issues and identify malicious traffic patterns.

The objective of this lab is to demonstrate proficiency in **Packet Capture (PCAP) analysis**, **TCP/IP protocol behavior**, and **Network Forensics**.

---

### 🛠️ Tools & Technologies
*   **Network Analysis:** Wireshark v4.0, Tcpdump
*   **Network Scanning:** Nmap
*   **Traffic Generation:** Browser (HTTP/HTTPS), Python scripts
*   **Environment:** Virtualized Lab (Windows/Linux VMs)

---

### 📂 Module 1: Protocol Security (HTTP vs. HTTPS)
**Objective:** Demonstrate the vulnerability of unencrypted transport protocols by capturing credentials in plain text.

*   **Scenario:** A user logs into a legacy web application using HTTP.
*   **Wireshark Filter Used:**
    ```wireshark
    http.request.method == "POST"
    ```
*   **Analysis:**
    *   Isolated the `POST` request to the login server.
    *   Inspected the **Application Layer (HTML Form URL Encoded)**.
    *   **Finding:** Extracted plain-text `username` and `password` fields.
    *   **Comparison:** Analyzed a subsequent HTTPS login, verifying the **TLS 1.2 Handshake** and confirming that application data was encrypted and unreadable.

![Placeholder: Insert Screenshot of HTTP Password Capture Here]

---

### 📂 Module 2: Latency & Packet Loss Troubleshooting
**Objective:** Diagnose network performance issues by analyzing TCP handshake behaviors.

*   **Scenario:** User reports slow connection speeds and "lag" when accessing a file server.
*   **Wireshark Filter Used:**
    ```wireshark
    tcp.analysis.retransmission || tcp.analysis.duplicate_ack
    ```
*   **Analysis:**
    *   Identified a high volume of **TCP Retransmissions** (Black/Red packets).
    *   Observed multiple **Duplicate ACKs**, indicating that the client received out-of-order packets.
    *   **Conclusion:** The issue was not bandwidth saturation, but rather packet loss occurring at the router level, forcing the TCP protocol to re-send data segments.

---

### 📂 Module 3: Intrusion Detection (Nmap Scan Analysis)
**Objective:** Detect and fingerprint network reconnaissance activities (Port Scanning).

*   **Scenario:** An unknown IP is attempting to map open ports on the local network.
*   **Methodology:**
    1.  Launched a Stealth Scan (`nmap -sS`) against the target.
    2.  Captured traffic on the victim machine.
*   **Wireshark Filter Used:**
    ```wireshark
    ip.addr == [Attacker_IP] && tcp.flags.syn == 1 && tcp.flags.ack == 0
    ```
*   **Analysis:**
    *   Observed a flood of **SYN** packets to sequential ports (80, 443, 21, 22) within milliseconds.
    *   Noted the absence of the final **ACK** packet (the 3-way handshake was never completed).
    *   **Conclusion:** This pattern confirms a "Half-Open" SYN scan, typical of reconnaissance tools like Nmap.

![Placeholder: Insert Screenshot of Nmap SYN Flood Here]

---

### 🚀 Key Competencies Demonstrated
*   **Deep Packet Inspection (DPI):** Ability to dissect packet headers (Ethernet, IP, TCP, HTTP) to find root causes.
*   **Forensics:** Identifying Indicators of Compromise (IoCs) such as port scans and brute-force patterns.
*   **Troubleshooting:** Distinguishing between application errors (HTTP 404/500) and transport errors (Retransmissions/Resets).
*   **Filters:** Mastery of Wireshark Display Filters and BPF (Berkeley Packet Filters).

---

### ⚠️ Disclaimer
All traffic analysis was conducted in an isolated, controlled lab environment. No unauthorized systems were scanned or accessed during this project.

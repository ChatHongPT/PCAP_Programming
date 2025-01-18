# Packet Information Capture Program - KITRI WHS

[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Build Status](https://img.shields.io/badge/build-passing-brightgreen)](#)
[![Platform](https://img.shields.io/badge/platform-Linux-blue)](#)


This program captures and displays information about Ethernet, IP, and TCP packets using the `pcap` library. It is implemented in C/C++ and demonstrates the use of low-level networking APIs to analyze packets from a specific network interface.

## Features
- Captures Ethernet, IP, and TCP header details.
- Displays MAC addresses, IP addresses, and port numbers.
- Processes a specified number of packets in real-time.

## Prerequisites

Before running the program, ensure the following are installed on your system:

- GCC or another C/C++ compiler
- `libpcap` library and development headers
- Root or administrative privileges (required to access network interfaces)

## Compilation and Execution

1. Clone or download this repository.
2. Compile the program using:
   ```bash
   gcc -o PCAP_Programming PCAP_Programming.c -lpcap
   ```
3. Run the program with administrative privileges:
   ```bash
   sudo ./PCAP_Programming.c
   ```

## Output

The program prints the following information for each captured packet:
- **Ethernet Header**
  - Source MAC Address
  - Destination MAC Address
- **IP Header**
  - Source IP Address
  - Destination IP Address
- **TCP Header**
  - Source Port
  - Destination Port

### Sample Output
```
<Capture the Packet!>
MAC Source Address: 00:1a:2b:3c:4d:5e
MAC Destination Address: 01:2b:3c:4d:5e:6f

IP Source Address: 192.168.1.2
IP Destination Address: 192.168.1.3

Port Source Address: 443
Port Destination Address: 51545
```
## Notes

1. Replace `ens33` with the name of the network interface on your system.
   - Use `ifconfig` or `ip a` to list available network interfaces.
2. The program is designed for educational purposes. Ensure you comply with local laws and regulations when capturing network traffic.
3. Modify the `pcap_loop` parameter to adjust the number of packets to capture.

## License

This project is licensed under the MIT License. See the `LICENSE` file for details.

## Contributions

Feel free to submit issues and pull requests for improvements or bug fixes.

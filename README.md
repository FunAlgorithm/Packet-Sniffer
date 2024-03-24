# Packet-Sniffer
This repository contains code for a packet sniffer application written in C. The packet sniffer is capable of capturing and analyzing network packets at the data link layer and network layer.

## Features
**&bull; Capture Packets**: The packet sniffer captures network packets from the data link layer using a raw socket.

**&bull; Analyze Packets**: It analyzes captured packets to extract information such as Ethernet headers, IP headers, TCP headers, and UDP headers.

**&bull; Display Information**: The packet sniffer displays detailed information about each packet, including source and destination addresses, protocol type, packet length, TTL, and more.

## Requirements
**&bull; Operating System**: Linux-based operating system (tested on Ubuntu).

**&bull; Development Environment**: GCC compiler and standard C libraries.

**&bull; Permissions**: The application requires root privileges to capture network packets.

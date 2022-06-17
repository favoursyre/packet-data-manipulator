# Packet Data Manipulator
## Disclaimer
This script is for educational purposes only, I don't endorse or promote it's illegal usage

## Table of Contents
1. [Overview](#overview)
2. [Features](#features)
3. [Languages](#languages)
4. [Installations](#installations)
5. [Usage](#usage)
6. [Run](#run)

## Overview
This script performs a range of malicious packet data manipulations

## Features
* Performs a MITM attack and sniffs on the network
* Sniffs on target's network
* Performs a DOS attack

## Languages
* Python 3.9.7

## Installations
```shell
pip install scapy
pip install netifaces
```

## Usage
Instantiating the class
```python
target = "target's name"
target_IP = "target's IP"
packet_bender = PacketBender(target)
```

Performing a MITM attack
```python
count = 25
mitm_attack = packet_bender.sniffMITM(target_IP, count)
#This saves and hides the sniffed pcap file when it's done for you access when you are ready
```

Sniffing the target's network
```python
sniff_net = packet_bender.sniffer(count)
#This saves and hides the sniffed pcap file when it's done for you access when you are ready
```

Performing a DOS attack
```python
packet_count = 1000
dos_attack = packet_bender.dos_attacker(targetIP = target_IP, count_ = packet_count)
```

## Run
```shell
python packet-manipulator.py
```
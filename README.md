# IpSecraw

minimal educational IPsec ESP-like implementation using Linux raw sockets in C.

It demonstrates:

Raw socket packet capture
Adding a custom ESP-style header
AES encryption
Sending modified packets

Real IPsec requires:

Kernel XFRM/Netlink
IKEv2
SPI management
Sequence handling
Replay protection
Authentication (HMAC)
SA negotiation

But this is a good learning prototype.

This sample:

Captures IPv4 packets
Adds ESP-like header:
SPI
Sequence number
Encrypts payload using AES-256-CBC
Sends encrypted packet via raw socket

steps to install dependency

sudo apt-get install libssl-dev

step to compile

gcc ipsec_raw.c -o ipsec_raw -lcrypto

run as root 

sudo ./ipsec_raw


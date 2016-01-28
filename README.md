# SecureSocketProtocol
A network library designed to be secure.

Features
---
* Lightweight TCP/IP IPv4 & IPv6 Networking (1Gbps up/down)
* Network Serialization with Protobuf
* Builtin encryptions: Hardware Accelerated AES-256, WopEx
* Builtin Compressions: QuickLz
* Anonimized Authentication (Mazing Handshake) Includes Private Key(s) and Public key
* Layer System: Use multiple encryption(s) on-top of each other
* Data Integrity Layer (HMAC Support)
* SysLogger, A builtin debug logging system for detecting errors and more
* Operational Sockets: a "Virtual Socket" inside the real connection also known as "sessions"
* Message System: Send serialized messages from/to Server/Client with ease
* Set a maximum amount of time a client is able to be connected for
* Client & Server are made with Abstract

Missing Features / Todo's
---
* Download/Upload Kbps limit per client
* HTTP/Socks4/4a/5 Proxy (+Chaining)
* Black/White IP lists
And more features that will come to mind...

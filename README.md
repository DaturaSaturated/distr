**Offline network traffic analyzer written in C++.**

Parses packets from a PCAP file, detects protocol types, and dispatches them to protocol-specific handlers.

---

## ✨ Features

- Reads packets from `.pcap` files  
- Detects IP / TCP / UDP protocols  
- Processes:
  - TCP connections (complete & broken)
  - UDP packets
  - FTP Control traffic
  - FTP Data traffic
- Modular architecture:
  - `sniffer`
  - `parser`
  - `handlers`
  - `tracker`

---

## 🛠 Requirements

- C++17
- libpcap
- CMake

---

## ⚙️ Build

```bash
git clone https://github.com/DaturaSaturated/distr.git
cd distr
mkdir build && cd build
cmake ..
make

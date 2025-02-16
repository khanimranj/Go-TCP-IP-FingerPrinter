# TCP OS Fingerprinting Server (Or application)

Hey there! Welcome to the base code for our TCP OS Fingerprinting Server. This is just the starting point and a work in progress, so don't expect a production-ready solution yet. I am just playing around with raw sockets in Go because I needed to keep myself busy for a few hours.

## What It Does

- **Raw Socket Packet Capture**  
  Listens for incoming TCP packets using raw sockets (IPv4 and, eventually, IPv6).

- **Packet Analysis**  
  Parses IP and TCP headers to extract key fingerprinting signals like TTL, window size, MSS, and more.

- **OS Fingerprinting**  
  Uses a fingerprint signature to try and match packets to known OS profiles (e.g., Windows, macOS, Linux, etc.). This part is not built and the code currently does a simple if else for demo

- **Logging**  
  Prints detailed packet info and OS predictions to the console for debugging and development.

- **Response Handler (Planned)**  
  A placeholder is in place for sending a response back with the OS prediction – more to come!

## Getting Started

### Prerequisites

**Go 1.18+**
This project is written in Go.
**Root Privileges**
Raw socket operations typically require elevated privileges.
**Linux/MacOS**
Tested on Linux, should work on MacOS. Good chances it won't work on windows

### Installation
go run main.go //

### How It Works

    Packet Capture
    The server creates a raw socket to capture incoming TCP packets.

    Header Parsing
    It parses the IPv4 header followed by the TCP header to pull out fingerprinting data.

    Fingerprint Matching
    The extracted data is compared against a signature database (this part is incomplete) that maps various TCP/IP characteristics to specific operating systems.

    Logging & Response
    Results are logged to the console, and a placeholder exists for sending back a response.


### What's Next?


    Enhance Fingerprinting
    Add more detailed checks like MSS, window scaling, SACK support, timestamps, and TCP options order.

    IPv6 Support
    Expand raw socket support for IPv6.

    Crafting Responses
    Build the logic to send crafted TCP responses with OS prediction details.

    Better Concurrency
    Tweak and optimize the code to handle 10,000+ concurrent connections smoothly.

    More Robust Testing
    Expand unit tests to cover more edge cases and improve stability.

### Contributing


This is a fun project and we’re all learning as we go. If you have ideas or improvements, feel free to open an issue or submit a pull request. Let’s make OS fingerprinting fun and educational together!

### Disclaimer
This is just base code and a work in progress. It's not meant for production use. Use it as a learning tool, and contribute back if you make improvements!
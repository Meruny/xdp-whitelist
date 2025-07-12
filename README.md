XDP Whitelist and Rate Limiting Project




Project Introduction
This project implements a network filter using eBPF/XDP on Linux, providing the following functionalities:
Creating a whitelist of authorized IP addresses


Dropping packets from IPs not on the whitelist


Applying rate limiting for unauthorized (non-whitelisted) IPs


Project Structure


netprog.bpf.c         # eBPF program code (attached via XDP)
netprog.bpf.o         # Compiled BPF object file (output)
loader.c              # Loads and attaches BPF program to network interface
whitelist_user.c      # Adds IPs to whitelist and sets rate limits
list_whitelist        # Lists current whitelisted IPs
.output/              # Output folder for compiled files
README.md             # Project documentation







Project Files and Structure
netprog.bpf.c
 The eBPF program code which attaches as an XDP hook on the network interface.
 This code:


Inspects incoming packets


Checks the source IP address


Accepts packets if the IP is on the whitelist


Otherwise, applies rate limiting


Drops packets that exceed the allowed rate


Hooks into the network interface using XDP
- Inspects incoming packets
- Accepts packets from whitelisted IPs
- For non-whitelisted IPs, applies rate limiting
- Drops packets that exceed the rate


whitelist_user.c
 A user-space tool to manage the whitelist.
 It allows adding IPs to the whitelist, setting the allowed rate, and viewing the whitelist.
- Adds IPs to the whitelist
- Sets allowed packet rate per IP
- Displays whitelist contents


loader.c
 A program to load and attach the eBPF program to the network interface and to pin the maps.
	- Loads the compiled eBPF program
- Attaches it to the interface
- Pins BPF maps for user-space access




list_whitelist
 A tool to view the IPs currently in the whitelist.
- Displays IPs in the whitelist



Project Steps
Writing the eBPF Program
 The eBPF program was written in C and attached to the network interface via XDP. It inspects packets before they enter the network stack.


Compiling the Program
 The program was compiled with clang using the appropriate arguments targeting BPF.


Developing User-space Tools
 The whitelist_user tool was developed to add IPs to the whitelist and set allowed rates.


Loading the Program
 The loader program was used to load and attach the eBPF program to the network interface.


Testing Functionality


Ping tests with whitelisted IPs succeeded.


Packets from IPs outside the whitelist or exceeding rate limits were dropped or limited.










Important Notes
The default rate limit for non-whitelisted IPs is 10 packets per second (this value is configurable).


Whitelisted IPs can send packets without rate limiting.


BPF maps are pinned under /sys/fs/bpf/ to allow access from user-space tools.


Issues and Solutions
Initially, the compiler could not find vmlinux.h. This was resolved by adding the correct include path:

 bash
CopyEdit
-I/path/to/vmlinux
 (The exact path depends on your system.)


Network and VM limitations caused some packets to not be sent or received correctly during testing. These issues were debugged by proper network configuration and using tcpdump.


How to Run the Project
Compile the BPF program:

 bash
CopyEdit
clang -O2 -g -target bpf -D__TARGET_ARCH_x86 \
  -I/opt/kernel-playground/vmlinux \
  -I/opt/kernel-playground/kernel/linux/tools/lib/bpf/include \
  -I/opt/kernel-playground/kernel/linux/tools/bpf/resolve_btfids/libbpf/include \
  -c netprog.bpf.c -o .output/netprog.bpf.o




Load and attach the program to the network interface:

 bash
CopyEdit
sudo ./loader eth0 netprog.bpf.o

Add an IP to the whitelist (with a rate limit):

 bash
CopyEdit
sudo ./whitelist_user 10.88.0.10 100

View the whitelist:

 bash
CopyEdit
./list_whitelist

Test ping from whitelisted and non-whitelisted IPs to observe limitations.





Summary
This project helped me learn about eBPF, XDP, map management, and user-space interaction to build an IP-based network access control system with rate limiting. I also practiced network troubleshooting and testing in a virtualized environment.


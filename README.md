PcapVPN
=======

PcapVPN is a small program to turn any two-way connection between hosts into
a layer 2 VPN between one of the hosts and the other host's network.  It does
this using a tap device on one end (the host to put on the target network) and
pcap on the other (on a host on the target network).

This is very much a PoC at the moment and should not be relied upon.  However,
it is very simple and easy enough to audit.

For legal use only.


Details
-------
At its core, PcapVPN is nothing more than an adapter between a tap device and
stdin/out on one side of the VPN (the attacker side, usually) and between pcap
and stdin/out on the other (a victim, usually).

### Attacker side
When used with the `-t` flag, a tap device given on the command line is opened,
and any frames read are sent to standard output.

Any frames read from standard input are written to the tap device.

At the moment, a file interface to the tap device is required, i.e. OpenBSD's
`/dev/tapN` (as created by `ifconfig tap0 create`).

This does not necessarily require root access, so long as the tap device is
accessible by the user running PcapVPN.

### Victim side
When given an interface and a MAC address, an IP address, or a BPF filter,
PcapVPN sniffs the traffic on the given interface and any frames matching the
given MAC address, IP address, or filter are written to standard output.

Any frames read from standard input are injected via the given interface.

This requires PcapVPN be run as root, or, on Linux, given the appropriate
capabilities (e.g. with setcap(7)).

By default, promiscous mode is enabled on the victim's interface.  This can
be changed by setting the `-p` flag on the instance running on the .

### Transport
Generally speaking, PcapVPN is transport-agnostic, though so far, only SSH
has been used to connect the two instances of PcapVPN.  The protocol only adds
two bytes of overhead for every frame, so with possible modification to the MTU
of the tap device, it is likely possible to use UDP, ICMP, or any other sneaky
tunnel which blends in.


Protocol
--------
```
| <----2 bytes----> | <-N Bytes-> |
| Length of Payload |   Payload   |
```
PcapVPN's protocol on the wire is extremely simple.  Each frame has a two-byte
header in network byte order giving the length of the frame, followed
immediately by the frame.  A 0-byte payload (with a header of 0x0000) is legal.

Example
-------
There are two examples below.  Both make these assumptions:
- The attacker is running OpenBSD
- The victim host is running Linux and uses the iproute2 toolset
- The PcapVPN is on both hosts as `pcapvpn`,
- The commands are either run as root or with appropriate use of
doas/sudo/setcap.
- ksh is the shell on the attacker (bash will work, though the syntax to
connect two processes' stdio is different).
- The victim's `eth0` interface is connected to the network 

### Layer 2 filtering and DHCP
This is the "normal" usage for when there's no port filtering, arpwatch, or
anything of the sort.  Once connected, DHCP will be used to get an address.  Of
course, the tap device can just as well be assigned an address manually.

On the attacker:
```sh
# Make the tap device
ifconfig tap0 create

# Start the local end
./pcapvpn -t tap0 |&

# Connect it to the victim and filter on the tap device's MAC address
ssh user@victim "./pcapvpn eth0 $(ifconfig tap0 | egrep -o 'lladdr.*' | cut -f 2 -d ' ')" >&p <&p &

# Get a DHCP lease
dhclient tap0
```
Nothing need be done on the victim.

At this point, tap0 is (virtually) on the network to which the victim's `eth0`
interface is connected.

### Layer 3 filtering and a static address
In the case of MAC filtering on the victim's switch (or VirtualBox), or if
putting another MAC address on the network is a bad idea, it's possible to use
the victim interface's MAC address and only bring back frames destined to a
manually-set IP address.

This requires finding an unused IP address on the target network, as well as
making sure the victim host doesn't react adversely to unwanted frames (i.e.
frames sent to it with the wrong address).  There are various ways to do this;
the example assumes that this information has been previously gathered.

For this example, the victim's mac address is assumed to be `11:22:33:44:55:66`
and it is assumed 1.2.3.4/24 is a valid and unused (and safe to mooch) address
on the victim's network.

On the attacker:
```sh
# Make the tap device
ifconfig tap0 create

# Set to blend in with the target network
ifconfig tap0 lladdr 11:22:33:44:55:66
ifconfig tap0 inet 1.2.3.4/24

# Start the local end
./pcapvpn -t tap0 |&

# Connect it to the victim and filter on the tap device's MAC address
ssh user@victim "./pcapvpn eth0 1.2.3.4" >&p <&p &
```
It is probably wise at this point to monitor traffic on the victim for a bit.


Building
--------
The included script [build.sh](./build.sh) can be used to build PcapVPN.  It
is written for development, and will likely need tweaking, but is a good start,
anyways.


Future Features (Wishlist)
--------------------------
The following features may be implemented in the future:
- Encryption
- Standalone transports
- Linux tap device support
- Windows tap device equivalent support
Pull requests are welcome.

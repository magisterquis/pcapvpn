PcapVPN
=======

PcapVPN connects a tap(4) device on your attack box with your target's network.
It's a sneaky layer-2 VPN.

On the attacker side, it's a proxy between a tap(4) device and stdio
On the victim side, it's a proxy  between pcap sniffing/injection and stdio

Currently OpenBSD and Linux are supported.  It's probably fairly easy to port
to other operating systems.

For legal use only.


Why?
----
This tool solves the following irritants:
- Tools tend to assume a direct connection between tool and target.
- Tools that don't assume a proxy.  Proxies are slow (and require C2 tools
  which provide them).  Also, nobody has managed to agree on HTTP vs SOCKS.
- Port forwarding works great for a handful of TCP ports.  NFS?
- Other VPN solutions require their own comms paths and/or lots of files on
  target.
- Layer-2 VPNs tend to use a tap(4) device on target, which requires bridging,
  routing, nat, etc.
- Port forwarding reveals to defenders the target we've worked so hard to
  acquire.


Usage
-----
The same PcapVPN binary is used on both attacker and target.

###Attacker
This is probably a Kali box, but it's a neat trick to stick this on a gateway
to transparently route its network to target space.

```sh
pcapvpn -t tap_dev
```
Attaches pcapvpn to the given device (e.g. tap0).  On Linux, the device doesn't
need to exist.  It will be created if it does not already exist.

On OpenBSD, `/dev/tapN` should be used.

Any ethernet frame the kernel sends via the tap(4) interface will be written to
stdout, prepended with a two-byte size.

Anything written to stdin is interpreted as two bytes of size, and a ethernet
frame, which is then sent to the kernel via the tap(4) interface.

###Victim
The victim must already be compromised.  

```sh
pcapvpn [-p] device filter
```

Ethernet frames (preceeded by 2-byte sizes) are read from stdin and injected
via the given device.

The filter is used to choose what frames are sniffed from the wire (via the
given device).  This can take one of three forms:
1. MAC address, which is nearly functionally equivalent to plugging another
   device into the target network.
2. IP address, which is useful for when the target's switch does MAC filtering.
   Generally speaking, the MAC address of the tap(4) device on the attack host
   should be set to the MAC address of the device on the victim.
3. BPF filter.  Can be used for minimizing C2 comms.

The `-p` flag puts the victim interface into promiscuous mode.


Example
-------
Using SSH as a C2 channel, the following works nicely
```sh
mkfifo ./f
./pcapvpn -t tap0 <f | ssh user@victim "pcapvpn -p eth0 $(ifconfig tap0 | grep ether | egrep  -o '[a-f0-9:]{17}')" >f
dhclient tap0
```


Windows
-------
Looks possible with npcap or something similar.  Pull requests welcome.

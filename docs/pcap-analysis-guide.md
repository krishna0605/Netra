# PCAP Analysis Guide

This guide explains how to manually inspect the same PCAP files that Netra uploads and analyzes.

## Open a PCAP in Wireshark

1. Open Wireshark.
2. Select `File -> Open`.
3. Choose a file from:

```txt
samples/pcaps/
```

Good demo files:

```txt
samples/pcaps/hydra_ssh.pcap
samples/pcaps/mirai.pcap
samples/pcaps/zeus.pcap
samples/pcaps/normal.pcap
```

## Useful Display Filters

```txt
ip.addr == 192.168.0.10
tcp.port == 22
tcp.port == 21
dns
http
tls
icmp
tcp.flags.syn == 1
frame.len > 1000
```

## Follow a Stream

To inspect a conversation:

```txt
Right-click packet -> Follow -> TCP Stream
```

This is useful for HTTP, FTP, SMTP, and other plaintext protocols. Encrypted TLS traffic will not reveal payload content, but metadata such as SNI, timing, size, and destination remain useful.

## What to Look For

- Many repeated connections to the same service, such as SSH or FTP.
- One host touching many ports or many destinations.
- Very long DNS query names.
- Repeated periodic outbound connections.
- Large outbound transfers.
- Unusual services for the network.
- Many SYN packets without normal completed conversations.

## Compare Wireshark With Netra

| Wireshark View | Netra View |
|---|---|
| Packet list | Packet Explorer |
| Conversations | Sessions |
| Protocol Hierarchy | Protocol Decoder |
| IO Graph | Traffic Timeline |
| Manual findings | Alerts and Anomalies |
| File properties/hash | Evidence Metadata |

Workflow:

1. Open the PCAP in Wireshark.
2. Note suspicious hosts, ports, and protocols.
3. Upload the same PCAP in Netra.
4. Compare Netra alerts, sessions, graph, and report with your manual observations.

# Netra Sensor Agent

The Netra sensor is a small native companion for bounded packet capture. It runs
outside Docker so it can see the host network interfaces exposed by Wireshark
Npcap on Windows or `dumpcap`/`tcpdump` on Linux.

## Windows

```powershell
.\sensor-agent\scripts\install-windows.ps1
npm run netra:sensor:check
npm run netra:sensor:interfaces
npm run netra:sensor:start
```

## Linux

```bash
./sensor-agent/scripts/install-linux.sh
./sensor-agent/scripts/run-linux.sh check
./sensor-agent/scripts/run-linux.sh interfaces
./sensor-agent/scripts/run-linux.sh run
```

The agent registers with the local Netra API, reports interfaces and heartbeats,
polls for bounded capture commands, rotates short PCAP chunks, and uploads each
chunk for encrypted storage and incremental processing.

On Windows, prefer the active Wi-Fi or Ethernet adapter for a first smoke test.
The Npcap loopback adapter can be restricted by the local Npcap installation. If
capture permission is limited, run the sensor terminal as Administrator.

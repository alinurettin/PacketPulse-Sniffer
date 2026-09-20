# 📐 System Architecture Specification: PacketPulse-Sniffer (v2.0.0)
- **Project:** PacketPulse-Sniffer
- **Author:** Expert Software Architect & SDLC Team
- **Status:** APPROVED & VERIFIED
- **Version:** 2.0.0

---

## 1. High-Level Component Topology

```mermaid
flowchart TD
    Raw["📦 Raw Wire Frames (PCAP / Sockets / JSON Hex)"] --> Gateway["⚡ Ingestion API (Port 6023)"]
    Gateway --> Dissector["🔬 Layered Protocol Dissector (Ethernet -> IPv4 -> TCP/UDP -> DNS)"]
    Dissector --> Checksum["🛡️ 16-Bit RFC 791 Checksum Verifier"]
    Dissector --> FlowEngine["🔄 Symmetric Bidirectional Flow Tracker"]
    FlowEngine --> StateMachine["⚙️ TCP 3-Way Handshake State Machine"]
    FlowEngine --> AnomalyEngine["🚨 Security Anomaly Detector (SYN Flood / Port Scan)"]
    FlowEngine --> Exporter["📈 Telemetry & Flow Exporter"]
    Gateway --> WebUI["💻 Dark-Mode Operational Dashboard (public/)"]
```

---

## 2. Packet Dissection Pipeline & Layer Decoding

```mermaid
flowchart LR
    Frame["Ethernet II Frame (14B)"] -->|EtherType 0x0800| IPv4["IPv4 Header (20-60B)"]
    IPv4 -->|Protocol 6| TCP["TCP Segment (20-60B)"]
    IPv4 -->|Protocol 17| UDP["UDP Datagram (8B)"]
    UDP -->|Port 53| DNS["DNS Wire Format (RFC 1035)"]
```

---

## 3. TCP Handshake State Transitions

```mermaid
stateDiagram-v2
    [*] --> INIT: First Packet
    INIT --> SYN_SENT: Outbound SYN (ack=0)
    SYN_SENT --> SYN_RECEIVED: Inbound SYN-ACK
    SYN_RECEIVED --> ESTABLISHED: Outbound ACK
    ESTABLISHED --> FIN_WAIT: FIN Received
    ESTABLISHED --> RESET: RST Received
    FIN_WAIT --> [*]: Closed
    RESET --> [*]: Closed
```

# 🚀 Release Notes: PacketPulse-Sniffer v2.0.0

- **Version:** `2.0.0`
- **Release Type:** Major Architectural Upgrade
- **Author:** Ali Nurettin Demir ([@alinurettin](https://github.com/alinurettin))
- **Date:** 2026-09-20

---

## 🌟 Key Highlights & Enhancements
1. **Multi-Layer Protocol Dissector:**
   - Pure Node.js zero-dependency binary frame decoder for Ethernet II (IEEE 802.3), IPv4 (RFC 791), TCP (RFC 793), UDP (RFC 768), and DNS (RFC 1035 wire format).
   - 16-bit one's complement Internet checksum validation.

2. **Bidirectional Flow Tracker & TCP State Machine:**
   - Canonical symmetric flow pairing (`src:port <-> dst:port:proto`).
   - TCP 3-way handshake state machine tracking: `INIT`, `SYN_SENT`, `SYN_RECEIVED`, `ESTABLISHED`, `FIN_WAIT`, `RESET`.

3. **Autonomous Network Anomaly Detection:**
   - SYN flood anomaly heuristic ($\text{SYN} / \text{ACK} > 4$ under high volume).
   - Horizontal port scan detection flagging attacker IP addresses scanning $> 10$ distinct ports.

4. **Live Operational Web Studio:**
   - Real-time protocol ratio ribbon, active conversation table, interactive traffic generator, and live raw packet hex/base64 dissector.

5. **Exhaustive Automated Test Suite:**
   - 50 non-mocked assertions covering wire decoding, state machines, and live HTTP REST integration.

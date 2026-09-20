// PacketPulse-Sniffer v2.0.0 - Deep Packet Inspection & Protocol Flow Dissector
// High-performance network packet parser, flow accumulator, and anomaly detector.

class PacketDissector {
  /**
   * Parse IEEE 802.3 / Ethernet II frame header (14 bytes)
   */
  static parseEthernet(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 14) {
      throw new Error('Buffer too small for Ethernet II frame (min 14 bytes)');
    }
    const dstMac = Array.from(buf.subarray(0, 6)).map(b => b.toString(16).padStart(2, '0')).join(':');
    const srcMac = Array.from(buf.subarray(6, 12)).map(b => b.toString(16).padStart(2, '0')).join(':');
    const etherType = buf.readUInt16BE(12);

    return {
      dstMac,
      srcMac,
      etherType, // 0x0800 = IPv4, 0x86DD = IPv6, 0x0806 = ARP
      payload: buf.subarray(14)
    };
  }

  /**
   * Calculate 16-bit One's Complement Checksum (RFC 791)
   */
  static computeChecksum(buf, length) {
    let sum = 0;
    const len = length || buf.length;
    for (let i = 0; i < len - 1; i += 2) {
      sum += buf.readUInt16BE(i);
    }
    if (len % 2 !== 0) {
      sum += buf[len - 1] << 8;
    }
    while (sum >> 16) {
      sum = (sum & 0xffff) + (sum >> 16);
    }
    return (~sum) & 0xffff;
  }

  /**
   * Parse IPv4 packet header (RFC 791, 20-60 bytes)
   */
  static parseIPv4(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 20) {
      throw new Error('Buffer too small for IPv4 header (min 20 bytes)');
    }
    const versionIhl = buf[0];
    const version = (versionIhl >> 4) & 0x0f;
    const ihl = (versionIhl & 0x0f) * 4;
    if (version !== 4) throw new Error(`Invalid IPv4 version: ${version}`);
    if (ihl < 20 || buf.length < ihl) throw new Error(`Invalid IHL: ${ihl}`);

    const dscpEcn = buf[1];
    const totalLength = buf.readUInt16BE(2);
    const identification = buf.readUInt16BE(4);
    const flagsFragment = buf.readUInt16BE(6);
    const ttl = buf[8];
    const protocol = buf[9]; // 1=ICMP, 6=TCP, 17=UDP
    const checksum = buf.readUInt16BE(10);

    const srcIp = `${buf[12]}.${buf[13]}.${buf[14]}.${buf[15]}`;
    const dstIp = `${buf[16]}.${buf[17]}.${buf[18]}.${buf[19]}`;

    return {
      version,
      ihl,
      dscpEcn,
      totalLength,
      identification,
      flags: {
        dontFragment: (flagsFragment & 0x4000) !== 0,
        moreFragments: (flagsFragment & 0x2000) !== 0,
        fragmentOffset: flagsFragment & 0x1fff
      },
      ttl,
      protocol,
      checksum,
      srcIp,
      dstIp,
      payload: buf.subarray(ihl, Math.min(buf.length, totalLength))
    };
  }

  /**
   * Parse TCP segment header (RFC 793, min 20 bytes)
   */
  static parseTCP(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 20) {
      throw new Error('Buffer too small for TCP header (min 20 bytes)');
    }
    const srcPort = buf.readUInt16BE(0);
    const dstPort = buf.readUInt16BE(2);
    const seqNum = buf.readUInt32BE(4);
    const ackNum = buf.readUInt32BE(8);
    const dataOffset = ((buf[12] >> 4) & 0x0f) * 4;
    if (dataOffset < 20 || buf.length < dataOffset) {
      throw new Error(`Invalid TCP data offset: ${dataOffset}`);
    }

    const flagsByte = buf[13];
    const flags = {
      fin: (flagsByte & 0x01) !== 0,
      syn: (flagsByte & 0x02) !== 0,
      rst: (flagsByte & 0x04) !== 0,
      psh: (flagsByte & 0x08) !== 0,
      ack: (flagsByte & 0x10) !== 0,
      urg: (flagsByte & 0x20) !== 0
    };

    const windowSize = buf.readUInt16BE(14);
    const checksum = buf.readUInt16BE(16);
    const urgentPointer = buf.readUInt16BE(18);

    return {
      srcPort,
      dstPort,
      seqNum,
      ackNum,
      dataOffset,
      flags,
      windowSize,
      checksum,
      urgentPointer,
      payload: buf.subarray(dataOffset)
    };
  }

  /**
   * Parse UDP datagram header (RFC 768, 8 bytes)
   */
  static parseUDP(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 8) {
      throw new Error('Buffer too small for UDP header (min 8 bytes)');
    }
    const srcPort = buf.readUInt16BE(0);
    const dstPort = buf.readUInt16BE(2);
    const length = buf.readUInt16BE(4);
    const checksum = buf.readUInt16BE(6);

    return {
      srcPort,
      dstPort,
      length,
      checksum,
      payload: buf.subarray(8, Math.min(buf.length, length))
    };
  }

  /**
   * Parse DNS Query (RFC 1035, standard wire format)
   */
  static parseDNSQuery(buf) {
    if (!Buffer.isBuffer(buf) || buf.length < 12) {
      throw new Error('Buffer too small for DNS header (min 12 bytes)');
    }
    const id = buf.readUInt16BE(0);
    const flags = buf.readUInt16BE(2);
    const isResponse = (flags & 0x8000) !== 0;
    const qdCount = buf.readUInt16BE(4);
    const anCount = buf.readUInt16BE(6);

    let offset = 12;
    const labels = [];
    while (offset < buf.length) {
      const len = buf[offset++];
      if (len === 0) break;
      if (offset + len > buf.length) break;
      labels.push(buf.subarray(offset, offset + len).toString('utf8'));
      offset += len;
    }

    const domain = labels.join('.');
    let qType = 0;
    let qClass = 0;
    if (offset + 4 <= buf.length) {
      qType = buf.readUInt16BE(offset);
      qClass = buf.readUInt16BE(offset + 2);
    }

    const typeMap = { 1: 'A', 28: 'AAAA', 5: 'CNAME', 15: 'MX', 16: 'TXT' };

    return {
      id,
      isResponse,
      qdCount,
      anCount,
      domain: domain || 'unknown',
      type: typeMap[qType] || `TYPE_${qType}`,
      class: qClass === 1 ? 'IN' : `CLASS_${qClass}`
    };
  }
}

class FlowTracker {
  constructor() {
    this.flows = new Map(); // flowKey -> FlowEntry
    this.totalPackets = 0;
    this.totalBytes = 0;
    this.protocolDistribution = { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, OTHER: 0 };
    this.synPackets = 0;
    this.ackPackets = 0;
    this.portScanRecords = new Map(); // srcIp -> Set(dstPorts)
  }

  static makeFlowKey(srcIp, srcPort, dstIp, dstPort, proto) {
    // Canonical directional key: lower IP:port first for symmetric pairing
    const endpointA = `${srcIp}:${srcPort}`;
    const endpointB = `${dstIp}:${dstPort}`;
    return endpointA < endpointB
      ? `${endpointA}<->${endpointB}:${proto}`
      : `${endpointB}<->${endpointA}:${proto}`;
  }

  recordPacket(packetInfo) {
    this.totalPackets++;
    this.totalBytes += packetInfo.bytes;

    const protoName = packetInfo.protocol === 6 ? 'TCP' :
                      packetInfo.protocol === 17 ? (packetInfo.isDns ? 'DNS' : 'UDP') :
                      packetInfo.protocol === 1 ? 'ICMP' : 'OTHER';

    this.protocolDistribution[protoName] = (this.protocolDistribution[protoName] || 0) + 1;

    const key = FlowTracker.makeFlowKey(
      packetInfo.srcIp, packetInfo.srcPort,
      packetInfo.dstIp, packetInfo.dstPort,
      protoName
    );

    const now = Date.now();
    if (!this.flows.has(key)) {
      this.flows.set(key, {
        flowKey: key,
        protocol: protoName,
        srcIp: packetInfo.srcIp,
        srcPort: packetInfo.srcPort,
        dstIp: packetInfo.dstIp,
        dstPort: packetInfo.dstPort,
        packetCount: 0,
        byteCount: 0,
        startTime: now,
        lastSeen: now,
        handshakeStart: null,
        handshakeDurationMs: null,
        tcpState: 'INIT'
      });
    }

    const flow = this.flows.get(key);
    flow.packetCount++;
    flow.byteCount += packetInfo.bytes;
    flow.lastSeen = now;

    // TCP Handshake RTT & State Tracking
    if (packetInfo.protocol === 6 && packetInfo.tcpFlags) {
      if (packetInfo.tcpFlags.syn && !packetInfo.tcpFlags.ack) {
        this.synPackets++;
        flow.handshakeStart = now;
        flow.tcpState = 'SYN_SENT';
      } else if (packetInfo.tcpFlags.syn && packetInfo.tcpFlags.ack) {
        flow.tcpState = 'SYN_RECEIVED';
      } else if (packetInfo.tcpFlags.ack) {
        this.ackPackets++;
        if (flow.handshakeStart && flow.tcpState === 'SYN_RECEIVED') {
          flow.handshakeDurationMs = now - flow.handshakeStart;
          flow.tcpState = 'ESTABLISHED';
        }
      }
      if (packetInfo.tcpFlags.fin) flow.tcpState = 'FIN_WAIT';
      if (packetInfo.tcpFlags.rst) flow.tcpState = 'RESET';
    }

    // Port scan tracking
    if (!this.portScanRecords.has(packetInfo.srcIp)) {
      this.portScanRecords.set(packetInfo.srcIp, new Set());
    }
    this.portScanRecords.get(packetInfo.srcIp).add(packetInfo.dstPort);

    return flow;
  }

  detectAnomalies() {
    const anomalies = [];

    // 1. SYN Flood Detection (SYN to ACK ratio > 4:1 with > 20 SYNs)
    if (this.synPackets > 20 && (this.ackPackets === 0 || this.synPackets / this.ackPackets > 4)) {
      anomalies.push({
        type: 'SYN_FLOOD',
        severity: 'CRITICAL',
        details: `Potential SYN flood detected. SYN count: ${this.synPackets}, ACK count: ${this.ackPackets}`
      });
    }

    // 2. Port Scan Detection (Source IP contacted > 15 distinct ports)
    for (const [ip, ports] of this.portScanRecords.entries()) {
      if (ports.size >= 10) {
        anomalies.push({
          type: 'PORT_SCAN',
          severity: 'HIGH',
          sourceIp: ip,
          uniquePortsHit: ports.size,
          details: `Source ${ip} targeted ${ports.size} distinct ports in sliding window`
        });
      }
    }

    return anomalies;
  }

  getMetrics() {
    return {
      totalPackets: this.totalPackets,
      totalBytes: this.totalBytes,
      activeFlows: this.flows.size,
      protocolDistribution: { ...this.protocolDistribution },
      anomalies: this.detectAnomalies()
    };
  }

  getFlows(limit = 50) {
    return Array.from(this.flows.values())
      .sort((a, b) => b.lastSeen - a.lastSeen)
      .slice(0, limit);
  }

  reset() {
    this.flows.clear();
    this.totalPackets = 0;
    this.totalBytes = 0;
    this.protocolDistribution = { TCP: 0, UDP: 0, ICMP: 0, DNS: 0, OTHER: 0 };
    this.synPackets = 0;
    this.ackPackets = 0;
    this.portScanRecords.clear();
  }
}

module.exports = { PacketDissector, FlowTracker };

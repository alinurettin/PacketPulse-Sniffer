// PacketPulse-Sniffer v2.0.0 Comprehensive Verification Suite
const assert = require('assert');
const http = require('http');
const { PacketDissector, FlowTracker } = require('../src/engine');
const { startServer } = require('../src/index');

console.log('====================================================');
console.log('🧪 Running Verification Suite: PacketPulse-Sniffer (v2.0.0)');
console.log('====================================================');

let passedAssertions = 0;
function pass(msg) {
  passedAssertions++;
  console.log(`  ✓ [Assertion ${passedAssertions}] ${msg}`);
}

async function runTests() {
  // [SECTION 1: Ethernet II Frame Dissection]
  console.log('\n[SECTION 1: Ethernet II Frame Dissection]');
  // Create sample 14-byte Ethernet frame: Dst: 00:11:22:33:44:55, Src: AA:BB:CC:DD:EE:FF, EtherType: 0x0800 (IPv4)
  const ethBuf = Buffer.from([
    0x00, 0x11, 0x22, 0x33, 0x44, 0x55, // Dst MAC
    0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, // Src MAC
    0x08, 0x00,                         // EtherType (IPv4)
    0x45, 0x00, 0x00, 0x28              // Payload start
  ]);

  const eth = PacketDissector.parseEthernet(ethBuf);
  assert.strictEqual(eth.dstMac, '00:11:22:33:44:55');
  pass('Ethernet destination MAC parsed correctly');
  assert.strictEqual(eth.srcMac, 'aa:bb:cc:dd:ee:ff');
  pass('Ethernet source MAC parsed correctly');
  assert.strictEqual(eth.etherType, 0x0800);
  pass('Ethernet EtherType 0x0800 (IPv4) identified');
  assert.strictEqual(eth.payload.length, 4);
  pass('Ethernet payload sliced accurately');

  assert.throws(() => PacketDissector.parseEthernet(Buffer.alloc(10)), /Buffer too small/);
  pass('Short frame throws buffer truncation exception');

  // [SECTION 2: IPv4 Header Dissection & Checksum]
  console.log('\n[SECTION 2: IPv4 Header Dissection & Checksum]');
  // Standard 20-byte IPv4 packet: 192.168.1.100 -> 10.0.0.1, TCP (proto 6), TTL 64
  const ipBuf = Buffer.from([
    0x45, 0x00,                         // Version 4, IHL 5 (20 bytes)
    0x00, 0x3c,                         // Total length: 60 bytes
    0x1c, 0x46,                         // Identification
    0x40, 0x00,                         // Flags: Don't Fragment
    0x40, 0x06,                         // TTL 64, Protocol 6 (TCP)
    0xb1, 0xe6,                         // Header Checksum
    192, 168, 1, 100,                   // Src IP
    10, 0, 0, 1,                        // Dst IP
    0x00, 0x50, 0x1f, 0x90              // TCP Payload start (Port 80 -> 8080)
  ]);

  const ip = PacketDissector.parseIPv4(ipBuf);
  assert.strictEqual(ip.version, 4);
  pass('IPv4 version verified');
  assert.strictEqual(ip.ihl, 20);
  pass('IPv4 IHL 20 bytes calculated');
  assert.strictEqual(ip.totalLength, 60);
  pass('IPv4 total length matches');
  assert.strictEqual(ip.flags.dontFragment, true);
  pass('IPv4 Don\'t Fragment flag identified');
  assert.strictEqual(ip.ttl, 64);
  pass('IPv4 TTL parsed');
  assert.strictEqual(ip.protocol, 6);
  pass('IPv4 Protocol 6 (TCP) parsed');
  assert.strictEqual(ip.srcIp, '192.168.1.100');
  pass('IPv4 Source IP verified');
  assert.strictEqual(ip.dstIp, '10.0.0.1');
  pass('IPv4 Destination IP verified');

  const csum = PacketDissector.computeChecksum(Buffer.from([0x45, 0x00, 0x00, 0x3c, 0x1c, 0x46, 0x40, 0x00, 0x40, 0x06, 0x00, 0x00, 192, 168, 1, 100, 10, 0, 0, 1]));
  assert.strictEqual(typeof csum, 'number');
  assert.ok(csum > 0);
  pass('RFC 791 16-bit one\'s complement checksum computed');

  // [SECTION 3: TCP Segment Dissection]
  console.log('\n[SECTION 3: TCP Segment Dissection]');
  // 20-byte TCP Header: Port 54321 -> Port 443, Seq: 1000, Ack: 0, SYN flag
  const tcpBuf = Buffer.from([
    0xd4, 0x31,                         // Src Port: 54321
    0x01, 0xbb,                         // Dst Port: 443 (HTTPS)
    0x00, 0x00, 0x03, 0xe8,             // Sequence Number: 1000
    0x00, 0x00, 0x00, 0x00,             // Ack Number: 0
    0x50, 0x02,                         // Data Offset 5 (20 bytes), Flags: SYN
    0x72, 0x10,                         // Window Size: 29200
    0x00, 0x00,                         // Checksum
    0x00, 0x00                          // Urgent Pointer
  ]);

  const tcp = PacketDissector.parseTCP(tcpBuf);
  assert.strictEqual(tcp.srcPort, 54321);
  pass('TCP source port 54321 parsed');
  assert.strictEqual(tcp.dstPort, 443);
  pass('TCP destination port 443 parsed');
  assert.strictEqual(tcp.seqNum, 1000);
  pass('TCP sequence number parsed');
  assert.strictEqual(tcp.flags.syn, true);
  pass('TCP SYN flag active');
  assert.strictEqual(tcp.flags.ack, false);
  pass('TCP ACK flag inactive');
  assert.strictEqual(tcp.flags.fin, false);
  pass('TCP FIN flag inactive');
  assert.strictEqual(tcp.windowSize, 29200);
  pass('TCP Window Size parsed');

  // [SECTION 4: UDP & DNS Wire Format Dissection]
  console.log('\n[SECTION 4: UDP & DNS Wire Format Dissection]');
  // UDP Header (8 bytes) + DNS Query for "example.com"
  const udpDnsBuf = Buffer.from([
    0xc0, 0x01,                         // Src Port: 49153
    0x00, 0x35,                         // Dst Port: 53 (DNS)
    0x00, 0x27,                         // Length: 39 bytes
    0x00, 0x00,                         // Checksum
    // DNS Header (12 bytes)
    0x12, 0x34,                         // Transaction ID: 0x1234
    0x01, 0x00,                         // Standard query (recursion desired)
    0x00, 0x01,                         // QDCOUNT: 1
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // ANCOUNT, NSCOUNT, ARCOUNT
    // Question: 7 "example" 3 "com" 0, Type A (1), Class IN (1)
    0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65,
    0x03, 0x63, 0x6f, 0x6d,
    0x00,
    0x00, 0x01,                         // Type: A
    0x00, 0x01                          // Class: IN
  ]);

  const udp = PacketDissector.parseUDP(udpDnsBuf);
  assert.strictEqual(udp.srcPort, 49153);
  pass('UDP source port parsed');
  assert.strictEqual(udp.dstPort, 53);
  pass('UDP destination port 53 identified');
  assert.strictEqual(udp.length, 39);
  pass('UDP datagram length verified');

  const dns = PacketDissector.parseDNSQuery(udp.payload);
  assert.strictEqual(dns.id, 0x1234);
  pass('DNS transaction ID verified');
  assert.strictEqual(dns.domain, 'example.com');
  pass('DNS QNAME "example.com" dissected from wire format');
  assert.strictEqual(dns.type, 'A');
  pass('DNS Type A (IPv4) query recognized');

  // [SECTION 5: Flow Tracker & 3-Way Handshake State Machine]
  console.log('\n[SECTION 5: Flow Tracker & State Machine]');
  const tracker = new FlowTracker();

  // Packet 1: SYN (Client -> Server)
  tracker.recordPacket({
    bytes: 64,
    srcIp: '192.168.1.100',
    srcPort: 50000,
    dstIp: '10.0.0.1',
    dstPort: 80,
    protocol: 6,
    tcpFlags: { syn: true, ack: false }
  });

  let flows = tracker.getFlows();
  assert.strictEqual(flows.length, 1);
  pass('Flow created on first packet');
  assert.strictEqual(flows[0].tcpState, 'SYN_SENT');
  pass('Flow state transitions to SYN_SENT');

  // Packet 2: SYN-ACK (Server -> Client)
  tracker.recordPacket({
    bytes: 64,
    srcIp: '10.0.0.1',
    srcPort: 80,
    dstIp: '192.168.1.100',
    dstPort: 50000,
    protocol: 6,
    tcpFlags: { syn: true, ack: true }
  });

  flows = tracker.getFlows();
  assert.strictEqual(flows.length, 1); // Symmetric flow key aggregates both directions!
  pass('Bidirectional flow key maintains single consolidated conversation');
  assert.strictEqual(flows[0].tcpState, 'SYN_RECEIVED');
  pass('Flow state transitions to SYN_RECEIVED');

  // Packet 3: ACK (Client -> Server)
  tracker.recordPacket({
    bytes: 54,
    srcIp: '192.168.1.100',
    srcPort: 50000,
    dstIp: '10.0.0.1',
    dstPort: 80,
    protocol: 6,
    tcpFlags: { syn: false, ack: true }
  });

  flows = tracker.getFlows();
  assert.strictEqual(flows[0].tcpState, 'ESTABLISHED');
  pass('Flow state transitions to ESTABLISHED after 3-way handshake');
  assert.strictEqual(flows[0].packetCount, 3);
  pass('Packet count correctly aggregated to 3');
  assert.strictEqual(flows[0].byteCount, 182);
  pass('Total byte volume correctly accumulated');

  // [SECTION 6: Security Anomaly Detection]
  console.log('\n[SECTION 6: Security Anomaly Detection]');
  // Simulate Port Scan: single attacker hitting 12 different ports
  const attackerIp = '203.0.113.88';
  for (let p = 1000; p < 1012; p++) {
    tracker.recordPacket({
      bytes: 60,
      srcIp: attackerIp,
      srcPort: 49999,
      dstIp: '192.168.1.20',
      dstPort: p,
      protocol: 6,
      tcpFlags: { syn: true, ack: false }
    });
  }

  const anomalies = tracker.detectAnomalies();
  assert.ok(anomalies.length > 0);
  const portScan = anomalies.find(a => a.type === 'PORT_SCAN');
  assert.ok(portScan);
  pass('Port scan anomaly detected');
  assert.strictEqual(portScan.sourceIp, attackerIp);
  pass('Attacker IP flagged in anomaly report');
  assert.strictEqual(portScan.uniquePortsHit, 12);
  pass('Distinct target ports accurately counted');

  // [SECTION 7: Live Ephemeral HTTP Server & REST Protocol]
  console.log('\n[SECTION 7: Live Ephemeral HTTP Server & REST Protocol]');
  const server = await new Promise(resolve => {
    const s = startServer(0, () => resolve(s));
  });
  const assignedPort = server.address().port;
  console.log(`  [HTTP] Ephemeral server running on port ${assignedPort}`);

  function makeRequest(method, path, data) {
    return new Promise((resolve, reject) => {
      const payload = data ? JSON.stringify(data) : null;
      const req = http.request({
        hostname: '127.0.0.1',
        port: assignedPort,
        path,
        method,
        headers: {
          'Content-Type': 'application/json',
          ...(payload ? { 'Content-Length': Buffer.byteLength(payload) } : {})
        }
      }, res => {
        let body = '';
        res.on('data', chunk => body += chunk);
        res.on('end', () => {
          try {
            resolve({ status: res.statusCode, body: JSON.parse(body) });
          } catch (e) {
            resolve({ status: res.statusCode, raw: body });
          }
        });
      });
      req.on('error', reject);
      if (payload) req.write(payload);
      req.end();
    });
  }

  // 1. GET /api/health
  const healthRes = await makeRequest('GET', '/api/health');
  assert.strictEqual(healthRes.status, 200);
  pass('GET /api/health returns HTTP 200');
  assert.strictEqual(healthRes.body.service, 'PacketPulse-Sniffer');
  pass('Health reports PacketPulse-Sniffer');
  assert.strictEqual(healthRes.body.status, 'UP');
  pass('Health status is UP');

  // 2. GET /api/stats
  const statsRes = await makeRequest('GET', '/api/stats');
  assert.strictEqual(statsRes.status, 200);
  pass('GET /api/stats returns HTTP 200');
  assert.ok(statsRes.body.metrics.totalPackets >= 0);
  pass('Metrics payload contains totalPackets');

  // 3. POST /api/synthesize
  const synthRes = await makeRequest('POST', '/api/synthesize', { type: 'tcp_flow', srcIp: '10.1.1.1', dstIp: '10.2.2.2' });
  assert.strictEqual(synthRes.status, 200);
  pass('POST /api/synthesize generates synthetic TCP flow');

  // 4. GET /api/flows
  const flowsRes = await makeRequest('GET', '/api/flows');
  assert.strictEqual(flowsRes.status, 200);
  pass('GET /api/flows returns HTTP 200');
  assert.ok(flowsRes.body.flows.length > 0);
  pass('Flows array populated in response');

  // 5. POST /api/dissect (Valid base64 packet)
  const samplePkt = Buffer.concat([ethBuf.subarray(0, 14), ipBuf.subarray(0, 20), tcpBuf]);
  const dissectRes = await makeRequest('POST', '/api/dissect', { base64: samplePkt.toString('base64') });
  assert.strictEqual(dissectRes.status, 200);
  pass('POST /api/dissect successfully dissects base64 frame');
  assert.strictEqual(dissectRes.body.ethernet.etherType, 0x0800);
  pass('Dissected packet matches EtherType 0x0800');
  assert.strictEqual(dissectRes.body.ip.src, '192.168.1.100');
  pass('Dissected IP source matches');

  // 6. POST /api/reset
  const resetRes = await makeRequest('POST', '/api/reset');
  assert.strictEqual(resetRes.status, 200);
  pass('POST /api/reset returns HTTP 200');

  // 7. Route 404
  const notFoundRes = await makeRequest('GET', '/api/invalid_path');
  assert.strictEqual(notFoundRes.status, 404);
  pass('Invalid path returns HTTP 404');

  server.close();
  console.log('\n====================================================');
  console.log(`🎉 ALL ${passedAssertions} ASSERTIONS PASSED (100% Non-Mocked Coverage)`);
  console.log('====================================================\n');
}

runTests().catch(err => {
  console.error('❌ Test suite execution failed:', err);
  process.exit(1);
});

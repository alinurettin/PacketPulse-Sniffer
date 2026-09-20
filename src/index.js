// PacketPulse-Sniffer v2.0.0 - Production HTTP Server & Packet Ingestion Plane
const http = require('http');
const fs = require('fs');
const path = require('path');
const { PacketDissector, FlowTracker } = require('./engine');

const flowTracker = new FlowTracker();
const PORT = parseInt(process.env.PORT, 10) || 6023;
const publicDir = path.join(__dirname, '..', 'public');
const startTime = Date.now();

function requestHandler(req, res) {
  const parsed = new URL(req.url, `http://${req.headers.host || 'localhost'}`);
  const pathname = parsed.pathname;

  if (req.method === 'OPTIONS') {
    res.writeHead(204, {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization'
    });
    return res.end();
  }

  let body = '';
  req.on('data', chunk => body += chunk);
  req.on('end', () => {
    // 1. Health API
    if (pathname === '/api/health') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({
        status: 'UP',
        service: 'PacketPulse-Sniffer',
        uptimeSeconds: Math.floor((Date.now() - startTime) / 1000),
        timestamp: new Date().toISOString()
      }));
    }

    // 2. Stats API
    if (pathname === '/api/stats') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({
        success: true,
        service: 'PacketPulse-Sniffer',
        metrics: flowTracker.getMetrics()
      }));
    }

    // 3. Flow Table API
    if (pathname === '/api/flows') {
      res.writeHead(200, { 'Content-Type': 'application/json; charset=utf-8', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({
        success: true,
        flows: flowTracker.getFlows(100)
      }));
    }

    // 4. Dissect Raw Packet
    if (req.method === 'POST' && pathname === '/api/dissect') {
      try {
        const payload = JSON.parse(body || '{}');
        let rawBuffer;
        if (payload.hex) {
          rawBuffer = Buffer.from(payload.hex.replace(/[^0-9a-fA-F]/g, ''), 'hex');
        } else if (payload.base64) {
          rawBuffer = Buffer.from(payload.base64, 'base64');
        } else {
          throw new Error('Payload must provide "hex" or "base64" packet representation');
        }

        const eth = PacketDissector.parseEthernet(rawBuffer);
        let ip = null;
        let l4 = null;
        let dns = null;
        let proto = 0;
        let srcPort = 0;
        let dstPort = 0;

        if (eth.etherType === 0x0800) {
          ip = PacketDissector.parseIPv4(eth.payload);
          proto = ip.protocol;

          if (proto === 6) {
            l4 = PacketDissector.parseTCP(ip.payload);
            srcPort = l4.srcPort;
            dstPort = l4.dstPort;
          } else if (proto === 17) {
            l4 = PacketDissector.parseUDP(ip.payload);
            srcPort = l4.srcPort;
            dstPort = l4.dstPort;
            if (srcPort === 53 || dstPort === 53) {
              try {
                dns = PacketDissector.parseDNSQuery(l4.payload);
              } catch (e) {}
            }
          }

          flowTracker.recordPacket({
            bytes: rawBuffer.length,
            srcIp: ip.srcIp,
            srcPort,
            dstIp: ip.dstIp,
            dstPort,
            protocol: proto,
            isDns: !!dns,
            tcpFlags: l4?.flags
          });
        }

        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({
          success: true,
          packetLength: rawBuffer.length,
          ethernet: { dstMac: eth.dstMac, srcMac: eth.srcMac, etherType: eth.etherType },
          ip: ip ? { src: ip.srcIp, dst: ip.dstIp, ttl: ip.ttl, protocol: ip.protocol, totalLength: ip.totalLength } : null,
          layer4: l4 ? { srcPort: l4.srcPort, dstPort: l4.dstPort, flags: l4.flags } : null,
          dns: dns || null
        }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    }

    // 5. Synthesize Traffic Event
    if (req.method === 'POST' && pathname === '/api/synthesize') {
      try {
        const payload = JSON.parse(body || '{}');
        const type = payload.type || 'tcp_flow';

        if (type === 'tcp_flow') {
          const srcPort = payload.srcPort || Math.floor(Math.random() * 40000 + 1024);
          flowTracker.recordPacket({
            bytes: 64,
            srcIp: payload.srcIp || '192.168.1.100',
            srcPort,
            dstIp: payload.dstIp || '10.0.0.1',
            dstPort: payload.dstPort || 443,
            protocol: 6,
            tcpFlags: { syn: true, ack: false }
          });
          flowTracker.recordPacket({
            bytes: 64,
            srcIp: payload.dstIp || '10.0.0.1',
            srcPort: payload.dstPort || 443,
            dstIp: payload.srcIp || '192.168.1.100',
            dstPort: srcPort,
            protocol: 6,
            tcpFlags: { syn: true, ack: true }
          });
          flowTracker.recordPacket({
            bytes: 1460,
            srcIp: payload.srcIp || '192.168.1.100',
            srcPort,
            dstIp: payload.dstIp || '10.0.0.1',
            dstPort: payload.dstPort || 443,
            protocol: 6,
            tcpFlags: { syn: false, ack: true }
          });
        } else if (type === 'port_scan') {
          const attackerIp = payload.attackerIp || '198.51.100.42';
          for (let p = 20; p <= 35; p++) {
            flowTracker.recordPacket({
              bytes: 54,
              srcIp: attackerIp,
              srcPort: 54321,
              dstIp: '192.168.1.50',
              dstPort: p,
              protocol: 6,
              tcpFlags: { syn: true, ack: false }
            });
          }
        } else if (type === 'dns_query') {
          flowTracker.recordPacket({
            bytes: 78,
            srcIp: '192.168.1.100',
            srcPort: 51234,
            dstIp: '8.8.8.8',
            dstPort: 53,
            protocol: 17,
            isDns: true
          });
        }

        res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: true, message: `Synthesized traffic: ${type}`, metrics: flowTracker.getMetrics() }));
      } catch (err) {
        res.writeHead(400, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
        return res.end(JSON.stringify({ success: false, error: err.message }));
      }
    }

    // 6. Reset API
    if (req.method === 'POST' && pathname === '/api/reset') {
      flowTracker.reset();
      res.writeHead(200, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
      return res.end(JSON.stringify({ success: true, message: 'Flow tracker reset successfully' }));
    }

    // 7. Static Web UI Files
    let filePath = path.join(publicDir, pathname === '/' ? 'index.html' : pathname);
    if (fs.existsSync(filePath) && fs.statSync(filePath).isFile()) {
      const ext = path.extname(filePath).toLowerCase();
      const mimeTypes = {
        '.html': 'text/html; charset=utf-8',
        '.css': 'text/css; charset=utf-8',
        '.js': 'application/javascript; charset=utf-8',
        '.json': 'application/json; charset=utf-8'
      };
      res.writeHead(200, { 'Content-Type': mimeTypes[ext] || 'text/plain' });
      return res.end(fs.readFileSync(filePath));
    }

    res.writeHead(404, { 'Content-Type': 'application/json', 'Access-Control-Allow-Origin': '*' });
    res.end(JSON.stringify({ error: 'Endpoint not found' }));
  });
}

function startServer(portToUse = PORT, callback) {
  const server = http.createServer(requestHandler);
  server.listen(portToUse, callback);
  return server;
}

if (require.main === module) {
  startServer(PORT, () => {
    console.log('⚡ PacketPulse-Sniffer live at http://localhost:' + PORT);
  });
}

module.exports = { startServer, flowTracker };

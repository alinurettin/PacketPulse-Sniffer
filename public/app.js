// PacketPulse-Sniffer Client Dashboard Logic
let streamInterval = null;

const sampleEthernetHex = '001122334455aabbccddeeff08004500003c1c4640004006b1e6c0a801640a000001d43101bb000003e8000000005002721000000000';

const el = {
  valTotalPackets: document.getElementById('valTotalPackets'),
  valTotalBytes: document.getElementById('valTotalBytes'),
  valActiveFlows: document.getElementById('valActiveFlows'),
  valProtoDist: document.getElementById('valProtoDist'),
  valAlertsCount: document.getElementById('valAlertsCount'),
  anomalyBanner: document.getElementById('anomalyBanner'),
  anomalyList: document.getElementById('anomalyList'),
  btnResetAll: document.getElementById('btnResetAll'),
  btnSimTcp: document.getElementById('btnSimTcp'),
  btnSimDns: document.getElementById('btnSimDns'),
  btnSimScan: document.getElementById('btnSimScan'),
  btnToggleStream: document.getElementById('btnToggleStream'),
  dissectForm: document.getElementById('dissectForm'),
  hexInput: document.getElementById('hexInput'),
  btnLoadSample: document.getElementById('btnLoadSample'),
  dissectOutput: document.getElementById('dissectOutput'),
  btnRefreshFlows: document.getElementById('btnRefreshFlows'),
  flowsBody: document.getElementById('flowsBody')
};

function formatBytes(bytes) {
  if (bytes === 0) return '0 B';
  const k = 1024;
  const sizes = ['B', 'KB', 'MB', 'GB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(2)) + ' ' + sizes[i];
}

async function fetchTelemetry() {
  try {
    const res = await fetch('/api/stats');
    if (!res.ok) return;
    const data = await res.json();
    const m = data.metrics;
    if (!m) return;

    el.valTotalPackets.textContent = m.totalPackets.toLocaleString();
    el.valTotalBytes.textContent = formatBytes(m.totalBytes);
    el.valActiveFlows.textContent = m.activeFlows.toLocaleString();

    const d = m.protocolDistribution;
    el.valProtoDist.textContent = `TCP: ${d.TCP || 0} | UDP: ${d.UDP || 0} | DNS: ${d.DNS || 0}`;

    const alerts = m.anomalies || [];
    el.valAlertsCount.textContent = alerts.length;

    if (alerts.length > 0) {
      el.anomalyBanner.style.display = 'block';
      el.anomalyList.innerHTML = alerts.map(a => `
        <div class="alert-item">🚨 [${a.type}] (${a.severity}) &bull; ${a.details}</div>
      `).join('');
    } else {
      el.anomalyBanner.style.display = 'none';
      el.anomalyList.innerHTML = '';
    }
  } catch (err) {
    console.error('Failed to fetch telemetry:', err);
  }
}

async function fetchFlows() {
  try {
    const res = await fetch('/api/flows');
    if (!res.ok) return;
    const data = await res.json();
    const flows = data.flows || [];

    if (flows.length === 0) {
      el.flowsBody.innerHTML = '<tr><td colspan="7" class="text-center text-muted">Awaiting network traffic. Click simulator buttons above.</td></tr>';
      return;
    }

    el.flowsBody.innerHTML = flows.map(f => {
      let stateClass = 'tag-state-syn';
      if (f.tcpState === 'ESTABLISHED') stateClass = 'tag-state-est';
      else if (f.tcpState === 'RESET') stateClass = 'tag-state-rst';
      else if (f.tcpState === 'FIN_WAIT') stateClass = 'tag-state-fin';

      const ts = new Date(f.lastSeen).toLocaleTimeString();
      return `
        <tr>
          <td><span class="tag-proto">${f.protocol}</span></td>
          <td>${f.srcIp}:${f.srcPort}</td>
          <td>${f.dstIp}:${f.dstPort}</td>
          <td><strong>${f.packetCount.toLocaleString()}</strong></td>
          <td>${formatBytes(f.byteCount)}</td>
          <td class="${stateClass}">${f.tcpState}</td>
          <td>${ts}</td>
        </tr>
      `;
    }).join('');
  } catch (err) {
    console.error('Failed to fetch flows:', err);
  }
}

async function synthesizeTraffic(type) {
  try {
    await fetch('/api/synthesize', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ type })
    });
    fetchTelemetry();
    fetchFlows();
  } catch (err) {
    console.error('Synthesis failed:', err);
  }
}

// Event Listeners
el.btnSimTcp.addEventListener('click', () => synthesizeTraffic('tcp_flow'));
el.btnSimDns.addEventListener('click', () => synthesizeTraffic('dns_query'));
el.btnSimScan.addEventListener('click', () => synthesizeTraffic('port_scan'));

el.btnToggleStream.addEventListener('click', () => {
  if (streamInterval) {
    clearInterval(streamInterval);
    streamInterval = null;
    el.btnToggleStream.textContent = '▶ Start Stream';
    el.btnToggleStream.classList.remove('active');
  } else {
    streamInterval = setInterval(() => {
      const types = ['tcp_flow', 'tcp_flow', 'dns_query'];
      const pick = types[Math.floor(Math.random() * types.length)];
      synthesizeTraffic(pick);
    }, 500);
    el.btnToggleStream.textContent = '⏸ Stop Stream';
    el.btnToggleStream.classList.add('active');
  }
});

el.btnResetAll.addEventListener('click', async () => {
  try {
    await fetch('/api/reset', { method: 'POST' });
    fetchTelemetry();
    fetchFlows();
  } catch (err) {}
});

el.btnRefreshFlows.addEventListener('click', () => {
  fetchTelemetry();
  fetchFlows();
});

el.btnLoadSample.addEventListener('click', () => {
  el.hexInput.value = sampleEthernetHex;
});

el.dissectForm.addEventListener('submit', async (e) => {
  e.preventDefault();
  const hex = el.hexInput.value.trim();
  try {
    const res = await fetch('/api/dissect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ hex })
    });
    const json = await res.json();
    el.dissectOutput.textContent = JSON.stringify(json, null, 2);
    fetchTelemetry();
    fetchFlows();
  } catch (err) {
    el.dissectOutput.textContent = 'Dissection error: ' + err.message;
  }
});

// Initial load & periodic refresh
fetchTelemetry();
fetchFlows();
setInterval(fetchTelemetry, 3000);

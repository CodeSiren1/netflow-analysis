/* ================================================================
   NETFLOW SIMULATION ENGINE
   ================================================================ */

// --- Static network topology ---
const INTERNAL_ASSETS = [
  {ip:'10.0.1.10', role:'Web Server',     gw:true,  normalPorts:[80,443],       normalProtos:['TCP'],       weight:12},
  {ip:'10.0.1.11', role:'Web Server',     gw:true,  normalPorts:[80,443],       normalProtos:['TCP'],       weight:10},
  {ip:'10.0.1.20', role:'App Server',     gw:true,  normalPorts:[8080,8443],    normalProtos:['TCP'],       weight:11},
  {ip:'10.0.1.21', role:'App Server',     gw:true,  normalPorts:[8080,9090],    normalProtos:['TCP'],       weight:9},
  {ip:'10.0.2.10', role:'DB Server',      gw:true,  normalPorts:[3306],         normalProtos:['TCP'],       weight:6},
  {ip:'10.0.2.11', role:'DB (Postgres)',  gw:true,  normalPorts:[5432],         normalProtos:['TCP'],       weight:5},
  {ip:'10.0.2.50', role:'Cache Redis',    gw:true,  normalPorts:[6379],         normalProtos:['TCP'],       weight:4},
  {ip:'10.0.3.5',  role:'Admin WS',       gw:false, normalPorts:[22,443],       normalProtos:['TCP'],       weight:2,  rogue:true},
  {ip:'10.0.3.6',  role:'Dev WS',         gw:true,  normalPorts:[443,8080],     normalProtos:['TCP'],       weight:2},
  {ip:'10.0.3.7',  role:'Analyst Laptop', gw:false, normalPorts:[443],          normalProtos:['TCP'],       weight:2,  rogue:true},
  {ip:'10.0.4.1',  role:'VoIP Gateway',   gw:false, normalPorts:[5060,5061],    normalProtos:['UDP','SIP'], weight:5},
  {ip:'10.0.4.2',  role:'VoIP Phone',     gw:true,  normalPorts:[5060],         normalProtos:['UDP'],       weight:4},
  {ip:'10.0.5.1',  role:'DNS Server',     gw:true,  normalPorts:[53],           normalProtos:['UDP','TCP'], weight:18},
  {ip:'10.0.5.2',  role:'NTP Server',     gw:true,  normalPorts:[123],          normalProtos:['UDP'],       weight:7},
  {ip:'10.0.5.10', role:'SMTP Relay',     gw:true,  normalPorts:[25,587],       normalProtos:['TCP'],       weight:4},
  {ip:'10.0.6.1',  role:'Load Balancer',  gw:true,  normalPorts:[80,443],       normalProtos:['TCP'],       weight:15},
  {ip:'10.0.6.2',  role:'Reverse Proxy',  gw:true,  normalPorts:[80,443],       normalProtos:['TCP'],       weight:13},
  {ip:'10.0.7.1',  role:'Firewall',       gw:true,  normalPorts:[443,22],       normalProtos:['TCP','ICMP'],weight:14},
  {ip:'10.0.7.2',  role:'IDS Sensor',     gw:true,  normalPorts:[514,443],      normalProtos:['TCP','UDP'], weight:8},
  {ip:'10.0.8.1',  role:'SIEM',           gw:true,  normalPorts:[514,9200],     normalProtos:['TCP','UDP'], weight:9},
  {ip:'10.0.8.2',  role:'Log Aggregator', gw:false, normalPorts:[9200,5044],    normalProtos:['TCP'],       weight:6,  rogue:true},
  {ip:'10.0.9.1',  role:'Storage NAS',    gw:true,  normalPorts:[445,2049],     normalProtos:['TCP'],       weight:3},
  {ip:'10.0.9.2',  role:'Backup Target',  gw:true,  normalPorts:[873,22],       normalProtos:['TCP'],       weight:2},
  {ip:'10.0.10.1', role:'Mgmt Switch',    gw:false, normalPorts:[161,22],       normalProtos:['UDP','TCP'], weight:5,  rogue:true},
];

const PUBLIC_IPS = [
  {ip:'8.8.8.8',           org:'Google DNS',        risk:'low',  port:53,  proto:'UDP'},
  {ip:'8.8.4.4',           org:'Google DNS',        risk:'low',  port:53,  proto:'UDP'},
  {ip:'1.1.1.1',           org:'Cloudflare DNS',    risk:'low',  port:53,  proto:'UDP'},
  {ip:'1.0.0.1',           org:'Cloudflare DNS',    risk:'low',  port:53,  proto:'UDP'},
  {ip:'204.79.197.200',    org:'Microsoft',         risk:'low',  port:443, proto:'TCP'},
  {ip:'151.101.1.140',     org:'Fastly CDN',        risk:'low',  port:443, proto:'TCP'},
  {ip:'52.84.15.30',       org:'Amazon AWS',        risk:'low',  port:443, proto:'TCP'},
  {ip:'172.217.14.110',    org:'Google',            risk:'low',  port:443, proto:'TCP'},
  {ip:'104.21.62.15',      org:'Cloudflare',        risk:'low',  port:443, proto:'TCP'},
  {ip:'13.32.99.38',       org:'CloudFront',        risk:'low',  port:443, proto:'TCP'},
  {ip:'74.125.200.84',     org:'Google SMTP',       risk:'low',  port:25,  proto:'TCP'},
  {ip:'185.60.219.35',     org:'Meta/Facebook',     risk:'med',  port:443, proto:'TCP'},
  {ip:'91.108.4.10',       org:'Telegram',          risk:'med',  port:443, proto:'TCP'},
  {ip:'87.240.132.67',     org:'VK (social)',       risk:'med',  port:443, proto:'TCP'},
  {ip:'45.33.32.156',      org:'Linode VPS',        risk:'high', port:22,  proto:'TCP'},
  {ip:'194.165.16.78',     org:'Unknown-RU',        risk:'high', port:4444,proto:'TCP'},
  {ip:'103.224.182.250',   org:'Unknown-CN',        risk:'high', port:8080,proto:'TCP'},
  {ip:'198.51.100.42',     org:'Suspicious ASN',    risk:'high', port:9200,proto:'TCP'},
  {ip:'203.0.113.15',      org:'Unknown-APAC',      risk:'high', port:0,   proto:'ICMP'},
];

const PROTOCOLS = ['TCP','UDP','ICMP','DNS','HTTPS','HTTP','SSH','SIP'];
const SANCTIONED_PORTS = new Set([80,443,8080,8443,53,123,25,587,3306,5432,6379,5060,5061,22,514,9200,161,873,445,2049]);
const GATEWAY = '10.0.0.1';

// --- Simulation State ---
let state = {
  paused: false,
  speed: 3,
  elapsed: 0,          // seconds elapsed (simulated)
  windowSecs: 14400,   // 4 hours
  totalFlows: 0,
  flowBuffer: [],      // recent flows for table
  assetFlows: {},      // ip -> flow count
  pubipFlows: {},      // ip -> {count, org, risk, port, proto}
  natBypass: {},       // ip -> {ext, proto, port, count, first}
  protoFlows: {},      // proto -> count
  portFlows: {},       // port -> {proto, count}
  alertCount: 0,
  flowsThisSec: 0,
  rateHistory: [],     // last 40 data points for rate chart
  lastAlert: null,
  simTime: new Date(),
};

let _lastFlowRendered = 0;

function resetSim(){
  state.elapsed=0; state.totalFlows=0; state.flowBuffer=[];
  state.assetFlows={}; state.pubipFlows={}; state.natBypass={};
  state.protoFlows={}; state.portFlows={}; state.alertCount=0;
  state.flowsThisSec=0; state.rateHistory=[]; state.lastAlert=null;
  state.simTime=new Date();
  document.getElementById('flow-tbody').innerHTML='';
  _lastFlowRendered = 0;
  document.getElementById('alert-banner').classList.remove('show');
  updateAllUI();
}

function togglePause(){
  state.paused=!state.paused;
  const btn=document.getElementById('btn-pause');
  btn.textContent=state.paused?'▶ RESUME':'⏸ PAUSE';
  btn.style.color=state.paused?'var(--green)':'var(--amber)';
  btn.style.borderColor=state.paused?'rgba(0,230,118,.4)':'rgba(255,171,0,.4)';
}

function setSpeed(v){
  state.speed=parseInt(v);
  document.getElementById('speed-lbl').textContent=v+'x';
}

function showTab(id,el){
  document.querySelectorAll('.tab').forEach(t=>t.classList.remove('active'));
  document.querySelectorAll('.section').forEach(s=>s.classList.remove('active'));
  el.classList.add('active');
  document.getElementById('sec-'+id).classList.add('active');
  if(id==='topology'){ topoActive=false; setTimeout(renderTopology,50); }
  else { topoActive=false; if(topoInterval){ clearInterval(topoInterval); topoInterval=null; } }
}

/* ---- Flow Generator ---- */
function weightedRandom(arr){
  const total=arr.reduce((s,a)=>s+a.weight,0);
  let r=Math.random()*total;
  for(const a of arr){r-=a.weight;if(r<=0)return a;}
  return arr[0];
}

function randInt(a,b){return Math.floor(Math.random()*(b-a+1))+a;}
function randChoice(arr){return arr[Math.floor(Math.random()*arr.length)];}
function formatBytes(b){if(b<1024)return b+'B';if(b<1048576)return (b/1024).toFixed(1)+'KB';return (b/1048576).toFixed(2)+'MB';}
function simTimeStr(){
  const h=Math.floor(state.elapsed/3600)%24,m=Math.floor((state.elapsed%3600)/60),s=state.elapsed%60;
  return String(h).padStart(2,'0')+':'+String(m).padStart(2,'0')+':'+String(s).padStart(2,'0');
}

function generateFlow(){
  const asset=weightedRandom(INTERNAL_ASSETS);
  const isOutbound=Math.random()<0.6;
  
  // Decide if this is suspicious (5% chance for rogue assets, 1% otherwise)
  const isSuspicious=(asset.rogue && Math.random()<0.12)||(Math.random()<0.01);
  
  let srcIP, dstIP, proto, srcPort, dstPort, viaGW, pubRef;
  
  if(isOutbound){
    srcIP=asset.ip;
    if(isSuspicious){
      pubRef=PUBLIC_IPS.filter(p=>p.risk==='high')[randInt(0,4)];
    } else {
      pubRef=PUBLIC_IPS.filter(p=>p.risk!=='high')[randInt(0,PUBLIC_IPS.filter(p=>p.risk!=='high').length-1)];
    }
    dstIP=pubRef.ip;
    proto=pubRef.proto;
    dstPort=isSuspicious?pubRef.port:randChoice(asset.normalPorts)||pubRef.port;
    srcPort=randInt(1024,65535);
    viaGW=asset.gw&&!isSuspicious;
  } else {
    pubRef=randChoice(PUBLIC_IPS.filter(p=>p.risk==='low'));
    srcIP=pubRef.ip;
    dstIP=asset.ip;
    proto=randChoice(asset.normalProtos)||'TCP';
    dstPort=randChoice(asset.normalPorts)||80;
    srcPort=randInt(1024,65535);
    viaGW=asset.gw;
  }

  const bytes=isSuspicious?randInt(100,50000):randInt(500,500000);
  const pkts=Math.max(1,Math.floor(bytes/randInt(400,1400)));
  const flag=isSuspicious?'SUSPICIOUS':'NORMAL';

  return {
    time:simTimeStr(), srcIP, dstIP, proto, srcPort, dstPort,
    bytes, pkts, viaGW, flag, isSuspicious,
    asset, pubRef:(isOutbound?pubRef:null), isOutbound,
  };
}

function ingestFlow(f){
  state.totalFlows++;
  state.flowsThisSec++;

  // Asset tracking
  state.assetFlows[f.asset.ip]=(state.assetFlows[f.asset.ip]||0)+1;

  // Public IP tracking
  if(f.pubRef){
    if(!state.pubipFlows[f.pubRef.ip]){
      state.pubipFlows[f.pubRef.ip]={count:0,org:f.pubRef.org,risk:f.pubRef.risk,port:f.dstPort,proto:f.proto};
    }
    state.pubipFlows[f.pubRef.ip].count++;
  }

  // NAT bypass
  if(!f.viaGW && f.isOutbound && f.pubRef){
    const key=f.asset.ip+'|'+f.pubRef.ip;
    if(!state.natBypass[f.asset.ip]){
      state.natBypass[f.asset.ip]={
        role:f.asset.role, ext:f.pubRef.ip, proto:f.proto,
        port:f.dstPort, count:0, first:simTimeStr()
      };
    }
    state.natBypass[f.asset.ip].count++;
  }

  // Protocol tracking
  state.protoFlows[f.proto]=(state.protoFlows[f.proto]||0)+1;

  // Port tracking
  const pk=f.dstPort;
  if(!state.portFlows[pk]) state.portFlows[pk]={proto:f.proto,count:0};
  state.portFlows[pk].count++;

  // Alerts
  if(f.isSuspicious){
    state.alertCount++;
    state.lastAlert={src:f.srcIP,dst:f.dstIP,port:f.dstPort,proto:f.proto,time:f.time};
    showAlert(state.lastAlert);
  }

  // Buffer
  state.flowBuffer.unshift(f);
  if(state.flowBuffer.length>200) state.flowBuffer.pop();
}

function showAlert(a){
  const b=document.getElementById('alert-banner');
  document.getElementById('alert-msg').textContent=
    `[${a.time}] Suspicious: ${a.src} → ${a.dst}:${a.port} (${a.proto}) — possible C2 / unauthorized egress`;
  b.classList.add('show');
  setTimeout(()=>b.classList.remove('show'),6000);
}

/* ---- UI Updates ---- */
function flashVal(id,val){
  const el=document.getElementById(id);
  el.textContent=val;
  el.classList.remove('flash');
  void el.offsetWidth;
  el.classList.add('flash');
}

let lastFlowCount=0;
function updateAllUI(){
  // Metrics
  flashVal('m-flows',state.totalFlows.toLocaleString());
  document.getElementById('m-assets').textContent=Object.keys(state.assetFlows).length;
  document.getElementById('m-pubips').textContent=Object.keys(state.pubipFlows).length;
  document.getElementById('m-nat').textContent=Object.keys(state.natBypass).length;
  document.getElementById('m-proto').textContent=Object.keys(state.protoFlows).length;
  document.getElementById('m-ports').textContent=Object.keys(state.portFlows).length;
  document.getElementById('m-alerts').textContent=state.alertCount;
  document.getElementById('h-total').textContent=state.totalFlows.toLocaleString();

  // Window bar
  const pct=Math.min(100,(state.elapsed/state.windowSecs*100)).toFixed(1);
  document.getElementById('win-fill').style.width=pct+'%';
  document.getElementById('win-pct').textContent=pct+'%';
  const rem=state.windowSecs-state.elapsed;
  const rh=Math.floor(rem/3600),rm=Math.floor((rem%3600)/60),rs=rem%60;
  document.getElementById('win-refresh').textContent=
    String(rh).padStart(2,'0')+':'+String(rm).padStart(2,'0')+':'+String(rs).padStart(2,'0');

  // Elapsed
  const eh=Math.floor(state.elapsed/3600),em=Math.floor((state.elapsed%3600)/60),es=state.elapsed%60;
  document.getElementById('h-elapsed').textContent=
    String(eh).padStart(2,'0')+':'+String(em).padStart(2,'0')+':'+String(es).padStart(2,'0');

  updateCharts();
  updateFlowTable();
  updateAssetList();
  updatePubIPTable();
  updateNATTable();
  updatePortTable();
  updateComplianceTable();
}

/* ---- Flow Table ---- */
function updateFlowTable(){
  const tbody=document.getElementById('flow-tbody');
  const newCount = state.totalFlows - _lastFlowRendered;
  if(newCount <= 0) return;
  _lastFlowRendered = state.totalFlows;
  const newFlows = state.flowBuffer.slice(0, Math.min(newCount, 30));
  newFlows.forEach(f=>{
    const tr=document.createElement('tr');
    tr.className=f.isSuspicious?'alert-row new-row':'new-row';
    const gwBadge=f.viaGW?'<span class="badge ok">YES</span>':'<span class="badge err">NO</span>';
    const flag=f.isSuspicious?'<span class="badge err">ALERT</span>':'<span class="badge ok">NORMAL</span>';
    tr.innerHTML=`
      <td style="font-family:var(--mono);font-size:10px;color:var(--text3)">${f.time}</td>
      <td><code${f.isSuspicious?' class="r"':''}>${f.srcIP}</code></td>
      <td><code${f.isSuspicious?' class="r"':''}>${f.dstIP}</code></td>
      <td><span class="badge info">${f.proto}</span></td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text2)">${f.srcPort}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--amber)">${f.dstPort}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text2)">${formatBytes(f.bytes)}</td>
      <td style="font-family:var(--mono);font-size:10px;color:var(--text2)">${f.pkts}</td>
      <td>${gwBadge}</td>
      <td>${flag}</td>`;
    tbody.insertBefore(tr,tbody.firstChild);
    while(tbody.children.length>200) tbody.removeChild(tbody.lastChild);
  });
}

/* ---- Ticker ---- */
function updateTicker(f){
  const t=document.getElementById('ticker');
  const risk=f.isSuspicious?'err':'ok';
  const flag=f.isSuspicious?'ALERT':'OK';
  t.innerHTML=`<div class="tick-row">
    <span class="t-time">${f.time}</span>
    <span class="t-src" style="${f.isSuspicious?'color:var(--red)':''}">${f.srcIP}</span>
    <span class="t-arrow">→</span>
    <span class="t-dst" style="${f.isSuspicious?'color:var(--red)':''}">${f.dstIP}</span>
    <span class="t-proto">${f.proto}</span>
    <span class="t-port">:${f.dstPort}</span>
    <span class="t-bytes">${formatBytes(f.bytes)}</span>
    <span class="t-flag"><span class="badge ${risk}">${flag}</span></span>
    <span style="font-family:var(--mono);font-size:10px;color:var(--text3)">${f.viaGW?'via GW':'BYPASS'}</span>
  </div>`;
}

/* ---- Asset List ---- */
function updateAssetList(){
  const el=document.getElementById('asset-list');
  el.innerHTML='';
  const sorted=Object.entries(state.assetFlows).sort((a,b)=>b[1]-a[1]);
  sorted.forEach(([ip,cnt])=>{
    const a=INTERNAL_ASSETS.find(x=>x.ip===ip);
    if(!a) return;
    const hasNat=!!state.natBypass[ip];
    const cls=hasNat?'alert':(!a.gw?'warn':'active');
    const div=document.createElement('div');
    div.className='asset-item '+cls;
    div.innerHTML=`<span class="a-ip">${ip}</span><span class="a-role">${a.role}</span><span class="a-flows">${cnt.toLocaleString()}</span><span class="a-status">${hasNat?'<span class="badge err">NAT</span>':(!a.gw?'<span class="badge warn">BYPASS</span>':'<span class="badge ok">OK</span>')}</span>`;
    el.appendChild(div);
  });
}

/* ---- PubIP Table ---- */
function updatePubIPTable(){
  const tbody=document.getElementById('pubip-tbody');
  tbody.innerHTML='';
  const sorted=Object.entries(state.pubipFlows).sort((a,b)=>b[1].count-a[1].count).slice(0,20);
  sorted.forEach(([ip,d])=>{
    const tr=document.createElement('tr');
    const rc=d.risk==='high'?'err':d.risk==='med'?'warn':'ok';
    tr.innerHTML=`<td><code${d.risk==='high'?' class="r"':''}>${ip}</code></td><td style="font-size:11px;color:var(--text2)">${d.org}</td><td style="font-family:var(--mono);color:var(--amber)">${d.port}</td><td style="font-family:var(--mono)">${d.count}</td><td><span class="badge ${rc}">${d.risk.toUpperCase()}</span></td>`;
    tbody.appendChild(tr);
  });
}

/* ---- NAT Table ---- */
function updateNATTable(){
  const tbody=document.getElementById('nat-tbody');
  tbody.innerHTML='';
  Object.entries(state.natBypass).forEach(([ip,d])=>{
    const tr=document.createElement('tr');
    tr.className='alert-row';
    tr.innerHTML=`<td><code class="r">${ip}</code></td><td style="font-size:11px">${d.role}</td><td><code class="r">${d.ext}</code></td><td><span class="badge info">${d.proto}</span></td><td style="font-family:var(--mono);color:var(--amber)">${d.port||'—'}</td><td style="font-family:var(--mono)">${d.count}</td><td style="font-family:var(--mono);font-size:10px;color:var(--text3)">${d.first}</td><td><span class="badge err">Add NAT Rule</span></td>`;
    tbody.appendChild(tr);
  });
  if(!Object.keys(state.natBypass).length){
    const tr=document.createElement('tr');
    tr.innerHTML='<td colspan="8" style="text-align:center;color:var(--text3);font-family:var(--mono);font-size:11px;padding:20px">No bypass traffic detected yet...</td>';
    tbody.appendChild(tr);
  }
}

/* ---- Port Table ---- */
function updatePortTable(){
  const tbody=document.getElementById('port-tbody');
  tbody.innerHTML='';
  const sorted=Object.entries(state.portFlows).sort((a,b)=>b[1].count-a[1].count).slice(0,20);
  sorted.forEach(([port,d])=>{
    const ok=SANCTIONED_PORTS.has(parseInt(port));
    const tr=document.createElement('tr');
    tr.innerHTML=`<td style="font-family:var(--mono);color:var(--amber)">${port}</td><td><span class="badge info">${d.proto}</span></td><td style="font-family:var(--mono)">${d.count}</td><td>${ok?'<span class="badge ok">Sanctioned</span>':'<span class="badge err">Unsanctioned</span>'}</td>`;
    tbody.appendChild(tr);
  });
}

/* ---- Compliance Table ---- */
function updateComplianceTable(){
  const tbody=document.getElementById('comp-tbody');
  tbody.innerHTML='';
  const seen=Object.keys(state.assetFlows);
  INTERNAL_ASSETS.forEach(a=>{
    const flows=state.assetFlows[a.ip]||0;
    if(!flows) return;
    const hasNat=!!state.natBypass[a.ip];
    const gwOk=a.gw&&!hasNat;
    const seenPorts=Object.keys(state.portFlows).filter(p=>a.normalPorts.includes(parseInt(p)));
    const unseenPorts=a.normalPorts.filter(p=>!state.portFlows[p]);
    const seenProtos=Object.keys(state.protoFlows).filter(p=>a.normalProtos.includes(p));
    let score=100;
    if(!gwOk) score-=30;
    if(hasNat) score-=20;
    if(unseenPorts.length>0) score-=10;
    score=Math.max(0,Math.min(100,score));
    const sc=score>=90?'ok':score>=60?'warn':'err';
    const gwb=gwOk?'<span class="badge ok">Via GW</span>':'<span class="badge err">Bypass</span>';
    const tr=document.createElement('tr');
    tr.innerHTML=`<td><code>${a.ip}</code></td><td style="font-size:11px">${a.role}</td><td style="font-size:10px;font-family:var(--mono);color:var(--text2)">${a.normalProtos.join(', ')}</td><td style="font-size:10px;font-family:var(--mono);color:var(--text2)">${a.normalPorts.join(', ')}</td><td>${gwb}</td><td style="font-family:var(--mono)">${flows.toLocaleString()}</td><td><span class="badge ${sc}">${score}%</span></td><td>${score>=90?'<span class="badge ok">Compliant</span>':score>=60?'<span class="badge warn">Partial</span>':'<span class="badge err">Non-Compliant</span>'}</td>`;
    tbody.appendChild(tr);
  });
}

/* ================================================================
   CHARTS
   ================================================================ */
Chart.defaults.color='#3d5a80';
Chart.defaults.borderColor='#1e3050';

let rateChart, protoPieChart, assetChart, pubipChart, protoBarChart;

function initCharts(){
  const fontMono={family:'IBM Plex Mono',size:10};

  rateChart=new Chart(document.getElementById('chart-rate'),{
    type:'line',
    data:{labels:Array(40).fill(''),datasets:[{label:'Flows/sec',data:Array(40).fill(0),borderColor:'#00d4ff',backgroundColor:'rgba(0,212,255,0.06)',borderWidth:1.5,pointRadius:0,fill:true,tension:0.4}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:0},plugins:{legend:{display:false}},scales:{x:{display:false},y:{beginAtZero:true,ticks:{font:fontMono}}}}
  });

  protoPieChart=new Chart(document.getElementById('chart-proto-pie'),{
    type:'doughnut',
    data:{labels:[],datasets:[{data:[],backgroundColor:['#00d4ff','#00e676','#ffab00','#bb86fc','#ff4444','#26c6da','#ff7043','#69f0ae'],borderWidth:0,hoverOffset:4}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:300},plugins:{legend:{position:'bottom',labels:{font:fontMono,boxWidth:8,padding:8}}}}
  });

  assetChart=new Chart(document.getElementById('chart-assets'),{
    type:'bar',
    data:{labels:[],datasets:[{label:'Flows',data:[],backgroundColor:'rgba(0,230,118,0.35)',borderColor:'#00e676',borderWidth:1,borderRadius:2}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:200},indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{font:fontMono}},y:{ticks:{font:{family:'IBM Plex Mono',size:9}}}}}
  });

  pubipChart=new Chart(document.getElementById('chart-pubips'),{
    type:'bar',
    data:{labels:[],datasets:[{label:'Flows',data:[],backgroundColor:'rgba(255,171,0,0.35)',borderColor:'#ffab00',borderWidth:1,borderRadius:2}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:200},indexAxis:'y',plugins:{legend:{display:false}},scales:{x:{beginAtZero:true,ticks:{font:fontMono}},y:{ticks:{font:{family:'IBM Plex Mono',size:9}}}}}
  });

  protoBarChart=new Chart(document.getElementById('chart-proto-bar'),{
    type:'bar',
    data:{labels:[],datasets:[{label:'Flows',data:[],backgroundColor:'rgba(187,134,252,0.35)',borderColor:'#bb86fc',borderWidth:1,borderRadius:2}]},
    options:{responsive:true,maintainAspectRatio:false,animation:{duration:200},plugins:{legend:{display:false}},scales:{x:{ticks:{font:fontMono,maxRotation:30}},y:{beginAtZero:true,ticks:{font:fontMono}}}}
  });
}

let chartTick=0;
function updateCharts(){
  chartTick++;
  if(chartTick%4!==0) return; // update charts every 4th UI tick

  // Rate chart
  const rate=state.flowsThisSec;
  state.rateHistory.push(rate);
  if(state.rateHistory.length>40) state.rateHistory.shift();
  rateChart.data.datasets[0].data=[...state.rateHistory];
  rateChart.update('none');

  // Proto pie
  const pe=Object.entries(state.protoFlows).sort((a,b)=>b[1]-a[1]);
  protoPieChart.data.labels=pe.map(e=>e[0]);
  protoPieChart.data.datasets[0].data=pe.map(e=>e[1]);
  protoPieChart.update('none');

  // Asset bar
  const ae=Object.entries(state.assetFlows).sort((a,b)=>b[1]-a[1]).slice(0,8);
  assetChart.data.labels=ae.map(e=>e[0]);
  assetChart.data.datasets[0].data=ae.map(e=>e[1]);
  assetChart.update('none');

  // PubIP bar
  const ppe=Object.entries(state.pubipFlows).sort((a,b)=>b[1].count-a[1].count).slice(0,8);
  pubipChart.data.labels=ppe.map(e=>e[0]);
  pubipChart.data.datasets[0].data=ppe.map(e=>e[1].count);
  pubipChart.update('none');

  // Proto bar
  protoBarChart.data.labels=pe.map(e=>e[0]);
  protoBarChart.data.datasets[0].data=pe.map(e=>e[1]);
  protoBarChart.update('none');
}

/* ================================================================
   SIMULATION LOOP
   ================================================================ */
let uiTick=0;
let lastSecond=Date.now();

function simLoop(){
  if(state.paused){ requestAnimationFrame(simLoop); return; }

  const now=Date.now();
  const dt=now-lastSecond;

  if(dt>=1000){
    // Advance simulated time
    state.elapsed+=state.speed;
    if(state.elapsed>=state.windowSecs){
      state.elapsed=0; // reset window
    }

    // Generate flows: base 8-20 per second, multiplied by speed
    const baseRate=randInt(8,20);
    const numFlows=Math.floor(baseRate*state.speed*0.8);
    for(let i=0;i<numFlows;i++){
      const f=generateFlow();
      ingestFlow(f);
      if(i===0) updateTicker(f); // show latest in ticker
    }

    // Update FPS display
    document.getElementById('h-fps').textContent=numFlows;
    updateAllUI();
    state.flowsThisSec=0;
    lastSecond=now;
  }

  uiTick++;
  requestAnimationFrame(simLoop);
}

/* ================================================================
   TOPOLOGY — hierarchical SVG tree with animated flow pulses
   ================================================================ */

const PROTO_COLORS = {TCP:'#00d4ff', UDP:'#00e676', ICMP:'#ffab00', SIP:'#bb86fc', DNS:'#26c6da', HTTP:'#ff7043', HTTPS:'#00d4ff', SSH:'#ff4444'};

let topoInterval = null;
let topoPulses = []; // {el, startTime, duration, path}
let topoAnimFrame = null;
let topoActive = false;

function renderTopology(){
  topoActive = true;
  const root = document.getElementById('topo-root');
  root.innerHTML = '';

  // Panel 1: GW → Assets
  root.appendChild(buildGWPanel());
  // Panel 2: Assets → Public IPs
  root.appendChild(buildPubPanel());
  // Panel 3: Protocol distribution by asset type
  root.appendChild(buildProtoPanel());

  // Start pulse animation
  startPulseLoop();

  // Refresh every 3s
  if(topoInterval) clearInterval(topoInterval);
  topoInterval = setInterval(()=>{
    if(!document.getElementById('sec-topology').classList.contains('active')){
      topoActive=false; clearInterval(topoInterval); return;
    }
    renderTopology();
  }, 3000);
}

function buildGWPanel(){
  const panel = document.createElement('div');
  panel.className = 'topo-panel';
  panel.innerHTML = '<div class="topo-panel-title">One-to-Many: Gateway → Internal Assets</div>';

  const assets = INTERNAL_ASSETS.filter(a => state.assetFlows[a.ip] > 0);
  if(!assets.length){ panel.innerHTML += '<div style="padding:20px;font-family:var(--mono);font-size:11px;color:var(--text3)">Waiting for flows...</div>'; return panel; }

  const W = Math.max(900, assets.length * 70 + 100);
  const H = 200;
  const GW_Y = 36, ASSET_Y = 120;
  const gwX = W / 2;

  // Group assets by subnet for row layout
  const cols = Math.min(assets.length, Math.ceil(assets.length / 1));
  const spacingX = Math.max(60, (W - 80) / Math.max(cols - 1, 1));

  const svg = makeSVG(W, H);

  // Gateway node
  const gwW = 100, gwH = 24;
  const gwRect = makeRect(gwX - gwW/2, GW_Y - gwH/2, gwW, gwH, '#ffab00', 'rgba(255,171,0,0.15)', 1.5);
  const gwText = makeSVGText(gwX, GW_Y + 4, GATEWAY + ' [GW]', '#ffab00', '9px');
  svg.appendChild(gwRect); svg.appendChild(gwText);

  assets.forEach((a, i) => {
    const ax = 40 + i * spacingX;
    const ay = ASSET_Y;
    const hasNat = !!state.natBypass[a.ip];
    const col = hasNat ? '#ff4444' : (!a.gw ? '#ffab00' : '#00d4ff');
    const bgCol = hasNat ? 'rgba(255,68,68,0.12)' : (!a.gw ? 'rgba(255,171,0,0.1)' : 'rgba(0,212,255,0.08)');

    // Line from GW to asset
    const line = document.createElementNS('http://www.w3.org/2000/svg','line');
    line.setAttribute('x1', gwX); line.setAttribute('y1', GW_Y + gwH/2);
    line.setAttribute('x2', ax); line.setAttribute('y2', ay - 12);
    line.setAttribute('stroke', hasNat ? 'rgba(255,68,68,0.4)' : 'rgba(0,212,255,0.25)');
    line.setAttribute('stroke-width', hasNat ? '1.5' : '1');
    if(hasNat) line.setAttribute('stroke-dasharray','4,3');
    line.setAttribute('data-from-x', gwX); line.setAttribute('data-from-y', GW_Y + gwH/2);
    line.setAttribute('data-to-x', ax); line.setAttribute('data-to-y', ay - 12);
    line.setAttribute('data-color', hasNat ? 'rgba(255,68,68,0.9)' : 'rgba(0,212,255,0.9)');
    line.classList.add('topo-edge');
    svg.appendChild(line);

    // Asset node box
    const nW = 64, nH = 22;
    svg.appendChild(makeRect(ax - nW/2, ay - nH/2, nW, nH, col, bgCol, 1));
    svg.appendChild(makeSVGText(ax, ay - 2, a.ip, col, '8px'));
    svg.appendChild(makeSVGText(ax, ay + 9, a.role.slice(0,10), 'rgba(255,255,255,0.4)', '7px'));

    // Flow count badge
    const flows = state.assetFlows[a.ip] || 0;
    svg.appendChild(makeSVGText(ax, ay + 24, flows.toLocaleString(), 'rgba(0,212,255,0.5)', '7px'));
  });

  const wrap = document.createElement('div');
  wrap.className = 'topo-svg-wrap';
  wrap.style.overflowX = 'auto';
  wrap.appendChild(svg);
  panel.appendChild(wrap);

  // Schedule pulses on these edges
  schedulePulsesOnSVG(svg, 'gw');
  return panel;
}

function buildPubPanel(){
  const panel = document.createElement('div');
  panel.className = 'topo-panel';
  panel.innerHTML = '<div class="topo-panel-title g">One-to-Many: Internal Assets → Public IPs (Sample)</div>';

  const assets = INTERNAL_ASSETS.filter(a => state.assetFlows[a.ip] > 0).slice(0, 8);
  const pubIPs = Object.entries(state.pubipFlows).sort((a,b)=>b[1].count-a[1].count).slice(0, 20);

  if(!assets.length || !pubIPs.length){ panel.innerHTML += '<div style="padding:20px;font-family:var(--mono);font-size:11px;color:var(--text3)">Waiting for flows...</div>'; return panel; }

  const W = Math.max(900, Math.max(assets.length, pubIPs.length) * 72 + 60);
  const H = 220;
  const ASSET_Y = 36, PUB_Y = 160;

  const svg = makeSVG(W, H);

  const aSpacing = Math.max(72, (W - 60) / Math.max(assets.length - 1, 1));
  const pSpacing = Math.max(48, (W - 60) / Math.max(pubIPs.length - 1, 1));

  // Asset nodes (top row)
  const assetXs = {};
  assets.forEach((a, i) => {
    const ax = 30 + i * aSpacing;
    assetXs[a.ip] = ax;
    const hasNat = !!state.natBypass[a.ip];
    const col = hasNat ? '#ff4444' : '#00d4ff';
    const bgCol = hasNat ? 'rgba(255,68,68,0.12)' : 'rgba(0,212,255,0.08)';
    const nW = 66, nH = 22;
    svg.appendChild(makeRect(ax - nW/2, ASSET_Y - nH/2, nW, nH, col, bgCol, 1));
    svg.appendChild(makeSVGText(ax, ASSET_Y - 2, a.ip, col, '8px'));
    svg.appendChild(makeSVGText(ax, ASSET_Y + 9, a.role.slice(0,10), 'rgba(255,255,255,0.35)', '7px'));
  });

  // Public IP nodes (bottom row)
  const pubXs = {};
  pubIPs.forEach(([ip, d], i) => {
    const px = 30 + i * pSpacing;
    pubXs[ip] = px;
    const isHigh = d.risk === 'high';
    const col = isHigh ? '#ff4444' : '#00e676';
    const bgCol = isHigh ? 'rgba(255,68,68,0.1)' : 'rgba(0,230,118,0.08)';
    const nW = 58, nH = 20;
    svg.appendChild(makeRect(px - nW/2, PUB_Y - nH/2, nW, nH, col, bgCol, 1));
    svg.appendChild(makeSVGText(px, PUB_Y - 2, ip, col, '7px'));
    svg.appendChild(makeSVGText(px, PUB_Y + 9, (d.org||'').slice(0,10), 'rgba(255,255,255,0.35)', '6px'));
  });

  // Edges: each asset → subset of pub IPs
  assets.forEach((a, ai) => {
    const ax = assetXs[a.ip];
    const hasNat = !!state.natBypass[a.ip];
    // connect to a deterministic subset based on index
    pubIPs.forEach(([ip, d], pi) => {
      if((ai + pi) % 3 !== 0 && !hasNat) return; // sparse connections for clean look
      const px = pubXs[ip];
      const isHigh = d.risk === 'high';
      const col = (hasNat || isHigh) ? 'rgba(255,68,68,0.3)' : 'rgba(0,230,118,0.2)';
      const pcol = (hasNat || isHigh) ? 'rgba(255,68,68,0.9)' : 'rgba(0,230,118,0.9)';
      const line = document.createElementNS('http://www.w3.org/2000/svg','line');
      line.setAttribute('x1', ax); line.setAttribute('y1', ASSET_Y + 11);
      line.setAttribute('x2', px); line.setAttribute('y2', PUB_Y - 10);
      line.setAttribute('stroke', col); line.setAttribute('stroke-width','1');
      if(hasNat) line.setAttribute('stroke-dasharray','3,3');
      line.setAttribute('data-from-x', ax); line.setAttribute('data-from-y', ASSET_Y + 11);
      line.setAttribute('data-to-x', px); line.setAttribute('data-to-y', PUB_Y - 10);
      line.setAttribute('data-color', pcol);
      line.classList.add('topo-edge');
      svg.appendChild(line);
    });
  });

  const wrap = document.createElement('div');
  wrap.className = 'topo-svg-wrap';
  wrap.style.overflowX = 'auto';
  wrap.appendChild(svg);
  panel.appendChild(wrap);

  schedulePulsesOnSVG(svg, 'pub');
  return panel;
}

function buildProtoPanel(){
  const panel = document.createElement('div');
  panel.className = 'topo-panel';
  panel.innerHTML = '<div class="topo-panel-title p">Protocol Distribution by Asset Type</div>';

  // Group assets by role category
  const groups = [
    {label:'Web Servers', roles:['Web Server'], protos:['TCP','HTTPS','HTTP']},
    {label:'App Servers', roles:['App Server'], protos:['TCP']},
    {label:'DB Servers',  roles:['DB Server','DB (Postgres)','Cache Redis'], protos:['TCP']},
    {label:'DNS/NTP',     roles:['DNS Server','NTP Server'], protos:['UDP','TCP']},
    {label:'VoIP',        roles:['VoIP Gateway','VoIP Phone'], protos:['UDP','SIP']},
    {label:'SMTP',        roles:['SMTP Relay'], protos:['TCP']},
    {label:'Load Bal.',   roles:['Load Balancer','Reverse Proxy'], protos:['TCP']},
    {label:'Firewall',    roles:['Firewall','IDS Sensor'], protos:['TCP','ICMP','UDP']},
  ];

  const protos = ['TCP','UDP','ICMP','SIP'];
  const pColors = {TCP:'#00d4ff', UDP:'#00e676', ICMP:'#ffab00', SIP:'#bb86fc'};

  // Compute flow counts per group per proto
  const maxVal = { val: 1 };
  const data = groups.map(g => {
    const ips = INTERNAL_ASSETS.filter(a => g.roles.some(r => a.role.includes(r))).map(a => a.ip);
    const totalFlows = ips.reduce((s,ip) => s + (state.assetFlows[ip]||0), 0);
    const pData = {};
    protos.forEach(p => {
      // Approximate: assign proto flows proportionally to assets in group
      pData[p] = g.protos.includes(p) ? Math.round(totalFlows * (0.5 + Math.random()*0.3)) : 0;
    });
    const total = Object.values(pData).reduce((s,v)=>s+v,0);
    if(total > maxVal.val) maxVal.val = total;
    return {label: g.label, pData, total};
  });

  // Legend
  const legend = document.createElement('div');
  legend.className = 'topo-legend';
  protos.forEach(p => {
    legend.innerHTML += `<span><i style="background:${pColors[p]}"></i>${p}</span>`;
  });
  panel.appendChild(legend);

  // Build SVG bar chart
  const W = 900, H = 240;
  const BAR_W = 60, GAP = 44, LEFT = 50, BOTTOM = 200, TOP = 20;
  const svg = makeSVG(W, H);
  svg.setAttribute('viewBox', `0 0 ${W} ${H}`);

  // Y axis labels
  const steps = 4;
  for(let s=0;s<=steps;s++){
    const v = Math.round(maxVal.val * s / steps);
    const y = BOTTOM - (BOTTOM - TOP) * s / steps;
    const gl = document.createElementNS('http://www.w3.org/2000/svg','line');
    gl.setAttribute('x1',LEFT); gl.setAttribute('y1',y); gl.setAttribute('x2',W-20); gl.setAttribute('y2',y);
    gl.setAttribute('stroke','rgba(30,48,80,0.6)'); gl.setAttribute('stroke-width','1');
    svg.appendChild(gl);
    svg.appendChild(makeSVGText(LEFT-6, y+3, v >= 1000 ? (v/1000).toFixed(1)+'K' : v, 'rgba(60,90,128,0.8)', '8px', 'end'));
  }

  data.forEach((g, gi) => {
    const x = LEFT + gi * (BAR_W + GAP);
    let stackY = BOTTOM;
    protos.forEach(p => {
      const v = g.pData[p] || 0;
      if(!v) return;
      const barH = Math.max(2, (v / maxVal.val) * (BOTTOM - TOP));
      const rect = document.createElementNS('http://www.w3.org/2000/svg','rect');
      rect.setAttribute('x', x); rect.setAttribute('y', stackY - barH);
      rect.setAttribute('width', BAR_W); rect.setAttribute('height', barH);
      rect.setAttribute('fill', pColors[p]+'99');
      rect.setAttribute('stroke', pColors[p]); rect.setAttribute('stroke-width','0.5');
      // animate
      rect.style.transition = 'height 0.6s ease, y 0.6s ease';
      svg.appendChild(rect);
      stackY -= barH;
    });
    svg.appendChild(makeSVGText(x + BAR_W/2, BOTTOM + 14, g.label.slice(0,8), 'rgba(120,156,192,0.7)', '8px'));
    if(g.total > 0)
      svg.appendChild(makeSVGText(x + BAR_W/2, stackY - 4, g.total.toLocaleString(), 'rgba(0,212,255,0.6)', '8px'));
  });

  const wrap = document.createElement('div');
  wrap.className = 'topo-svg-wrap topo-proto-chart';
  wrap.appendChild(svg);
  panel.appendChild(wrap);
  return panel;
}

// ---- SVG helpers ----
function makeSVG(w, h){
  const svg = document.createElementNS('http://www.w3.org/2000/svg','svg');
  svg.setAttribute('width', w); svg.setAttribute('height', h);
  svg.setAttribute('viewBox', `0 0 ${w} ${h}`);
  svg.style.minWidth = w+'px';
  return svg;
}
function makeRect(x, y, w, h, stroke, fill, sw){
  const r = document.createElementNS('http://www.w3.org/2000/svg','rect');
  r.setAttribute('x',x); r.setAttribute('y',y); r.setAttribute('width',w); r.setAttribute('height',h);
  r.setAttribute('rx','3'); r.setAttribute('fill',fill);
  r.setAttribute('stroke',stroke); r.setAttribute('stroke-width',sw||1);
  return r;
}
function makeSVGText(x, y, txt, fill, size, anchor){
  const t = document.createElementNS('http://www.w3.org/2000/svg','text');
  t.setAttribute('x',x); t.setAttribute('y',y);
  t.setAttribute('fill',fill); t.setAttribute('font-size',size||'9px');
  t.setAttribute('font-family','IBM Plex Mono,monospace');
  t.setAttribute('text-anchor', anchor||'middle');
  t.textContent = txt;
  return t;
}

// ---- Pulse animation ----
function schedulePulsesOnSVG(svg, type){
  const edges = svg.querySelectorAll('.topo-edge');
  edges.forEach(edge => {
    // random stagger
    const delay = Math.random() * 2000;
    setTimeout(()=> addPulseOnEdge(edge, type), delay);
  });
}

function addPulseOnEdge(edge, type){
  if(!topoActive) return;
  const x1=+edge.getAttribute('data-from-x'), y1=+edge.getAttribute('data-from-y');
  const x2=+edge.getAttribute('data-to-x'),   y2=+edge.getAttribute('data-to-y');
  const col = edge.getAttribute('data-color') || 'rgba(0,212,255,0.9)';
  const svg = edge.closest('svg');
  if(!svg) return;

  const circle = document.createElementNS('http://www.w3.org/2000/svg','circle');
  circle.setAttribute('r','3.5');
  circle.setAttribute('fill', col);
  circle.setAttribute('filter','url(#glow)');
  svg.appendChild(circle);

  // Ensure glow filter exists
  if(!svg.querySelector('defs')){
    const defs = document.createElementNS('http://www.w3.org/2000/svg','defs');
    defs.innerHTML = `<filter id="glow" x="-50%" y="-50%" width="200%" height="200%">
      <feGaussianBlur stdDeviation="2.5" result="blur"/>
      <feMerge><feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/></feMerge>
    </filter>`;
    svg.insertBefore(defs, svg.firstChild);
  }

  const duration = 800 + Math.random() * 600;
  const start = performance.now();

  function animatePulse(now){
    if(!topoActive){ circle.remove(); return; }
    if(state.paused){ requestAnimationFrame(animatePulse); return; }
    const t = Math.min(1, (now - start) / duration);
    const x = x1 + (x2 - x1) * t;
    const y = y1 + (y2 - y1) * t;
    circle.setAttribute('cx', x); circle.setAttribute('cy', y);
    circle.setAttribute('opacity', t < 0.1 ? t*10 : t > 0.85 ? (1-t)/0.15 : 1);
    if(t < 1){
      requestAnimationFrame(animatePulse);
    } else {
      circle.remove();
      // repeat
      const repeat_delay = 400 + Math.random() * 1200;
      setTimeout(() => addPulseOnEdge(edge, type), repeat_delay);
    }
  }
  requestAnimationFrame(animatePulse);
}

function startPulseLoop(){
  topoActive = true;
}

/* ---- BOOT ---- */
initCharts();
simLoop();
async function fetchConnections() {
  try {
    const res = await fetch('http://localhost:3000/api/connections');
    const data = await res.json();

    console.log(data);

    // Example UI update
    const el = document.getElementById('conn-count');
    if (el) el.textContent = data.total;

  } catch (err) {
    console.error('Fetch error:', err);
  }
}

// refresh every 2 seconds
setInterval(fetchConnections, 2000);
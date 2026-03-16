#!/usr/bin/env python3
"""Bettercap dashboard proxy — serves dark HTML UI on port 8082,
   proxies /api/* to bettercap REST API on 127.0.0.1:8081."""
import http.server, urllib.request, base64, socket

PORT    = 8082
BC_URL  = 'http://127.0.0.1:8081'
BC_USER = 'user'
BC_PASS = 'pass'
_AUTH   = base64.b64encode(f'{BC_USER}:{BC_PASS}'.encode()).decode()

HTML = b"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>PiBot \u2014 Bettercap</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{background:#0d0d0d;color:#e0e0e0;font-family:monospace;padding:12px}
  h1{color:#00ff88;font-size:1.1em}
  .hdr{display:flex;justify-content:space-between;align-items:center;
       margin-bottom:14px;border-bottom:1px solid #333;padding-bottom:8px}
  .badge{background:#1a1a2e;border:1px solid #00ff88;color:#00ff88;
         padding:2px 8px;border-radius:4px;font-size:.75em}
  .badge.red{border-color:#ff4444;color:#ff4444}
  .timer{color:#555;font-size:.7em}
  .info{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:14px}
  .box{background:#1a1a1a;border:1px solid #333;padding:5px 10px;
       border-radius:4px;font-size:.8em}
  .box span{color:#00ff88}
  .sec{color:#777;font-size:.7em;text-transform:uppercase;letter-spacing:1px;
       margin:12px 0 5px}
  .mods{display:flex;flex-wrap:wrap;gap:6px;margin-bottom:4px}
  .mod{padding:2px 8px;border-radius:3px;font-size:.75em}
  .on{background:#003322;border:1px solid #00aa55;color:#00ff88}
  .off{background:#1a1a1a;border:1px solid #333;color:#444}
  table{width:100%;border-collapse:collapse;font-size:.8em}
  th{background:#1a1a2e;color:#00ff88;padding:6px 8px;text-align:left;
     border-bottom:1px solid #333}
  td{padding:5px 8px;border-bottom:1px solid #1e1e1e}
  tr:hover td{background:#151515}
  .mac{color:#666;font-size:.85em}
  .esp{color:#ff9900}.amz{color:#ff9900}.itl{color:#4da6ff}
  .apl{color:#aaa}.rpi{color:#cc0033}
</style>
</head>
<body>
<div class="hdr">
  <h1>&#x1F6E1;&#xFE0F; PiBot Bettercap</h1>
  <div>
    <span class="badge" id="st">connecting\u2026</span>
    <span class="timer" id="tmr"></span>
  </div>
</div>
<div class="info" id="info"></div>
<div class="sec">Modules</div>
<div class="mods" id="mods"></div>
<div class="sec">Devices &mdash; <span id="cnt">0</span> discovered</div>
<table>
  <thead><tr><th>IP</th><th>Hostname</th><th>Vendor</th><th>MAC</th></tr></thead>
  <tbody id="tb"></tbody>
</table>
<script>
let cd=5;
function vc(v){
  if(!v)return'';v=v.toLowerCase();
  if(v.includes('espressif'))return'esp';
  if(v.includes('amazon'))return'amz';
  if(v.includes('intel'))return'itl';
  if(v.includes('apple'))return'apl';
  if(v.includes('raspberry')||v.includes('pi'))return'rpi';
  return'';
}
async function go(){
  try{
    const r=await fetch('/api/session');
    if(!r.ok)throw r.status;
    const j=await r.json();
    const d=j.data||j;
    document.getElementById('st').textContent='live';
    document.getElementById('st').className='badge';
    const ifc=d.interface||{},gw=d.gateway||{};
    document.getElementById('info').innerHTML=
      `<div class="box">Iface: <span>${ifc.name||'?'}</span></div>`+
      `<div class="box">IP: <span>${ifc.ipv4||'?'}</span></div>`+
      `<div class="box">MAC: <span>${ifc.mac||'?'}</span></div>`+
      `<div class="box">GW: <span>${gw.ipv4||'?'}</span></div>`;
    document.getElementById('mods').innerHTML=
      (d.modules||[]).map(m=>`<span class="mod ${m.running?'on':'off'}">${m.name}</span>`).join('');
    const eps=(d.endpoints||[]).slice().sort((a,b)=>{
      const x=(a.ipv4||'').split('.').map(Number),y=(b.ipv4||'').split('.').map(Number);
      for(let i=0;i<4;i++)if(x[i]!==y[i])return x[i]-y[i];return 0;
    });
    document.getElementById('cnt').textContent=eps.length;
    document.getElementById('tb').innerHTML=eps.map(e=>
      `<tr><td><b>${e.ipv4||'?'}</b></td><td>${e.hostname||''}</td>`+
      `<td class="${vc(e.vendor)}">${e.vendor||''}</td>`+
      `<td class="mac">${e.mac||''}</td></tr>`).join('');
  }catch{
    document.getElementById('st').textContent='offline';
    document.getElementById('st').className='badge red';
  }
}
function tick(){cd--;document.getElementById('tmr').textContent=` \u00b7 ${cd}s`;if(cd<=0){cd=5;go();}}
go();setInterval(tick,1000);
</script>
</body>
</html>"""

class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def do_GET(self):
        if self.path.startswith('/api/'):
            req = urllib.request.Request(BC_URL + self.path)
            req.add_header('Authorization', f'Basic {_AUTH}')
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = resp.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Access-Control-Allow-Origin', '*')
                self.end_headers()
                self.wfile.write(data)
            except Exception as e:
                self.send_response(502)
                self.end_headers()
                self.wfile.write(str(e).encode())
        else:
            self.send_response(200)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(HTML)))
            self.end_headers()
            self.wfile.write(HTML)

if __name__ == '__main__':
    try:
        ip = socket.gethostbyname(socket.gethostname())
    except Exception:
        ip = '0.0.0.0'
    print(f'[dashboard] http://{ip}:{PORT}')
    http.server.HTTPServer(('0.0.0.0', PORT), Handler).serve_forever()

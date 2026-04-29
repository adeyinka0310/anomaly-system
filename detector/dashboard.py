import json, logging, time
import aiohttp.web
import psutil

log = logging.getLogger('hng.dashboard')

HTML = open('/home/ubuntu/hng-anomaly-system/detector/dashboard.html').read() if False else """<!DOCTYPE html>
<html lang=en><head><meta charset=UTF-8><meta name=viewport content="width=device-width,initial-scale=1">
<title>HNG Anomaly Detector</title>
<style>
:root{--bg:#0a0c10;--surface:#111520;--border:#1e2535;--accent:#00e5ff;--danger:#ff3d71;--warn:#ffaa00;--ok:#00e096;--muted:#4a5568;--text:#e2e8f0}
*{box-sizing:border-box;margin:0;padding:0}body{background:var(--bg);color:var(--text);font-family:system-ui,sans-serif}
header{display:flex;align-items:center;justify-content:space-between;padding:.9rem 2rem;border-bottom:1px solid var(--border);background:rgba(17,21,32,.97);position:sticky;top:0;z-index:10}
.logo{font-size:1rem;font-weight:700}.logo span{color:var(--accent)}
.pill{display:flex;align-items:center;gap:.4rem;font-size:.7rem;color:var(--ok);background:rgba(0,224,150,.08);border:1px solid rgba(0,224,150,.2);border-radius:99px;padding:.3rem .8rem}
.dot{width:7px;height:7px;background:var(--ok);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
main{max-width:1300px;margin:0 auto;padding:1.5rem 2rem;display:grid;grid-template-columns:repeat(auto-fit,minmax(270px,1fr));gap:1rem}
.card{background:var(--surface);border:1px solid var(--border);border-radius:12px;padding:1.2rem}
.card.wide{grid-column:span 2}
.label{font-size:.62rem;letter-spacing:.1em;text-transform:uppercase;color:var(--muted);margin-bottom:.6rem}
.num{font-size:2.6rem;font-weight:800;line-height:1;font-family:monospace}
.num.danger{color:var(--danger)}.num.ok{color:var(--ok)}.num.accent{color:var(--accent)}
.sub{font-size:.68rem;color:var(--muted);margin-top:.25rem}
.chips{display:flex;gap:.4rem;margin-top:.7rem;flex-wrap:wrap}
.chip{font-size:.62rem;background:rgba(255,255,255,.04);border:1px solid var(--border);border-radius:5px;padding:.2rem .5rem;color:var(--muted)}
.chip b{color:var(--text)}.bar{margin-top:.7rem;height:4px;background:var(--border);border-radius:99px;overflow:hidden}
.fill{height:100%;border-radius:99px;transition:width .5s;background:var(--accent)}
.fill.danger{background:var(--danger)}.fill.warn{background:var(--warn)}.fill.ok{background:var(--ok)}
.bans{list-style:none;display:flex;flex-direction:column;gap:.45rem;margin-top:.5rem;max-height:240px;overflow-y:auto}
.ban{display:flex;align-items:center;justify-content:space-between;background:rgba(255,61,113,.07);border:1px solid rgba(255,61,113,.2);border-radius:7px;padding:.45rem .7rem;font-size:.7rem;font-family:monospace}
.ban-ip{color:var(--danger);font-weight:700}.ban-meta{color:var(--muted);font-size:.62rem}
.badge{background:rgba(255,61,113,.2);color:var(--danger);border-radius:4px;padding:.1rem .35rem;font-size:.62rem}
.empty{font-size:.72rem;color:var(--muted);text-align:center;padding:1.2rem 0}
table{width:100%;border-collapse:collapse;font-family:monospace;font-size:.7rem;margin-top:.5rem}
th{text-align:left;color:var(--muted);font-size:.6rem;letter-spacing:.08em;text-transform:uppercase;padding:.35rem .5rem;border-bottom:1px solid var(--border)}
td{padding:.4rem .5rem;border-bottom:1px solid rgba(255,255,255,.025)}
.uptime{font-family:monospace;font-size:1.2rem;font-weight:700;color:var(--accent);margin-top:.3rem}
footer{text-align:center;padding:1.2rem;font-size:.62rem;color:var(--muted);border-top:1px solid var(--border)}
</style></head><body>
<header><div class=logo>HNG <span>Anomaly</span> Detector</div>
<div class=pill><div class=dot></div><span id=st>LIVE</span></div></header>
<main>
<div class=card><div class=label>Banned IPs</div><div class="num danger" id=bc>0</div>
<div class=sub>active blocks</div><ul class=bans id=bl><li class=empty>No active bans</li></ul></div>
<div class=card><div class=label>Global Traffic</div><div class="num accent" id=gr>0.00</div>
<div class=sub>req/sec (60s window)</div>
<div class=chips><div class=chip>mean <b id=gm>-</b></div><div class=chip>stddev <b id=gs>-</b></div><div class=chip>z-score <b id=gz>-</b></div></div>
<div class=bar><div class=fill id=gg style="width:0%"></div></div></div>
<div class=card><div class=label>System Resources</div><div class="num ok" id=cp>0%</div>
<div class=sub>CPU usage</div><div class=bar><div class="fill ok" id=cg style="width:0%"></div></div>
<div style="margin-top:.9rem"><div class=label style="margin-bottom:.25rem">Memory</div>
<div class=uptime id=mp>0%</div><div class=bar style="margin-top:.35rem"><div class="fill warn" id=mg style="width:0%"></div></div></div></div>
<div class=card><div class=label>Uptime</div><div class=uptime id=up>0s</div>
<div style="margin-top:.9rem"><div class=label style="margin-bottom:.2rem">Last Baseline Recalc</div>
<div class=uptime id=lr style="font-size:.9rem;color:var(--muted)">-</div></div>
<div style="margin-top:.9rem"><div class=label style="margin-bottom:.2rem">Effective Mean / Stddev</div>
<div style="font-family:monospace;font-size:.85rem;color:var(--accent)" id=bd>-/-</div></div></div>
<div class="card wide"><div class=label>Top 10 Source IPs (last 60s)</div>
<table><thead><tr><th>#</th><th>IP</th><th>Requests</th><th>Bar</th><th>Status</th></tr></thead>
<tbody id=tb><tr><td colspan=5 style="text-align:center;color:var(--muted);padding:1rem">Waiting...</td></tr></tbody></table></div>
</main>
<footer>Refreshing every 3s | HNG cloud.ng | <span id=ft></span></footer>
<script>
const f2=n=>typeof n==='number'?n.toFixed(2):'-';
function uptime(s){const h=Math.floor(s/3600),m=Math.floor((s%3600)/60),sc=Math.floor(s%60);return h?h+'h '+m+'m '+sc+'s':m?m+'m '+sc+'s':sc+'s'}
function ago(ts){if(!ts)return'-';const d=Math.round(Date.now()/1000-ts);return d<60?d+'s ago':Math.round(d/60)+'m ago'}
async function refresh(){
try{
const d=await(await fetch('/api/stats')).json();
document.getElementById('bc').textContent=d.banned_count||0;
const bl=document.getElementById('bl');
bl.innerHTML=d.banned_ips&&d.banned_ips.length?d.banned_ips.map(b=>'<li class=ban><span class=ban-ip>'+b.ip+'</span><span class=ban-meta>'+(b.condition||'').slice(0,30)+'</span><span class=badge>'+(b.permanent?'PERM':b.remaining_str)+'</span></li>').join(''):'<li class=empty>No active bans</li>';
const gr=d.global_rate||0,mean=d.baseline_mean||1;
document.getElementById('gr').textContent=f2(gr);
document.getElementById('gm').textContent=f2(d.baseline_mean);
document.getElementById('gs').textContent=f2(d.baseline_stddev);
document.getElementById('gz').textContent=f2(d.global_zscore);
const pct=Math.min(100,(gr/(mean*6))*100),gg=document.getElementById('gg');
gg.style.width=pct+'%';gg.className='fill'+(pct>80?' danger':pct>50?' warn':'');
document.getElementById('cp').textContent=(d.cpu_pct||0).toFixed(1)+'%';
document.getElementById('cg').style.width=(d.cpu_pct||0)+'%';
document.getElementById('mp').textContent=(d.mem_pct||0).toFixed(1)+'%';
document.getElementById('mg').style.width=(d.mem_pct||0)+'%';
document.getElementById('up').textContent=uptime(d.uptime_seconds||0);
document.getElementById('lr').textContent=ago(d.last_recalc);
document.getElementById('bd').textContent=f2(d.baseline_mean)+' / '+f2(d.baseline_stddev);
const tb=document.getElementById('tb'),mx=(d.top_ips&&d.top_ips[0])?d.top_ips[0][1]:1;
tb.innerHTML=d.top_ips&&d.top_ips.length?d.top_ips.map(function(item,i){
const ip=item[0],c=item[1],bp=Math.round(c/mx*100),banned=d.banned_ips&&d.banned_ips.some(function(b){return b.ip===ip});
return '<tr><td style="color:var(--muted)">#'+(i+1)+'</td><td style="color:'+(banned?'var(--danger)':'var(--text)')+'">'+ip+'</td><td>'+c+'</td><td><div style="width:'+bp+'px;height:4px;background:var(--accent);opacity:.6;border-radius:2px"></div></td><td style="color:'+(banned?'var(--danger)':'var(--ok)')+'"> '+(banned?'BLOCKED':'NORMAL')+'</td></tr>';
}).join(''):'<tr><td colspan=5 style="text-align:center;color:var(--muted)">No traffic yet</td></tr>';
document.getElementById('ft').textContent=new Date().toUTCString();
document.getElementById('st').textContent='LIVE';
}catch(e){document.getElementById('st').textContent='RECONNECTING...'}
}
refresh();setInterval(refresh,3000);
</script></body></html>"""

class Dashboard:
    def __init__(self, cfg, baseline, blocker, unbanner, start_time):
        self._host = cfg['dashboard']['host']
        self._port = cfg['dashboard']['port']
        self._baseline = baseline
        self._blocker = blocker
        self._start_time = start_time
        self._monitor = None

    def set_monitor(self, monitor): self._monitor = monitor

    async def _index(self, req):
        return aiohttp.web.Response(text=HTML, content_type='text/html')

    async def _stats(self, req):
        bans = self._blocker.get_bans()
        now = time.time()
        banned_list = []
        for ip, r in bans.items():
            rem = r.time_remaining()
            if rem is not None:
                h,m,s = int(rem//3600),int((rem%3600)//60),int(rem%60)
                rs = (str(h)+'h '+str(m)+'m '+str(s)+'s') if h else (str(m)+'m '+str(s)+'s')
            else:
                rs = 'permanent'
            banned_list.append({'ip':ip,'condition':r.condition,
                                'remaining_str':rs,'permanent':r.is_permanent()})
        top_ips = self._monitor.get_top_ips(10) if self._monitor else []
        global_rate = self._monitor.get_global_rate() if self._monitor else 0.0
        return aiohttp.web.Response(
            text=json.dumps({
                'banned_count': len(bans),
                'banned_ips': banned_list,
                'global_rate': round(global_rate,3),
                'global_zscore': round(self._baseline.zscore(global_rate),3),
                'top_ips': top_ips,
                'cpu_pct': round(psutil.cpu_percent(interval=None),1),
                'mem_pct': round(psutil.virtual_memory().percent,1),
                'baseline_mean': round(self._baseline.effective_mean,3),
                'baseline_stddev': round(self._baseline.effective_stddev,3),
                'last_recalc': self._baseline.last_recalc or None,
                'uptime_seconds': round(now-self._start_time,1),
            }),
            content_type='application/json',
            headers={'Access-Control-Allow-Origin':'*'})

    async def run(self):
        app = aiohttp.web.Application()
        app.router.add_get('/', self._index)
        app.router.add_get('/api/stats', self._stats)
        runner = aiohttp.web.AppRunner(app)
        await runner.setup()
        await aiohttp.web.TCPSite(runner, self._host, self._port).start()
        log.info('Dashboard live at http://%s:%d/', self._host, self._port)
        while True:
            await asyncio.sleep(3600)

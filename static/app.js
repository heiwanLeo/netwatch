'use strict';
const $ = id => document.getElementById(id);
let state = null, token = '', pollTimer, toastTimer, busy = new Set(), lastNodeHTML = '';
const esc = value => String(value ?? '').replace(/[&<>"']/g, ch => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[ch]));
const finite = value => typeof value === 'number' && Number.isFinite(value);
const number = value => finite(value) ? (value < 100 ? value.toFixed(1) : Math.round(value).toLocaleString('zh-CN')) : '—';
const clock = ts => ts ? new Date(ts * 1000).toLocaleTimeString('zh-CN', {hour12:false}) : '—';
function relative(ts) {
  if (!ts) return '未检测';
  const age = Math.max(0, Math.floor(Date.now() / 1000 - ts));
  return age < 5 ? '刚刚' : age < 60 ? `${age} 秒前` : `${Math.floor(age / 60)} 分钟前`;
}
function toast(message, error = false) {
  $('toast').textContent = message; $('toast').className = 'toast' + (error ? ' error' : ''); $('toast').hidden = false;
  clearTimeout(toastTimer); toastTimer = setTimeout(() => $('toast').hidden = true, 5000);
}
async function api(path, data) {
  const response = await fetch(path, {method:'POST', headers:{'Content-Type':'application/json', 'X-Netwatch-Token':token}, body:JSON.stringify(data ?? {})});
  const result = await response.json();
  if (!response.ok) throw new Error(result.error || '操作失败，请重试。');
  return result;
}
async function action(key, path, data) {
  if (busy.has(key)) return;
  busy.add(key); renderButtons();
  try { const result = await api(path, data); toast(result.message); await refresh(); }
  catch (e) { toast(e.message, true); await refresh(); }
  finally { busy.delete(key); renderButtons(); }
}
function status(id, text, color) { $(id).textContent = text; $(id).className = 'tag ' + color; }
function setInput(id, value) { if (document.activeElement !== $(id) && !busy.has('settings')) $(id).value = value; }
function banner(message) { $('banner').hidden = !message; $('banner').textContent = message || ''; }
function fresh(node) { return node?.checked_at && Date.now()/1000 - node.checked_at < 180 && node.url === state.settings.probe_url; }
function renderButtons() {
  const connected = !!state?.connected;
  const scanning = !!state?.scan.running;
  $('scan').disabled = !connected || scanning || busy.has('scan');
  $('scan').textContent = scanning ? `◎ 测速中 ${state.scan.done}/${state.scan.total}` : '◎ 测全部节点';
  $('fastest').disabled = !connected || busy.has('switch') || !state?.nodes.some(n => finite(n.delay) && fresh(n));
  $('fastest').textContent = busy.has('switch') ? '正在复测与切换…' : '↗ 切换到最快节点';
  $('auto').disabled = !connected || busy.has('settings');
  $('group').disabled = scanning || busy.has('settings');
  $('probe-url').disabled = scanning || busy.has('settings');
  document.querySelectorAll('.node-button').forEach(b => b.disabled = busy.has('switch') || !connected || b.dataset.node === state?.active);
}
function render() {
  if (!state) return;
  const s = state, net = s.network, direct = net.direct || [], gateway = net.gateway || {};
  const base = direct[0];
  renderQuality('base-quality',s.quality?.direct); renderQuality('vpn-quality',s.quality?.vpn); renderWifi();
  const active = s.nodes.find(n => n.name === s.active);
  const stale = s.last_sample && Date.now()/1000 - s.last_sample > 75;
  $('network-name').textContent = s.identity?.label || '未识别当前网络';
  $('network-id-note').textContent = s.identity ? (s.identity.ssid ? s.identity.interface : '按网关识别 · ' + s.identity.interface) : '';
  setInput('network-label', s.identity?.label || '');
  $('connection').textContent = s.connected ? 'Clash 已连接' : 'Clash 未连接';
  $('connection').className = 'pill ' + (s.connected ? 'good' : 'bad');
  document.body.classList.toggle('offline', !!stale);
  const modeProblem = s.mode === 'direct' ? 'Clash 当前为直连模式，节点切换不会改变流量出口。请在 Clash 中选择规则或全局模式。'
    : s.mode === 'global' && s.settings.group !== 'GLOBAL' ? '当前为全局模式，请选择 GLOBAL 节点组来切换实际出口。'
    : s.mode === 'rule' && s.settings.group === 'GLOBAL' ? '当前为规则模式，请选择实际使用的节点组。' : '';
  banner(s.error || net.error || modeProblem || (stale ? '检测记录尚未更新，显示的是上一次结果。' : ''));
  const baseOK = finite(base?.delay);
  $('base-delay').textContent = number(base?.delay);
  $('base-detail').textContent = baseOK ? `国内直连 · ${base.target} · TCP 握手` : s.last_sample ? '国内检测目标未响应，请查看直连检测详情' : '正在检测物理网卡上的直连连接';
  status('base-status', baseOK ? (base.delay > 100 ? '延迟偏高' : '直连可达') : s.last_sample ? '未响应' : '检测中', baseOK ? (base.delay > 100 ? 'warn' : 'good') : s.last_sample ? 'bad' : '');
  $('gateway-delay').textContent = `${number(gateway.delay)} ms`;
  $('gateway-loss').textContent = finite(gateway.loss) ? `${gateway.loss}%` : '—';
  $('interface').textContent = net.interface || '—';
  $('direct-details').innerHTML = direct.map(d => `<div>${esc(d.target)} · ${finite(d.delay) ? number(d.delay)+' ms' : '未响应'} · 失败 ${d.failures}/${d.samples}<br>${esc(d.interface)} · ${esc(d.source || '暂无源地址')} · 已绑定物理网卡</div>`).join('');
  $('vpn-delay').textContent = number(active?.delay);
  $('active-node').textContent = s.active || (s.connected ? '请选择节点组' : '等待 Clash 启动');
  $('active-node').title = s.active || '';
  $('active-group').textContent = s.settings.group || '—';
  $('vpn-time').textContent = relative(active?.checked_at);
  const vpnFresh = fresh(active);
  status('vpn-status', active?.checked_at ? !vpnFresh ? '结果已过期' : !finite(active.delay) ? '探测超时' : s.quality?.vpn.score === null ? '学习中' : s.quality?.vpn.score < s.settings.vpn_score_threshold ? '评分偏低' : '连接可用' : '等待检测', active?.checked_at ? !vpnFresh ? '' : !finite(active.delay) ? 'bad' : active.delay > s.settings.threshold ? 'warn' : 'good' : '');
  if (!busy.has('settings')) $('auto').checked = s.settings.auto;
  $('auto-title').textContent = s.settings.auto ? '慢了，就换一条路。' : '把选择交给自己';
  $('auto-description').textContent = s.settings.auto ? `当前节点评分连续两轮低于 ${s.settings.vpn_score_threshold} 分时，寻找更好的节点；切换至少间隔 ${s.settings.cooldown} 秒。` : '按成功率、均值、波动与 P95 综合评分。低于你设定的分数时寻找更好的节点。';
  const remaining = Math.max(0, Math.ceil(s.settings.cooldown - (Date.now()/1000 - s.last_switch)));
  $('auto-note').textContent = s.settings.auto && remaining ? `切换冷却中，还剩 ${remaining} 秒` : '候选节点复测通过才会切换';
  setInput('threshold', s.settings.vpn_score_threshold); setInput('interval', s.settings.interval); setInput('cooldown', s.settings.cooldown); setInput('probe-url', s.settings.probe_url);
  const options = s.groups.map(g => `<option value="${esc(g.name)}">${esc(g.name)} · ${g.count} 个节点</option>`).join('');
  if ($('group').innerHTML !== options && document.activeElement !== $('group')) $('group').innerHTML = options;
  setInput('group', s.settings.group);
  $('nodes-count').textContent = s.nodes.length;
  $('scan-progress').hidden = !s.scan.running;
  $('scan-count').textContent = `${s.scan.done} / ${s.scan.total}`;
  $('progress').value = s.scan.done; $('progress').max = s.scan.total || 1;
  $('scan-description').textContent = s.scan.running ? '测速结果陆续更新；保持当前出口，完成后可选择更快节点。' : '统一检测地址，按实际延迟从低到高排序。';
  $('last-update').textContent = s.last_sample ? '最近更新 ' + clock(s.last_sample) : '等待首轮检测';
  $('history-note').textContent = s.history.length ? `当前网络最近 ${s.history.length} 次真实检测 · 缺失数据保留空白` : '正在积累真实检测记录';
  $('chart-empty').hidden = s.history.some(p => finite(p.direct) || finite(p.gateway) || finite(p.vpn));
  $('events').innerHTML = s.events.length ? s.events.map(e => `<div class="event ${e.kind === 'switch' ? 'switch-event' : ''}"><span class="event-time">${clock(e.ts)}</span><span class="event-message">${esc(e.message)}</span></div>`).join('') : '<p class="empty-text">还没有活动记录。</p>';
  renderStatistics('base-stats', s.statistics?.direct); renderStatistics('vpn-stats', s.statistics?.vpn);
  renderNodes(); renderButtons(); drawChart();
}
function renderQuality(id,q) {
  if(!q)return;
  const score=q.score, color=score===null?'':score>=80?'good':score>=65?'warn':'bad';
  $(id).innerHTML=`<div class="quality-summary"><span>质量评分</span><strong class="${color}">${score===null?'学习中':score+' <small>/ 100</small>'}</strong><span>${q.samples} 次样本</span></div><details class="score-details"><summary>评分依据</summary><div class="score-parts">${q.parts.map(p=>`<div><span>${esc(p.name)} · ${p.weight}%</span><b>${p.score} 分</b></div>`).join('')}</div><p>越高越好，至少 ${q.minimum} 次探测后评分；这是本工具的质量指标。</p></details>`;
}
function renderWifi(){
  const w=state.wifi;if(!w)return;
  const authorized=w.authorized;
  $('wifi-authorize').textContent=authorized?'Wi-Fi 读取已允许':'允许 Wi-Fi 读取';
  $('wifi-authorize').disabled=authorized||w.busy||busy.has('wifi');
  $('wifi-scan').disabled=!authorized||w.busy||busy.has('wifi');
  $('wifi-auto').disabled=!authorized||busy.has('settings');
  if(!busy.has('settings'))$('wifi-auto').checked=state.settings.wifi_auto;
  setInput('wifi-score-threshold',state.settings.wifi_score_threshold);setInput('wifi-cooldown',state.settings.wifi_cooldown);setInput('learn-minutes',state.settings.learn_minutes);
  $('wifi-permission-note').textContent=w.busy?w.message:authorized?w.message:'macOS 需要允许 Netwatch Wi-Fi 的定位权限，才能读取 Wi-Fi 名称和扫描结果。程序不请求地理坐标。允许前，网关监控与 VPN 功能仍可使用。';
  $('wifi-profiles').innerHTML=w.profiles.map(p=>`<div class="wifi-profile"><div class="wifi-profile-top"><strong>${esc(p.ssid)}</strong><span class="tag ${p.quality.score===null?'':p.quality.score>=80?'good':p.quality.score>=65?'warn':'bad'}">${p.quality.score===null?'学习中':p.quality.score+' 分'}</span></div><p>${p.current?'当前连接':p.visible?'附近可见':'暂未发现'} · ${Math.floor(p.seconds/60)} 分钟已观察连接 · ${p.quality.samples} 次近期探测${p.rssi?' · '+p.rssi+' dBm':''}</p><div class="wifi-profile-bottom"><label><input type="checkbox" data-trust="${esc(p.ssid)}" ${p.trusted?'checked':''}> ${p.origin==='learned'?'习惯已学习 · 自动候选':'允许作为候选'}</label><button class="node-button" data-wifi="${esc(p.ssid)}" ${!authorized||w.busy||!p.trusted||p.current?'disabled':''}>${p.current?'当前连接':'连接并验证'}</button></div></div>`).join('');
}
function renderStatistics(id, s) {
  s = s || {};
  const values = [
    ['平均值', number(s.mean) + ' ms', '成功探测耗时的算术平均值；超时单独计入失败率'],
    ['波动 · 标准差', number(s.stddev) + ' ms', '数值越大，成功探测的延迟越不稳定'],
    ['P95', number(s.p95) + ' ms', '95% 的成功探测不超过此值；不足 20 个成功样本时仅供参考'],
    ['最低 / 最高', number(s.min) + ' / ' + number(s.max), '近 15 分钟成功探测的最低 / 最高耗时，单位毫秒'],
    ['失败率', finite(s.failure_rate) ? s.failure_rate + '%' : '—', '失败次数除以总尝试次数；超时不会作为零毫秒参与延迟统计'],
    ['成功 / 尝试', `${s.successes || 0} / ${s.attempts || 0}`, '样本越多，统计越有参考价值；未连接 Clash 的时段不计入节点失败率']
  ];
  $(id).innerHTML = values.map(([label,value,hint]) => `<div title="${esc(hint)}"><span>${label}</span><strong>${value}</strong></div>`).join('');
}
function renderNodes() {
  if (!state) return;
  const query = $('search').value.toLowerCase();
  const sorted = [...state.nodes].sort((a,b) => {
    const av = finite(a.delay) && fresh(a) ? a.delay : Infinity, bv = finite(b.delay) && fresh(b) ? b.delay : Infinity;
    return av - bv || a.name.localeCompare(b.name, 'zh-CN');
  });
  const visible = sorted.filter(n => n.name.toLowerCase().includes(query));
  const valid = sorted.filter(n => finite(n.delay) && fresh(n));
  const timeouts = sorted.filter(n => n.checked_at && !finite(n.delay) && fresh(n)).length;
  $('node-summary').textContent = `${valid.length} 个可达 · ${timeouts} 个检测超时 · ${state.nodes.length - valid.length - timeouts} 个待测或已过期`;
  const html = visible.map(n => {
    const current = n.name === state.active;
    const measured = !!n.checked_at, stale = measured && !fresh(n);
    const color = !measured ? '' : !finite(n.delay) ? 'bad' : n.delay > state.settings.threshold ? 'warn' : '';
    const label = measured ? finite(n.delay) ? `${number(n.delay)} ms` : '超时' : '未测速';
    return `<div class="node-row ${current ? 'is-active' : ''}"><div class="node-title"><span title="${esc(n.name)}">${esc(n.name)}</span>${current ? '<span class="current-badge">当前使用</span>' : ''}</div><span class="protocol">${esc(n.type)}</span><div class="node-latency ${color} ${stale ? 'stale' : ''}" title="${esc(measured ? clock(n.checked_at) + (stale ? ' · 已过期，请复测' : '') : '等待测速')}">${finite(n.delay) ? `<meter class="latency-bar" min="0" max="${state.settings.threshold}" value="${Math.min(state.settings.threshold, n.delay)}"></meter>` : ''}<span>${label}${stale ? ' *' : ''}</span></div><button class="node-button" data-node="${esc(n.name)}" ${current || busy.has('switch') ? 'disabled' : ''}>${current ? '使用中' : '切换'}</button></div>`;
  }).join('') || `<div class="empty-state">${query ? '没有匹配的节点。' : state.connected ? '此节点组没有可直接选择的节点，请更换节点组。' : '等待 Clash 连接后读取节点。'}</div>`;
  if (html !== lastNodeHTML) { $('node-list').innerHTML = html; lastNodeHTML = html; }
}
function drawChart() {
  const canvas = $('chart'), ctx = canvas.getContext('2d'), box = canvas.getBoundingClientRect();
  if (!box.width) return;
  const dpr = window.devicePixelRatio || 1;
  canvas.width = Math.round(box.width*dpr); canvas.height = Math.round(box.height*dpr); ctx.scale(dpr,dpr);
  const w=box.width, h=box.height, left=40, right=12, top=10, bottom=25;
  const pts = state?.history || [], plotW=w-left-right, plotH=h-top-bottom;
  const max = Math.max(100, ...pts.flatMap(p => [p.direct,p.vpn,p.gateway].filter(finite)));
  const ceiling = Math.ceil(max/100)*100;
  ctx.font='9px -apple-system, sans-serif'; ctx.fillStyle='#a8b09e'; ctx.textBaseline='middle';
  for(let i=0;i<=3;i++) {
    const y=top+plotH*i/3; ctx.strokeStyle='#eef1e8'; ctx.setLineDash([3,4]); ctx.beginPath();ctx.moveTo(left,y);ctx.lineTo(w-right,y);ctx.stroke();
    ctx.fillText(Math.round(ceiling*(1-i/3))+'',2,y);
  }
  ctx.setLineDash([]);
  if (!pts.length) return;
  const first=pts[0].ts, last=pts[pts.length-1].ts;
  const x = ts => left + (last === first ? .5 : (ts-first)/(last-first))*plotW;
  const y = ms => top+plotH*(1-ms/ceiling);
  for(const [key,color] of [['gateway','#bbc6b0'],['direct','#709d77'],['vpn','#a997d4']]) {
    ctx.strokeStyle=color;ctx.lineWidth=1.8;ctx.lineJoin='round';ctx.lineCap='round';ctx.beginPath();let connected=false;
    for(const p of pts) { if(!finite(p[key])){connected=false;continue;} if(connected)ctx.lineTo(x(p.ts),y(p[key]));else ctx.moveTo(x(p.ts),y(p[key]));connected=true; }
    ctx.stroke();ctx.fillStyle=color;
    for(const p of pts)if(finite(p[key])){ctx.beginPath();ctx.arc(x(p.ts),y(p[key]),pts.length<15?2.7:1.4,0,Math.PI*2);ctx.fill();}
  }
  ctx.fillStyle='#a8b09e';ctx.textAlign='left';ctx.fillText(clock(first).slice(0,5),left,h-6);
  ctx.textAlign='right';ctx.fillText(clock(last).slice(0,5),w-right,h-6);ctx.textAlign='left';
}
async function refresh() {
  try {
    const response = await fetch('/api/state', {cache:'no-store'});
    if (!response.ok) throw new Error('本机服务返回错误');
    state = await response.json(); token = state.token; document.body.classList.remove('offline');render();
  } catch(e) {
    $('connection').textContent='本机服务未连接';$('connection').className='pill bad';document.body.classList.add('offline');
    banner('本机服务暂时无法连接。若已停止，请双击项目中的“启动 Netwatch.command”。');
  }
}
async function poll() { await refresh(); pollTimer = setTimeout(poll, 2000); }
$('refresh').addEventListener('click', () => action('refresh','/api/refresh'));
$('scan').addEventListener('click', () => action('scan','/api/scan'));
$('fastest').addEventListener('click', () => action('switch','/api/switch'));
$('node-list').addEventListener('click', e => { const b=e.target.closest('[data-node]');if(b && !b.disabled)action('switch','/api/switch',{name:b.dataset.node}); });
$('auto').addEventListener('change', () => action('settings','/api/settings',{auto:$('auto').checked}));
$('threshold-form').addEventListener('submit', e => { e.preventDefault();action('settings','/api/settings',{vpn_score_threshold:Number($('threshold').value)}); });
$('group').addEventListener('change', () => action('settings','/api/settings',{group:$('group').value}));
$('settings-form').addEventListener('submit', e => { e.preventDefault();action('settings','/api/settings',{interval:Number($('interval').value),cooldown:Number($('cooldown').value),probe_url:$('probe-url').value}); });
$('search').addEventListener('input', renderNodes);
$('wifi-authorize').addEventListener('click',()=>action('wifi','/api/wifi/authorize'));
$('wifi-scan').addEventListener('click',()=>action('wifi','/api/wifi/scan'));
$('wifi-auto').addEventListener('change',()=>action('settings','/api/settings',{wifi_auto:$('wifi-auto').checked}));
$('wifi-settings-form').addEventListener('submit',e=>{e.preventDefault();action('settings','/api/settings',{wifi_score_threshold:Number($('wifi-score-threshold').value),learn_minutes:Number($('learn-minutes').value),wifi_cooldown:Number($('wifi-cooldown').value)});});
$('wifi-profiles').addEventListener('click',e=>{const b=e.target.closest('[data-wifi]');if(b&&!b.disabled)action('wifi','/api/wifi/switch',{ssid:b.dataset.wifi});});
$('wifi-profiles').addEventListener('change',e=>{const b=e.target.closest('[data-trust]');if(b)action('wifi','/api/wifi/trust',{ssid:b.dataset.trust,trusted:b.checked});});
$('network-form').addEventListener('submit', e => { e.preventDefault(); action('network','/api/network-name',{label:$('network-label').value}); });
new ResizeObserver(drawChart).observe($('chart'));
poll();

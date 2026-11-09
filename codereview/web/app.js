/* SAST Triage web app. Talks only to the local server (/api/...), with this session's token in every request.
   Security rule for this file: code, file names, scanner and AI text are untrusted, so they are only ever put
   on the page with textContent (the el() and sv() helpers below), never with innerHTML. */
'use strict';

/* ---------------- session token ---------------- */
let TOKEN = '';
(function readToken(){
  const m = location.hash.match(/^#t=([A-Za-z0-9_-]+)$/);
  if (m) { TOKEN = m[1]; try { localStorage.setItem('token', TOKEN); } catch(e) {} history.replaceState(null, '', location.pathname + '#dashboard'); }
  else { try { TOKEN = localStorage.getItem('token') || ''; } catch(e) {} }
})();

async function api(path, opts={}){
  const headers = Object.assign({'X-Token': TOKEN}, opts.body ? {'Content-Type':'application/json'} : {});
  const r = await fetch(path, {method: opts.method || 'GET', headers, body: opts.body ? JSON.stringify(opts.body) : undefined});
  if (r.status === 401) { noToken(); throw new Error('no token'); }
  if (!r.ok) { let msg = 'Something went wrong (' + r.status + ')'; try { const j = await r.json(); if (j.detail) msg = typeof j.detail === 'string' ? j.detail : 'The request was not valid.'; } catch(e) {} throw new Error(msg); }
  return opts.raw ? r : r.json();
}
async function download(path){
  try { const r = await api(path, {raw:true}); const blob = await r.blob();
    const name = (r.headers.get('Content-Disposition') || '').match(/filename="([^"]+)"/)?.[1] || 'download';
    const a = el('a', {href: URL.createObjectURL(blob), download: name}); document.body.append(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(a.href), 4000);
  } catch(e) { if (e.message !== 'no token') toastMsg(e.message); }
}

/* ---------------- small DOM helpers (text only, never HTML) ---------------- */
const $ = (s, r=document) => r.querySelector(s);
function el(t, a={}, ...k){ const e=document.createElement(t);
  for(const [x,v] of Object.entries(a)){ if(x==='class') e.className=v; else if(x==='text') e.textContent=v; else if(x.startsWith('on')) e.addEventListener(x.slice(2),v); else if(v!==null&&v!==undefined&&v!==false) e.setAttribute(x,v===true?'':v); }
  for(const c of k.flat()){ if(c==null||c===false) continue; e.append(c instanceof Node?c:document.createTextNode(String(c))); } return e; }
const SVGNS = 'http://www.w3.org/2000/svg';
function sv(t, a={}, ...k){ const e=document.createElementNS(SVGNS,t);
  for(const [x,v] of Object.entries(a)){ if(x.startsWith('on')) e.addEventListener(x.slice(2),v); else e.setAttribute(x,v); }
  k.flat().forEach(c=>c!=null&&e.append(c instanceof Node?c:document.createTextNode(String(c)))); return e; }
const tip = $('#tip');
function hover(node, text){ node.addEventListener('mousemove',e=>{tip.hidden=false;tip.textContent=text;tip.style.left=Math.min(e.clientX+14,innerWidth-270)+'px';tip.style.top=(e.clientY+14)+'px';}); node.addEventListener('mouseleave',()=>tip.hidden=true); }
function toastMsg(t){ const d=el('div',{class:'toast',role:'status',text:t}); document.body.append(d); setTimeout(()=>d.remove(),2400); }
const money = c => c ? '$' + (c < 0.01 ? c.toFixed(4) : c.toFixed(c < 1 ? 3 : 2)) : '$0';
const dur = s => s < 90 ? Math.round(s) + ' s' : Math.round(s/60) + ' min';
const MON = ['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'];
const toDate = s => new Date(String(s).replace(' ', 'T'));
const dayOf = s => { const d = toDate(s); return isNaN(d) ? String(s).slice(0,10) : `${d.getDate()} ${MON[d.getMonth()]}`; };
const timeOf = s => String(s).replace('T',' ').slice(11,16);
const stamp = s => s ? `${dayOf(s)} ${timeOf(s)}` : '';
const fmtConf = a => a.conf == null ? 'not judged' : a.conf.toFixed(2);

/* ---------------- data ---------------- */
let STATUS = null, RUNS = [], ISSUES = [], JOBS = [], HIST = [];
let A = [];                                   // the issues on screen (latest scan of each project, or one scan)
let CWE = {}, RULE = {}, CW = [], PROJ = [];
const OWASP = [['A01','Broken Access Control'],['A02','Security Misconfiguration'],['A03','Software Supply Chain Failures'],['A04','Cryptographic Failures'],['A05','Injection'],
  ['A06','Insecure Design'],['A07','Authentication Failures'],['A08','Software or Data Integrity Failures'],['A09','Security Logging and Alerting Failures'],['A10','Mishandling of Exceptional Conditions']];
const MODELS = {'claude-haiku-5-5':['Claude Haiku 5.5','var(--k-c1)'], 'claude-sonnet-5-5':['Claude Sonnet 5.5','var(--k-c3)'], 'qwen3:14b':['Qwen3 14B (local)','var(--k-c2)'],
  'mock':['Demo model','var(--k-hid)'], 'scanner only':['Scanner only','var(--k-hid)']};
const modelName = m => (MODELS[m] || [m])[0];
const modelCol = m => (MODELS[m] || [0, 'var(--k-c5)'])[1];
const GN = {Confirmed:'Confirmed by AI', Review:'Needs review', Hidden:'Auto-ignored'};
const GC = {Confirmed:'var(--k-conf)', Review:'var(--k-rev)', Hidden:'var(--k-hid)'};
const SEVC = {critical:'var(--k-crit)', high:'var(--k-high)', medium:'var(--k-med)', low:'var(--k-med)'};
const SEVW = {critical:3, high:2, medium:1, low:0};
const MINE_N = {real:'Real vulnerability', fp:'False alarm', unsure:'Not sure', cleared:'Decision cleared'};
const open = a => a.g !== 'Hidden' && a.mine !== 'fp';
const S = {view:'dashboard', proj:new Set(), cwe:new Set(), sev:new Set(['critical','high','medium','low']), grp:new Set(['Confirmed','Review','Hidden']),
  onlyNew:false, bin:null, sort:'open', otile:null, run:null, cmp:{a:'',b:''}, cmpShow:'changed', models:new Set()};

function titleOf(i){
  const src = ((i.code || []).find(c => c[0] === i.line) || [0, ''])[1];
  const t = {'CWE-502': /dumps?\(/.test(src) ? 'pickle used to write data' : 'Untrusted data passed to a deserializer', 'CWE-95':'Dynamic code run with eval() or exec()',
    'CWE-78':'Process started from program input', 'CWE-89':'SQL statement built from strings', 'CWE-611':'XML parsed with external entities', 'CWE-614':'Cookie sent without Secure flag'};
  return t[i.cwe] || i.rule || i.cwe;
}
function verdictText(i){
  if(!i.verdict) return 'not checked by the AI';
  let t = i.verdict.replace(/_/g, ' ');
  if(i.group === 'Needs review' && /false/.test(i.verdict)) t += !i.verified ? ', cited lines not found' : (i.conf != null && i.conf < STATUS.threshold ? `, confidence below ${STATUS.threshold}` : '');
  return t;
}
function ensureCwe(c){ if(!CWE[c]){ CWE[c] = [c === 'unknown' ? 'Other' : c, 'medium', '']; RULE[c] = ''; } if(!CW.includes(c)) CW.push(c); }
function adapt(i){
  i.p = i.project; i.g = i.group === 'Needs review' ? 'Review' : i.group;
  i.mine = i.review && i.review.label || null; i.isNew = !!i.new; i.history = i.history || [];
  i.title = titleOf(i); ensureCwe(i.cwe); if(!(i.sev in SEVW)) i.sev = 'medium';
  return i;
}
async function load(){
  const runParam = S.run ? '?run=' + encodeURIComponent(S.run) : '';
  [STATUS, RUNS, ISSUES, JOBS, HIST] = await Promise.all([api('/api/status'), api('/api/runs'), api('/api/issues' + runParam), api('/api/scans'), api('/api/history')]);
  const first = !CW.length;
  CWE = {}; RULE = {}; CW = [];
  Object.entries(STATUS.cwes).forEach(([c, x]) => { CWE[c] = [x.name, x.sev, (x.owasp || '').slice(0, 3)]; RULE[c] = x.rule; CW.push(c); });
  A = ISSUES.map(adapt);
  if(first || !S.cwe.size) CW.forEach(c => S.cwe.add(c)); else CW.forEach(c => { if(!(c in STATUS.cwes)) S.cwe.add(c); });
  const by = {}; A.forEach(a => by[a.p] = (by[a.p] || 0) + 1); PROJ = Object.entries(by).sort((x, y) => y[1] - x[1]).map(x => x[0]);
  if(!NS.job){ const running = JOBS.find(j => ['cloning','counting','queued','judging'].includes(j.state)); if(running){ NS.job = running; setTimeout(pollJob, 900); } }
  LIVE.sig = liveSig(RUNS, JOBS); LIVE.at = Date.now();
  drawFoot();
}
function drawFoot(){
  const m = STATUS.models.claude.model, last = RUNS[0];
  if(STATUS.demo){ setDemo(); $('#footModel').textContent = 'Claude Haiku 5.5 results · threshold ' + STATUS.threshold; }
  else $('#footModel').textContent = STATUS.anthropic_key ? `${modelName(m)} · threshold ${STATUS.threshold}` : 'No Claude API key yet';
  $('#footLast').textContent = last ? `Last scan: ${last.project}, ${stamp(last.created)}` : 'No scans yet';
}

/* one filter set drives every chart; chart clicks add to it */
function F(opts={}){ return A.filter(a=>(!S.proj.size||S.proj.has(a.p))&&S.cwe.has(a.cwe)&&S.sev.has(a.sev)&&(opts.ignoreGrp||S.grp.has(a.g))&&(!S.onlyNew||a.isNew)
  &&(opts.ignoreBin||S.bin===null||(a.conf!=null&&Math.min(9,Math.floor(a.conf*10))===S.bin))); }
function matching(){ return F().filter(a=>!S.otile||CWE[a.cwe][2]===S.otile); }
const SEVS = () => ['critical','high','medium'].concat(A.some(a=>a.sev==='low')?['low']:[]);

/* ---------------- filter bar ---------------- */
function dropdown(label, items, set, id){
  const d=el('div',{class:'dd'}); let m=null;
  const b=el('button',{class:'ddb',type:'button','aria-expanded':'false',id},label,set.size?el('span',{class:'n',text:set.size}):el('span',{class:'n',text:'all'}),' ▾');
  b.onclick=e=>{e.stopPropagation(); if(m){m.remove();m=null;b.setAttribute('aria-expanded','false');return;}
    m=el('div',{class:'ddm',role:'group','aria-label':label},el('div',{class:'row'},el('button',{type:'button',onclick:()=>{set.clear();render();}},'Show all'),el('button',{type:'button',onclick:()=>{items.forEach(([k])=>set.add(k));render();}},'Tick all')),
      ...items.map(([k,n])=>el('label',{},el('input',{type:'checkbox',checked:set.has(k),onchange:e=>{e.target.checked?set.add(k):set.delete(k);render();}}),k,el('span',{text:n}))));
    m.onclick=e=>e.stopPropagation(); d.append(m); b.setAttribute('aria-expanded','true'); document.addEventListener('click',function c(){ if(m){m.remove();m=null;} document.removeEventListener('click',c); }); };
  d.append(b); return d;
}
function chk(label, on, onchange, color, count){ return el('label',{class:'chk'+(on?'':' off')},el('input',{type:'checkbox',checked:on,onchange}),color?el('span',{class:'sw',style:'background:'+color}):null,label,count!=null?el('span',{style:'color:var(--faint)',text:count}):null); }
function fp(t, clear){ return el('span',{class:'fpill'},t,el('button',{type:'button','aria-label':'Remove filter '+t,onclick:()=>{clear();render();}},'×')); }
const NOBAR = ['newscan','compare','config','integrations','issue','decisions'];
function renderBar(){
  const b=$('#fbar'); b.replaceChildren(); b.hidden=NOBAR.includes(S.view)||(!A.length&&!S.run);
  if(b.hidden) return;
  if(S.run){ const r=RUNS.find(x=>x.id===S.run);
    b.append(el('span',{class:'runban'},el('b',{text:'Showing one scan: '}),r?`${r.project}, ${stamp(r.created)}`:S.run,
      el('button',{class:'tbtn',type:'button',onclick:()=>openRun(null)},'Show the latest scan of every project'))); }
  const base=A.filter(a=>(!S.proj.size||S.proj.has(a.p)));
  b.append(el('span',{class:'fl',text:'Show'}),
    dropdown('Projects',PROJ.map(p=>[p,A.filter(a=>a.p===p).length]),S.proj,'ddProj'),
    ...SEVS().map(s=>chk(s[0].toUpperCase()+s.slice(1),S.sev.has(s),e=>{e.target.checked?S.sev.add(s):S.sev.delete(s);render();},SEVC[s],base.filter(a=>a.sev===s).length)),
    chk('New since last scan',S.onlyNew,e=>{S.onlyNew=e.target.checked;render();},'var(--accent)',base.filter(a=>a.isNew).length));
  const pills=el('div',{class:'pills'});
  const off=CW.filter(c=>!S.cwe.has(c)); if(off.length&&off.length<CW.length) pills.append(fp(`Types: ${S.cwe.size} of ${CW.length}`,()=>{CW.forEach(c=>S.cwe.add(c));}));
  if(S.cwe.size===1) pills.replaceChildren(fp(`Type: ${CWE[[...S.cwe][0]][0]}`,()=>CW.forEach(c=>S.cwe.add(c))));
  if(S.grp.size<3) pills.append(fp('AI result: '+[...S.grp].map(g=>GN[g]).join(', '),()=>['Confirmed','Review','Hidden'].forEach(g=>S.grp.add(g))));
  if(S.bin!==null) pills.append(fp(`Confidence ${(S.bin/10).toFixed(1)}–${((S.bin+1)/10).toFixed(1)}`,()=>S.bin=null));
  if(S.otile) pills.append(fp(`OWASP ${S.otile}`,()=>S.otile=null));
  b.append(pills);
  const n=matching().length;
  const dirty=S.proj.size||S.sev.size<SEVS().length||S.onlyNew||S.cwe.size<CW.length||S.grp.size<3||S.bin!==null||S.otile;
  if(dirty) b.append(el('button',{class:'reset',type:'button',onclick:()=>{S.proj.clear();S.sev=new Set(['critical','high','medium','low']);S.onlyNew=false;CW.forEach(c=>S.cwe.add(c));['Confirmed','Review','Hidden'].forEach(g=>S.grp.add(g));S.bin=null;S.otile=null;render();}},'Reset'));
  b.append(el('button',{class:'go',type:'button',onclick:()=>drill('These filters',matching())},`Open these ${n}`));
}

/* ---------------- scan history helpers (for the trend lines) ---------------- */
function histDays(){ return [...new Set(HIST.map(r=>r.created.slice(0,10)))].sort().slice(-6); }
function projAt(p, day){ let r=null; for(const h of HIST){ if(h.project===p&&h.created.slice(0,10)<=day) r=h; } return r; }
function histProjects(){ const all=[...new Set(HIST.map(h=>h.project))]; return S.proj.size?all.filter(p=>S.proj.has(p)):all; }
function series(f){ const days=histDays(), ps=histProjects(); return days.map(d=>ps.reduce((s,p)=>{ const r=projAt(p,d); return s+(r?f(r):0); },0)); }

/* ---------------- dashboard ---------------- */
function spark(vals, color){ const w=160,h=28,mx=Math.max(...vals),mn=Math.min(...vals),r=mx-mn||1; const pts=vals.map((v,i)=>[i*(w-4)/(vals.length-1)+2,h-3-(v-mn)/r*(h-8)]);
  return sv('svg',{viewBox:`0 0 ${w} ${h}`,preserveAspectRatio:'none','aria-hidden':'true'},sv('path',{d:'M'+pts.map(p=>p.join(',')).join(' L')+` L${w-2},${h} L2,${h} Z`,fill:color,opacity:.12}),
    sv('path',{d:'M'+pts.map(p=>p.join(',')).join(' L'),fill:'none',stroke:color,'stroke-width':1.6,'vector-effect':'non-scaling-stroke'}),sv('circle',{cx:pts.at(-1)[0],cy:pts.at(-1)[1],r:2.6,fill:color})); }
function kpis(){
  const all=F({ignoreGrp:true}), op=all.filter(open), rv=all.filter(a=>a.g==='Review'&&!a.mine), hd=all.filter(a=>a.g==='Hidden'), nw=op.filter(a=>a.isNew), mine=all.filter(a=>a.mine);
  const crit=op.filter(a=>a.sev==='critical').length;
  const many=!S.run&&histDays().length>1;
  const t=(cls,l,v,f,vals,col,go)=>el('button',{class:'kpi '+cls,type:'button',onclick:go},el('span',{class:'arrow','aria-hidden':'true',text:'→'}),el('span',{class:'l',text:l}),el('span',{class:'v',text:v}),el('span',{class:'f',text:f}),many&&vals?spark(vals,col):null);
  return el('div',{class:'g g-kpi'},
    t('crit','Open issues',op.length,`${crit} critical · ${op.length-crit} other`,series(r=>r.alerts-r.hidden),'var(--k-conf)',()=>drill('Open issues',op)),
    t('warn','Needs your review',rv.length,'AI was not sure, nobody decided yet',series(r=>r.alerts-r.hidden-r.confirmed),'var(--k-rev)',()=>drill('Needs your review',rv)),
    t('hid','Noise removed by AI',(all.length?Math.round(hd.length/all.length*100):0)+'%',`${hd.length} of ${all.length} alerts auto-ignored`,(()=>{ const h=series(r=>r.hidden), n=series(r=>r.alerts); return h.map((x,i)=>n[i]?x/n[i]*100:0); })(),'var(--k-hid)',()=>drill('Auto-ignored by the AI',hd)),
    t('new','New since last scan',nw.length,A.some(a=>a.new!=null)?'appeared in the latest scan':'needs two scans of a folder',null,null,()=>drill('New since last scan',nw)),
    t('ok','Your decisions',mine.length,`${mine.filter(a=>a.mine==='real').length} real · ${mine.filter(a=>a.mine==='fp').length} false alarm · ${mine.filter(a=>a.mine==='unsure').length} not sure`,null,null,()=>go('decisions')));
}
function projectsPanel(){
  const rows=F({ignoreGrp:true}); const by={}; rows.forEach(a=>{(by[a.p]=by[a.p]||{Confirmed:0,Review:0,Hidden:0,t:0}); by[a.p][a.g]++; by[a.p].t++;});
  let list=Object.entries(by);
  const key={open:([,x])=>-(x.Confirmed+x.Review),noise:([,x])=>-(x.Hidden/x.t),name:([p])=>p};
  list.sort((a,b)=>{const k=key[S.sort]; const va=k(a),vb=k(b); return va<vb?-1:va>vb?1:0;});
  const shown=list.slice(0,12), mx=Math.max(1,...shown.map(([,x])=>['Confirmed','Review','Hidden'].reduce((s,g)=>s+(S.grp.has(g)?x[g]:0),0)));
  const N=innerWidth<760, W=N?360:640,rowH=26,lab=N?92:118,H=shown.length*rowH+8;
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H}`,width:'100%',role:'img','aria-label':'Alerts per project'});
  if(S.proj.size) svg.classList.add('dim');
  shown.forEach(([p,x],i)=>{ const y=i*rowH+4; let xx=lab;
    const name=sv('text',{x:0,y:y+15,'font-size':12.5,fill:'var(--ink)','font-weight':600,style:'cursor:pointer'},p.length>(N?12:16)?p.slice(0,N?11:15)+'…':p); name.addEventListener('click',()=>{S.proj.has(p)?S.proj.delete(p):S.proj.add(p);render();}); hover(name,p+' · click to filter'); svg.append(name);
    ['Confirmed','Review','Hidden'].forEach(g=>{ if(!S.grp.has(g)||!x[g]) return; const w=x[g]/mx*(W-lab-(N?70:112));
      const r=sv('rect',{x:xx,y:y+3,width:Math.max(w,1.5),height:16,fill:GC[g],class:'mark'+(S.proj.has(p)?' sel':'')}); hover(r,`${p} · ${GN[g]}: ${x[g]} (click to open)`);
      r.addEventListener('click',()=>drill(`${p} · ${GN[g]}`,rows.filter(a=>a.p===p&&a.g===g))); svg.append(r); xx+=w; });
    svg.append(sv('text',{x:W-2,y:y+15,'font-size':12,'text-anchor':'end',fill:'var(--muted)'},N?`${x.Confirmed+x.Review}/${x.t}`:`${x.Confirmed+x.Review} open · ${x.t}`)); });
  const leg=el('div',{class:'leg'},...['Confirmed','Review','Hidden'].map(g=>chk(GN[g],S.grp.has(g),e=>{e.target.checked?S.grp.add(g):S.grp.delete(g); if(!S.grp.size) S.grp.add(g); render();},GC[g])));
  const sort=el('select',{class:'sortsel',id:'sortSel','aria-label':'Sort projects',onchange:e=>{S.sort=e.target.value;render();}},...[['open','Most open'],['noise','Most noise removed'],['name','A to Z']].map(([v,t])=>el('option',{value:v,selected:S.sort===v},t)));
  return el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Alerts per project'}),el('span',{class:'sub',text:list.length>12?`top 12 of ${list.length}`:`${list.length} project${list.length===1?'':'s'}`}),el('span',{class:'sp'}),sort),
    el('div',{class:'pb',style:'display:grid;gap:12px'},leg,shown.length?svg:el('div',{class:'empty',text:'Nothing matches these filters.'})));
}
/* donut: animated, group-by switch, hover pop-out, tap to reveal details */
const sevHint = s => CW.filter(c=>CWE[c][1]===s).map(c=>CWE[c][0]).join(', ');
const DIMS={
  result:{label:'AI result',keys:()=>['Confirmed','Review','Hidden'],of:a=>a.g,name:k=>GN[k],col:k=>GC[k],
    hint:{Confirmed:'AI traced untrusted input to the line',Review:'AI unsure, a person decides',Hidden:'AI showed it is safe, with lines that exist'},
    focus:k=>{S.grp.clear();S.grp.add(k);}},
  sev:{label:'Severity',keys:SEVS,of:a=>a.sev,name:k=>k[0].toUpperCase()+k.slice(1),col:k=>SEVC[k],hint:{get critical(){return sevHint('critical');},get high(){return sevHint('high');},get medium(){return sevHint('medium');}},
    focus:k=>{S.sev.clear();S.sev.add(k);}},
  cwe:{label:'Weakness type',keys:()=>CW,of:a=>a.cwe,name:k=>CWE[k][0],col:k=>'var(--k-c'+(CW.indexOf(k)%6+1)+')',hint:{},
    focus:k=>{S.cwe.clear();S.cwe.add(k);}},
  mine:{label:'Your decisions',keys:()=>['real','fp','unsure','none'],of:a=>a.mine||'none',name:k=>({real:'You said real',fp:'You said false alarm',unsure:'You are not sure',none:'No decision yet'})[k],
    col:k=>({real:'var(--k-conf)',fp:'var(--ok)',unsure:'var(--k-rev)',none:'var(--k-hid)'})[k],hint:{none:'Still waiting for a person'},focus:null}
};
S.dBy='result'; S.dSel=null; S.dOff=new Set(); let dPrev=null;
function arc(cx,cy,R,r,a0,a1){ const big=a1-a0>Math.PI?1:0, p=(rad,a)=>[cx+rad*Math.cos(a),cy+rad*Math.sin(a)];
  return `M${p(R,a0)} A${R},${R} 0 ${big} 1 ${p(R,a1)} L${p(r,a1)} A${r},${r} 0 ${big} 0 ${p(r,a0)} Z`; }
function donutPanel(){
  const D=DIMS[S.dBy], DK=D.keys(), rows=F({ignoreGrp:S.dBy==='result'});
  const cnt={}; DK.forEach(k=>cnt[k]=0); rows.forEach(a=>{const k=D.of(a); if(k in cnt) cnt[k]++;});
  const keys=DK.filter(k=>!S.dOff.has(k)); const tot=keys.reduce((s,k)=>s+cnt[k],0)||1;
  if(S.dSel&&(!keys.includes(S.dSel)||!cnt[S.dSel])) S.dSel=null;
  const cx=100,cy=100,R=82,r=56;
  const svg=sv('svg',{viewBox:'0 0 200 200',width:200,height:200,role:'img','aria-label':'Alerts by '+D.label,style:'overflow:visible;flex:none'});
  const gSl=sv('g'); svg.append(gSl);
  const big=sv('text',{x:cx,y:cy+4,'text-anchor':'middle','font-size':30,fill:'var(--ink)',style:'font-family:var(--serif)'});
  const small=sv('text',{x:cx,y:cy+24,'text-anchor':'middle','font-size':11.5,fill:'var(--muted)'});
  svg.append(big,small);
  const centre=k=>{ if(k){ big.textContent=cnt[k]; small.textContent=Math.round(cnt[k]/tot*100)+'% of alerts'; } else { big.textContent=keys.some(k=>cnt[k])?tot:0; small.textContent='alerts · tap a slice'; } };
  let a=-Math.PI/2; const target=keys.map(k=>{const a0=a; a+=cnt[k]/tot*Math.PI*2; return [k,a0,a];});
  const from=(dPrev&&dPrev.by===S.dBy)?dPrev.ang:null; dPrev={by:S.dBy,ang:Object.fromEntries(target.map(([k,a0,a1])=>[k,[a0,a1]]))};
  const paths=target.map(([k])=>{ const p=sv('path',{fill:D.col(k),stroke:'var(--surface)','stroke-width':2,class:'slice'+(S.dSel===k?' on':''),tabindex:0,role:'button','aria-label':`${D.name(k)}: ${cnt[k]}`});
    p.addEventListener('mouseenter',()=>{centre(k);p.classList.add('hov');}); p.addEventListener('mouseleave',()=>{centre(S.dSel);p.classList.remove('hov');});
    const pick=()=>{ S.dSel=S.dSel===k?null:k; render(); }; p.addEventListener('click',pick); p.addEventListener('keydown',e=>{if(e.key==='Enter'||e.key===' '){e.preventDefault();pick();}});
    gSl.append(p); return p; });
  const t0=performance.now(), dur=matchMedia('(prefers-reduced-motion: reduce)').matches?0:650;
  const ease=t=>1-Math.pow(1-t,3);
  const frame=now=>{ const t=dur?Math.min(1,(now-t0)/dur):1, e=ease(t);
    target.forEach(([k,a0,a1],i)=>{ let s0=a0,s1=a1; if(from&&from[k]){ s0=from[k][0]+(a0-from[k][0])*e; s1=from[k][1]+(a1-from[k][1])*e; } else { const st=-Math.PI/2; s0=st+(a0-st)*e; s1=st+(a1-st)*e; }
      const mid=(a0+a1)/2, push=S.dSel===k?7:0; paths[i].setAttribute('transform',`translate(${(Math.cos(mid)*push).toFixed(2)},${(Math.sin(mid)*push).toFixed(2)})`);
      paths[i].style.setProperty('--dx',(Math.cos(mid)*5).toFixed(2)+'px'); paths[i].style.setProperty('--dy',(Math.sin(mid)*5).toFixed(2)+'px');
      paths[i].setAttribute('d',s1-s0>0.0005?arc(cx,cy,R,r,s0,s1-0.0001):''); });
    if(t<1) requestAnimationFrame(frame); };
  requestAnimationFrame(frame); centre(S.dSel);
  if(S.dSel) svg.classList.add('dim'); paths.forEach(p=>p.classList.add('mark')); paths.forEach((p,i)=>{ if(target[i][0]===S.dSel) p.classList.add('sel'); });
  const seg=el('div',{class:'seg',role:'tablist','aria-label':'Group the donut by'},...Object.entries(DIMS).map(([k,d])=>el('button',{type:'button',role:'tab','aria-selected':S.dBy===k,class:S.dBy===k?'on':'',onclick:()=>{S.dBy=k;S.dSel=null;S.dOff.clear();render();}},d.label)));
  const legend=el('div',{class:'dleg'},...DK.map(k=>el('div',{class:'dl'+(S.dSel===k?' on':'')+(S.dOff.has(k)?' off':'')},
    el('input',{type:'checkbox','aria-label':'Show '+D.name(k),checked:!S.dOff.has(k),onchange:e=>{e.target.checked?S.dOff.delete(k):S.dOff.add(k); if(S.dOff.size===DK.length) S.dOff.delete(k); render();}}),
    el('button',{type:'button',onclick:()=>{S.dSel=S.dSel===k?null:k; S.dOff.delete(k); render();}},el('span',{class:'sw',style:'background:'+D.col(k)+';width:11px;height:11px'}),
      el('span',{class:'dn2'},D.name(k),D.hint[k]?el('small',{text:D.hint[k]}):S.dBy==='cwe'?el('small',{text:k+(CWE[k][2]?' · '+CWE[k][2]+':2025':'')}):null),el('b',{text:cnt[k]}),el('span',{class:'pct',text:Math.round(cnt[k]/tot*100)+'%'})))));
  let reveal=null;
  if(S.dSel){ const k=S.dSel, sub=rows.filter(a=>D.of(a)===k);
    const other=S.dBy==='result'?['sev',SEVS(),a=>a.sev,x=>SEVC[x],x=>x]:['result',['Confirmed','Review','Hidden'],a=>a.g,x=>GC[x],x=>GN[x]];
    const sc={}; other[1].forEach(x=>sc[x]=0); sub.forEach(a=>sc[other[2](a)]++);
    const pc={}; sub.forEach(a=>pc[a.p]=(pc[a.p]||0)+1); const topP=Object.entries(pc).sort((x,y)=>y[1]-x[1]).slice(0,3);
    const judged=sub.filter(a=>a.conf!=null); const avg=judged.length?(judged.reduce((s,a)=>s+a.conf,0)/judged.length).toFixed(2):'–';
    reveal=el('div',{class:'reveal'},
      el('div',{class:'rv-h'},el('span',{class:'sw',style:'background:'+D.col(k)+';width:12px;height:12px'}),el('b',{text:D.name(k)}),el('span',{class:'sub',text:`${sub.length} alerts · ${Math.round(sub.length/tot*100)}% · average AI confidence ${avg}`}),el('button',{class:'x2',type:'button','aria-label':'Close details',onclick:()=>{S.dSel=null;render();}},'×')),
      el('div',{class:'rv-g'},
        el('div',{},el('span',{class:'fl',text:other[0]==='sev'?'By severity':'By AI result'}),el('div',{class:'sbar',style:'height:12px;margin:6px 0'},...other[1].map(x=>el('span',{style:`width:${sub.length?sc[x]/sub.length*100:0}%;background:${other[3](x)}`}))),
          el('div',{class:'mini'},...other[1].map(x=>el('span',{},el('span',{class:'sw',style:'background:'+other[3](x)}),' ',other[4](x),' ',el('b',{text:sc[x]}))))),
        el('div',{},el('span',{class:'fl',text:'Top projects'}),el('div',{class:'mini col'},...topP.map(([p,n])=>el('button',{type:'button',class:'lnk',onclick:()=>drill(`${p} · ${D.name(k)}`,sub.filter(a=>a.p===p))},p,el('b',{text:n})))))),
      el('div',{class:'rv-a'},D.focus?el('button',{class:'tbtn',type:'button',onclick:()=>{D.focus(k);S.dSel=null;render();}},'Focus dashboard on this'):null,
        el('button',{class:'go',style:'margin-left:0',type:'button',onclick:()=>drill(D.name(k),sub)},`Open these ${sub.length}`)));
  }
  return el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'AI triage outcome'}),el('span',{class:'sub',text:S.run?'this scan':'latest scan of each project'})),
    el('div',{class:'pb',style:'display:grid;gap:14px'},seg,el('div',{class:'dwrap'},svg,legend),reveal));
}
function cwePanel(){
  const rows=F(); const by={}; rows.forEach(a=>{by[a.cwe]=(by[a.cwe]||0)+1;}); const list=CW.map(c=>[c,by[c]||0]).sort((a,b)=>b[1]-a[1]);
  const mx=Math.max(1,...list.map(x=>x[1])); const W=innerWidth<760?380:520,H=210,b=40,bw=(W-b)/Math.max(1,list.length);
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H}`,width:'100%',role:'img','aria-label':'Alerts by weakness type'});
  [0,.5,1].forEach(t=>{const y=170-t*140; svg.append(sv('line',{x1:b,x2:W,y1:y,y2:y,stroke:'var(--line)'}),sv('text',{x:b-8,y:y+4,'font-size':11,'text-anchor':'end',fill:'var(--faint)'},Math.round(mx*t)));});
  if(S.cwe.size<CW.length) svg.classList.add('dim');
  list.forEach(([c,n],i)=>{ const h=n/mx*140, x=b+i*bw+bw*.18, w=bw*.64;
    const r=sv('rect',{x,y:170-h,width:w,height:Math.max(h,1),fill:SEVC[CWE[c][1]],class:'mark'+(S.cwe.size<CW.length&&S.cwe.has(c)?' sel':''),rx:1}); hover(r,`${c} ${CWE[c][0]} · ${CWE[c][1]} · ${n} alerts · click to filter`);
    r.addEventListener('click',()=>{ if(S.cwe.size===1&&S.cwe.has(c)) CW.forEach(x=>S.cwe.add(x)); else {S.cwe.clear();S.cwe.add(c);} render(); });
    svg.append(r,sv('text',{x:x+w/2,y:165-h,'font-size':12,'text-anchor':'middle',fill:'var(--ink)','font-weight':600},n),
      sv('text',{x:x+w/2,y:188,'font-size':11,'text-anchor':'middle',fill:'var(--ink)',style:'font-family:var(--mono)'},c),sv('text',{x:x+w/2,y:203,'font-size':10.5,'text-anchor':'middle',fill:'var(--faint)'},CWE[c][2]?CWE[c][2]+':2025':'')); });
  const boxes=el('div',{class:'leg'},...CW.map(c=>chk(CWE[c][0],S.cwe.has(c),e=>{e.target.checked?S.cwe.add(c):S.cwe.delete(c); if(!S.cwe.size) S.cwe.add(c); render();},SEVC[CWE[c][1]])));
  return el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'By weakness type'}),el('span',{class:'sub',text:'colour = severity'})),el('div',{class:'pb',style:'display:grid;gap:12px'},boxes,svg));
}
function heatPanel(){
  const rows=F({ignoreGrp:true}); const sevs=SEVS(), gs=['Confirmed','Review','Hidden'];
  const m={}; rows.forEach(a=>{const k=a.sev+'|'+a.g; m[k]=(m[k]||0)+1;}); const mx=Math.max(1,...Object.values(m));
  const g=el('div',{style:'display:grid;grid-template-columns:auto repeat(3,minmax(0,1fr));gap:6px;align-items:stretch'},el('span'),
    ...gs.map(x=>el('span',{style:'font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);font-weight:600;text-align:center',text:GN[x]})));
  sevs.forEach(s=>{ g.append(el('span',{class:'sev '+s,style:'align-self:center',text:s}));
    gs.forEach(x=>{ const n=m[s+'|'+x]||0; const t=n/mx;
      const c=el('button',{type:'button',class:'hcell',style:`cursor:${n?'pointer':'default'};color:${t>.55?'var(--surface)':'var(--ink)'};background:color-mix(in srgb,${x==='Hidden'?'var(--k-hid)':SEVC[s]} ${Math.round(8+t*80)}%,var(--surface))`,disabled:!n,onclick:()=>drill(`${s} · ${GN[x]}`,rows.filter(a=>a.sev===s&&a.g===x))},n);
      hover(c,`${n} ${s} alerts ${x==='Hidden'?'auto-ignored':x==='Review'?'need review':'confirmed'}`); g.append(c); }); });
  return el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Severity × AI result'}),el('span',{class:'sub',text:'darker = more alerts'})),el('div',{class:'pb'},g));
}
function confPanel(){
  const rows=F({ignoreBin:true}).filter(a=>a.conf!=null); const bins=Array.from({length:10},()=>({fp:0,other:0,hid:0}));
  rows.forEach(a=>{const b=Math.min(9,Math.floor(a.conf*10)); if(a.g==='Hidden') bins[b].hid++; else if(/false/.test(a.verdict||'')) bins[b].fp++; else bins[b].other++;});
  const mx=Math.max(1,...bins.map(b=>b.fp+b.other+b.hid)); const W=innerWidth<760?400:560,H=210,L=34,bw=(W-L)/10;
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H}`,width:'100%',role:'img','aria-label':'AI confidence'});
  if(S.bin!==null) svg.classList.add('dim');
  [0,.5,1].forEach(t=>{const y=160-t*130; svg.append(sv('line',{x1:L,x2:W,y1:y,y2:y,stroke:'var(--line)'}),sv('text',{x:L-8,y:y+4,'font-size':11,'text-anchor':'end',fill:'var(--faint)'},Math.round(mx*t)));});
  bins.forEach((b,i)=>{ let y=160; const x=L+i*bw+3, w=bw-6;
    [['hid','var(--k-hid)','auto-ignored'],['fp','var(--k-rev)','said "false positive" but kept (low confidence or lines not found)'],['other','var(--k-conf)','said real or unsure']].forEach(([k,col,lab])=>{ if(!b[k]) return; const h=b[k]/mx*130; y-=h;
      const r=sv('rect',{x,y,width:w,height:h,fill:col,class:'mark'+(S.bin===i?' sel':'')}); hover(r,`confidence ${(i/10).toFixed(1)}–${((i+1)/10).toFixed(1)}: ${b[k]} ${lab}`); r.addEventListener('click',()=>{S.bin=S.bin===i?null:i;render();}); svg.append(r); });
    svg.append(sv('text',{x:x+w/2,y:176,'font-size':11,'text-anchor':'middle',fill:'var(--faint)'},(i/10).toFixed(1))); });
  const thr=STATUS.threshold, tx=L+thr*10*bw; svg.append(sv('line',{x1:tx,x2:tx,y1:22,y2:164,stroke:'var(--accent)','stroke-width':2,'stroke-dasharray':'4 3'}),
    sv('text',{x:tx+6,y:20,'font-size':11.5,fill:'var(--accent)','font-weight':700},'hide threshold '+thr),sv('text',{x:W/2+L/2,y:198,'font-size':11.5,'text-anchor':'middle',fill:'var(--muted)'},'AI confidence'));
  const leg=el('div',{class:'leg'},...[['var(--k-hid)','Auto-ignored'],['var(--k-rev)','“False positive” but kept'],['var(--k-conf)','Real or unsure']].map(([c,t])=>el('span',{class:'chk',style:'cursor:default'},el('span',{class:'sw',style:'background:'+c}),t)));
  return el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'How sure was the AI?'}),el('span',{class:'sub',text:`alerts by confidence, with the ${thr} gate`})),el('div',{class:'pb',style:'display:grid;gap:10px'},leg,svg));
}
function trendPanel(){
  const rows=F({ignoreGrp:true}); const by={}; rows.filter(open).forEach(a=>by[a.p]=(by[a.p]||0)+1);
  const days=histDays(), top=Object.entries(by).sort((a,b)=>b[1]-a[1]).slice(0,4); const cols=['var(--k-c1)','var(--k-c2)','var(--k-c3)','var(--k-c5)'];
  const head=el('div',{class:'ph'},el('h2',{text:'Open issues across scans'}),el('span',{class:'sub',text:'kept alerts per scan, the 4 projects with most open issues'}));
  if(days.length<2||!top.length) return el('div',{class:'panel'},head,el('div',{class:'empty',text:'This fills in after a project has been scanned on two different days.'}));
  const ser=top.map(([p])=>[p,days.map(d=>projAt(p,d))]); const mx=Math.max(1,...ser.flatMap(s=>s[1].map(r=>r?r.alerts-r.hidden:0))); const W=innerWidth<760?400:560,H=200,L=34,R=16, step=(W-L-R)/Math.max(1,days.length-1);
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H}`,width:'100%',role:'img','aria-label':'Open issues across scans'});
  [0,.5,1].forEach(t=>{const y=160-t*135; svg.append(sv('line',{x1:L,x2:W-R,y1:y,y2:y,stroke:'var(--line)'}),sv('text',{x:L-8,y:y+4,'font-size':11,'text-anchor':'end',fill:'var(--faint)'},Math.round(mx*t)));});
  days.forEach((d,i)=>svg.append(sv('text',{x:L+i*step,y:180,'font-size':11,'text-anchor':'middle',fill:'var(--faint)'},dayOf(d))));
  ser.forEach(([p,v],k)=>{ const pts=v.map((r,i)=>r?[L+i*step,160-(r.alerts-r.hidden)/mx*135,r,i]:null).filter(Boolean);
    if(pts.length>1) svg.append(sv('path',{d:'M'+pts.map(q=>q[0]+','+q[1]).join(' L'),fill:'none',stroke:cols[k],'stroke-width':2.2}));
    pts.forEach(q=>{const last=q[3]===days.length-1; const c=sv('circle',{cx:q[0],cy:q[1],r:last?4.5:3,fill:last?cols[k]:'var(--surface)',stroke:cols[k],'stroke-width':2,class:'mark'}); hover(c,`${p} · scan of ${stamp(q[2].created)}: ${q[2].alerts-q[2].hidden} kept`); c.addEventListener('click',()=>openRun(q[2].id)); svg.append(c);}); });
  const leg=el('div',{class:'leg'},...ser.map(([p],k)=>el('span',{class:'chk',style:'cursor:default'},el('span',{class:'sw',style:'background:'+cols[k]}),p)));
  return el('div',{class:'panel'},head,el('div',{class:'pb',style:'display:grid;gap:10px'},leg,svg));
}
function activityPanel(){
  const days=histDays(), ps=new Set(histProjects());
  const head=el('div',{class:'ph'},el('h2',{text:'New vs resolved'}),el('span',{class:'sub',text:'per scan day, compared with the scan before'}));
  const cols=days.map(d=>{ const rs=HIST.filter(h=>h.created.slice(0,10)===d&&ps.has(h.project)&&h.new!=null); return {d,rs,nw:rs.reduce((s,r)=>s+r.new,0),gone:rs.reduce((s,r)=>s+r.gone,0)}; }).filter(c=>c.rs.length);
  if(!cols.length) return el('div',{class:'panel'},head,el('div',{class:'empty',text:'This fills in after the same folder has been scanned twice.'}));
  const mx=Math.max(1,...cols.map(c=>Math.max(c.nw,c.gone))); const N=innerWidth<760, W=N?400:560,H=220,L=36,mid=104,sc=78/mx, bw=(W-L)/Math.max(cols.length,2);
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H}`,width:'100%',role:'img','aria-label':'New and resolved alerts per scan day'});
  svg.append(sv('line',{x1:L,x2:W,y1:mid,y2:mid,stroke:'var(--line-strong)'}),sv('text',{x:L-8,y:mid-70,'font-size':11,'text-anchor':'end',fill:'var(--faint)'},'+'+mx),sv('text',{x:L-8,y:mid+82,'font-size':11,'text-anchor':'end',fill:'var(--faint)'},'−'+mx));
  const pts=[];
  cols.forEach((c,k)=>{ const x=L+k*bw+bw*.22, w=bw*.56;
    const up=sv('rect',{x,y:mid-c.nw*sc,width:w,height:Math.max(1,c.nw*sc),fill:'var(--k-conf)',class:'mark'}); hover(up,`${dayOf(c.d)}: ${c.nw} new alerts`);
    const dn=sv('rect',{x,y:mid,width:w,height:Math.max(1,c.gone*sc),fill:'var(--ok)',class:'mark'}); hover(dn,`${dayOf(c.d)}: ${c.gone} resolved (gone since the scan before)`);
    [up,dn].forEach(r=>r.addEventListener('click',()=>{ if(c.rs.length===1) openRun(c.rs[0].id); else go('scans'); })); svg.append(up,dn);
    svg.append(sv('text',{x:x+w/2,y:H-8,'font-size':11,'text-anchor':'middle',fill:'var(--faint)'},dayOf(c.d))); pts.push([x+w/2,mid-(c.nw-c.gone)*sc]); });
  if(pts.length>1) svg.append(sv('path',{d:'M'+pts.map(p=>p.join(',')).join(' L'),fill:'none',stroke:'var(--ink)','stroke-width':1.8,'stroke-dasharray':'5 3'}));
  pts.forEach(p=>svg.append(sv('circle',{cx:p[0],cy:p[1],r:3,fill:'var(--ink)'})));
  const tn=cols.reduce((s,c)=>s+c.nw,0), tr=cols.reduce((s,c)=>s+c.gone,0);
  const leg=el('div',{class:'leg'},...[['var(--k-conf)','New'],['var(--ok)','Resolved'],['var(--ink)','Net change']].map(([c,t])=>el('span',{class:'chk',style:'cursor:default'},el('span',{class:'sw',style:'background:'+c}),t)),
    el('span',{class:'chk',style:'cursor:default;margin-left:auto'},'Net resolve rate ',el('b',{style:'color:var(--ink)',text:tn?Math.round(tr/tn*100)+'%':'–'})));
  return el('div',{class:'panel'},head,el('div',{class:'pb',style:'display:grid;gap:10px'},leg,svg));
}
function fixPanel(){
  const rows=F({ignoreGrp:true}).filter(a=>open(a)&&!a.mine).sort((a,b)=>SEVW[b.sev]-SEVW[a.sev]||(a.g==='Confirmed'?-1:1)-(b.g==='Confirmed'?-1:1)||(b.conf||0)-(a.conf||0)).slice(0,6);
  return el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Fix these first'}),el('span',{class:'sub',text:'open, no decision yet, most severe first'})),
    rows.length?el('div',{class:'fix'},...rows.map(a=>el('button',{type:'button',onclick:()=>openIssue(a,rows,false)},el('span',{class:'sev '+a.sev,text:a.sev}),el('span',{style:'min-width:0'},el('b',{text:a.title}),el('span',{class:'loc',text:`${a.p} · ${a.file}:${a.line}`})),el('span',{class:'pill '+a.g,text:GN[a.g]})))):el('div',{class:'empty',text:'Nothing open matches these filters.'}));
}
/* alert journey: scanner -> AI -> you (Sankey), drawn with DOM calls so project text never becomes markup */
function journeyPanel(){
  const rows=F({ignoreGrp:true}), tot=rows.length;
  const G=['Confirmed','Review','Hidden'], M=['real','fp','unsure','none'], mOf=a=>a.mine||'none';
  const MN={real:'You said real',fp:'You said false alarm',unsure:'You were not sure',none:'Not looked at yet'};
  const MC={real:'var(--k-crit)',fp:'var(--ok)',unsure:'var(--k-rev)',none:'var(--line-strong)'};
  const head=el('div',{class:'ph'},el('h2',{text:'Alert journey'}),el('span',{class:'sub',text:'what happened to every alert, from the scanner to the AI to you'}));
  if(!tot) return el('div',{class:'panel'},head,el('div',{class:'empty',text:'Nothing matches these filters.'}));
  if(innerWidth<760){   // phone: the same three steps as stacked bars, so nothing is too small to read
    const step=(label,keys,cnt,name,col,f)=>el('div',{class:'jstep'},el('span',{class:'fl',text:label}),
      el('div',{class:'sbar jbar'},...keys.filter(k=>cnt[k]).map(k=>el('button',{type:'button',style:`width:${cnt[k]/tot*100}%;background:${col(k)}`,'aria-label':`${name(k)}: ${cnt[k]}`,onclick:()=>f(k)}))),
      el('div',{class:'jleg'},...keys.filter(k=>cnt[k]).map(k=>el('button',{type:'button',class:'lnk',onclick:()=>f(k)},el('span',{class:'sw',style:'background:'+col(k)}),el('b',{text:cnt[k]}),' '+name(k)))));
    const c1={},c2={}; G.forEach(g=>c1[g]=rows.filter(a=>a.g===g).length); M.forEach(m=>c2[m]=rows.filter(a=>mOf(a)===m).length);
    return el('div',{class:'panel'},head,el('div',{class:'pb jphone'},
      el('div',{class:'jstep'},el('span',{class:'fl',text:'Scanner found'}),el('b',{class:'jn',text:tot+' alerts'})),
      step('AI decided',G,c1,g=>GN[g],g=>GC[g],g=>drill(GN[g],rows.filter(a=>a.g===g))),
      step('You decided',M,c2,m=>MN[m],m=>MC[m],m=>drill(MN[m],rows.filter(a=>mOf(a)===m)))));
  }
  const W=1000,H=280,gap=14,nw=12,X=[150,540,830],T0=30;
  const c1={},c2={}; G.forEach(g=>c1[g]=rows.filter(a=>a.g===g).length); M.forEach(m=>c2[m]=rows.filter(a=>mOf(a)===m).length);
  const used=(k,c)=>k.filter(x=>c[x]>0);
  const scale=Math.min((H-gap*(used(G,c1).length-1)-18*3)/tot,(H-gap*(used(M,c2).length-1)-18*3)/tot);
  const pos=(keys,cnt)=>{ const u=keys.filter(k=>cnt[k]); const dh=k=>Math.max(cnt[k]*scale,18); let y=T0+(H-(u.reduce((s,k)=>s+dh(k),0)+gap*(u.length-1)))/2; const o={}; keys.forEach(k=>{o[k]={y,h:cnt[k]?dh(k):0,in:(dh(k)-cnt[k]*scale)/2}; if(cnt[k]) y+=dh(k)+gap;}); return o; };
  const p0={y:T0+(H-tot*scale)/2,h:tot*scale}, p1=pos(G,c1), p2=pos(M,c2);
  const band=(x0,y0,x1,y1,h)=>{const m=(x0+x1)/2;return `M${x0},${y0}C${m},${y0} ${m},${y1} ${x1},${y1}L${x1},${y1+h}C${m},${y1+h} ${m},${y0+h} ${x0},${y0+h}Z`;};
  const svg=sv('svg',{viewBox:`0 0 ${W} ${H+T0+6}`,role:'img','aria-label':`Alert journey: ${tot} alerts, ${c1.Confirmed} confirmed, ${c1.Review} need review, ${c1.Hidden} auto-ignored; you decided ${tot-c2.none}`});
  const click=(n,f)=>{ n.addEventListener('click',f); return n; };
  svg.append(sv('text',{class:'ch',x:X[0]+nw,y:14,'text-anchor':'end'},'SCANNER FOUND'),sv('text',{class:'ch',x:X[1],y:14},'AI DECIDED'),sv('text',{class:'ch',x:X[2],y:14},'YOU DECIDED'));
  let y0=p0.y; G.forEach(g=>{ const h=c1[g]*scale; if(!h) return; svg.append(click(sv('path',{class:'band',d:band(X[0]+nw,y0,X[1],p1[g].y+p1[g].in,h),fill:GC[g]},sv('title',{},`${GN[g]}: ${c1[g]}`)),()=>drill(GN[g],rows.filter(a=>a.g===g)))); y0+=h; });
  const o1={},o2={}; G.forEach(g=>o1[g]=p1[g].y+p1[g].in); M.forEach(m=>o2[m]=p2[m].y+p2[m].in);
  G.forEach(g=>M.forEach(m=>{ const sub=rows.filter(a=>a.g===g&&mOf(a)===m), n=sub.length; if(!n) return; const h=n*scale;
    svg.append(click(sv('path',{class:'band',d:band(X[1]+nw,o1[g],X[2],o2[m],h),fill:GC[g]},sv('title',{},`${GN[g]}, then ${MN[m].toLowerCase()}: ${n}`)),()=>drill(`${GN[g]}, then ${MN[m].toLowerCase()}`,sub))); o1[g]+=h; o2[m]+=h; }));
  svg.append(sv('rect',{x:X[0],y:p0.y,width:nw,height:p0.h,rx:4,fill:'var(--muted)',opacity:.55}),
    sv('text',{class:'lab',x:X[0]-10,y:p0.y+p0.h/2-4,'text-anchor':'end'},sv('tspan',{class:'n'},tot),sv('tspan',{x:X[0]-10,dy:18},'scanner alerts')));
  G.forEach(g=>{ if(!c1[g]) return; const p=p1[g]; const cw=String(c1[g]).length*10+GN[g].length*7.4+30, cy=p.y+p.h/2; const f=()=>drill(GN[g],rows.filter(a=>a.g===g));
    svg.append(click(sv('rect',{class:'node',x:X[1],y:p.y,width:nw,height:p.h,rx:3,fill:GC[g]}),f),
      click(sv('g',{class:'chipg'},sv('rect',{class:'chip',x:X[1]+nw+10,y:cy-15,width:cw,height:30,rx:15}),sv('text',{class:'lab',x:X[1]+nw+24,y:cy+5},sv('tspan',{class:'n'},c1[g]),' '+GN[g])),f)); });
  M.forEach(m=>{ if(!c2[m]) return; const p=p2[m]; const f=()=>drill(MN[m],rows.filter(a=>mOf(a)===m));
    svg.append(click(sv('rect',{class:'node',x:X[2],y:p.y,width:nw,height:p.h,rx:3,fill:MC[m]}),f),sv('text',{class:'lab',x:X[2]+nw+8,y:p.y+p.h/2+5},sv('tspan',{class:'n'},c2[m]),' '+MN[m])); });
  return el('div',{class:'panel'},head,el('div',{class:'pb'},el('div',{class:'sk'},svg)));
}
function emptyState(v){
  v.replaceChildren(el('div',{class:'panel'},el('div',{class:'pb welcome'},
    el('h2',{text:'No scans yet'}),
    el('p',{text:'Pick a folder of Python code or a public GitHub link. Semgrep and Bandit look for six kinds of security weakness, then the AI checks each alert and hides only the ones it is confident are false alarms. Everything else is kept for you.'}),
    el('button',{class:'go',style:'margin-left:0',type:'button',onclick:()=>openScan('')},'Start your first scan'))));
}
function viewDash(){ const v=$('#view'); v.replaceChildren(kpis(),journeyPanel(),el('div',{class:'g g-21'},projectsPanel(),donutPanel()),el('div',{class:'g g-11'},cwePanel(),heatPanel()),el('div',{class:'g g-11'},confPanel(),trendPanel()),el('div',{class:'g g-11'},activityPanel(),fixPanel())); }

/* ---------------- OWASP view ---------------- */
function viewOwasp(){
  const rows=F({ignoreGrp:true}); const v=$('#view'); v.replaceChildren();
  const by={}; rows.forEach(a=>{const o=CWE[a.cwe][2]||'—'; by[o]=by[o]||{t:0,cwe:{}}; by[o].t++; const x=by[o].cwe[a.cwe]=by[o].cwe[a.cwe]||{Confirmed:0,Review:0,Hidden:0,t:0,open:0}; x[a.g]++; x.t++; if(open(a)) x.open++;});
  const mx=Math.max(1,...Object.values(by).map(x=>x.t));
  const covered=new Set(CW.map(c=>CWE[c][2]).filter(Boolean));
  const tiles=el('div',{class:'otiles'},...OWASP.map(([c,n],i)=>{ const d=by[c]; const t=el('button',{type:'button',class:'ot'+(d?'':' none')+(S.otile===c?' sel':''),style:`--cat:var(--c${i+1})`,disabled:!d,onclick:()=>{S.otile=S.otile===c?null:c;render();}},
      el('span',{class:'heat',style:d?`opacity:${(0.04+d.t/mx*.16).toFixed(2)}`:''}),el('span',{class:'code',text:c+':2025'}),el('span',{class:'nm',text:n}),el('span',{class:'ct'},d?String(d.t):'–',el('small',{text:d?'alerts':covered.has(c)?'none found':'no rule yet'})));
    if(d) hover(t,`${c} ${n}: ${d.t} alerts in ${Object.keys(d.cwe).length} types · click to show only this`); return t; }));
  const tb=el('tbody');
  [...OWASP,['—','Not mapped to OWASP']].forEach(([c,n],i)=>{ const d=by[c]; if(!d||(S.otile&&S.otile!==c)) return; const st=`--cat:var(--c${Math.min(i+1,10)})`;
    const op=Object.values(d.cwe).reduce((s,x)=>s+x.open,0), nt=Object.keys(d.cwe).length;
    tb.append(el('tr',{class:'grp',style:st},el('td',{colspan:7},el('span',{class:'code',text:c==='—'?'':c+':2025'}),n,el('span',{class:'sub',text:`${nt} type${nt>1?'s':''} · ${d.t} alerts · ${op} open`}))));
    Object.entries(d.cwe).sort((a,b)=>b[1].t-a[1].t).forEach(([cw,x])=>{
      const bar=el('div',{class:'sbar',title:`${x.Confirmed} confirmed · ${x.Review} need review · ${x.Hidden} auto-ignored`},...['Confirmed','Review','Hidden'].map(g=>el('span',{style:`width:${x[g]/x.t*100}%;background:${GC[g]}`})));
      tb.append(el('tr',{class:'row',style:st,tabindex:0,onclick:()=>drill(`${cw} ${CWE[cw][0]}`,rows.filter(a=>a.cwe===cw)),onkeydown:e=>{if(e.key==='Enter')e.currentTarget.click();}},
        el('td',{class:'w'},el('span',{class:'tag',text:cw}),' ',el('span',{class:'cwe-n',text:CWE[cw][0]})),el('td',{'data-l':'Severity'},el('span',{class:'sev '+CWE[cw][1],text:CWE[cw][1]})),
        el('td',{'data-l':'Policy rule'},el('span',{class:'tag',text:RULE[cw]||'none'})),el('td',{class:'w','data-l':'AI result'},bar),
        el('td',{'data-l':'Alerts'},el('span',{class:'num',text:x.t})),el('td',{'data-l':'Open'},el('span',{class:'num',style:'color:var(--crit)',text:x.open})),el('td',{'data-l':'Auto-ignored'},el('span',{class:'num',style:'color:var(--muted)',text:x.Hidden}))));
    }); });
  const leg=el('div',{class:'leg'},...['Confirmed','Review','Hidden'].map(g=>el('span',{class:'chk',style:'cursor:default'},el('span',{class:'sw',style:'background:'+GC[g]}),GN[g])));
  v.append(el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'OWASP Top 10:2025 coverage'}),el('span',{class:'sub',text:'click a category to focus the table'})),el('div',{class:'pb'},tiles)),
    el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Issues by category and weakness type'}),el('span',{class:'sub',text:'from policy/policy.yaml'}),el('span',{class:'sp'}),leg),
      tb.children.length?el('div',{style:'overflow-x:auto'},el('table',{class:'otab'},el('thead',{},el('tr',{},...['Weakness (CWE)','Severity','Policy rule','AI result','Alerts','Open','Auto-ignored'].map(h=>el('th',{text:h})))),tb)):el('div',{class:'empty',text:'Nothing matches these filters.'})));
}

/* ---------------- a list of alerts in a side panel (every chart click lands here) ---------------- */
function oneRun(rows){ const r=[...new Set(rows.map(a=>a.run))]; return r.length===1?r[0]:null; }
/* CSV of exactly the alerts shown (any mix of scans). Cells starting with = + - @ are prefixed so spreadsheets don't run them. */
function rowsCsv(rows,name){
  const q=v=>{ let t=v==null?'':String(v); if(/^[=+\-@\t\r]/.test(t)) t="'"+t; return /[",\n\r]/.test(t)?'"'+t.replace(/"/g,'""')+'"':t; };
  const head=['project','scan','file','line','cwe','severity','tool','rule','ai_group','ai_verdict','confidence','your_decision','your_note','gate'];
  const body=rows.map(a=>[a.p,a.run,a.file,a.line,a.cwe,a.sev,a.tool,a.rule,GN[a.g]||a.g,a.verdict,a.conf==null?'':a.conf.toFixed(2),a.mine?MINE_N[a.mine]:'',a.review&&a.review.note||'',a.decision].map(q).join(','));
  const blob=new Blob(['\ufeff'+[head.join(','),...body].join('\r\n')],{type:'text/csv'});
  const x=el('a',{href:URL.createObjectURL(blob),download:(name||'alerts').replace(/[^\w.-]+/g,'-').replace(/^-|-$/g,'')+'.csv'}); document.body.append(x); x.click(); x.remove(); setTimeout(()=>URL.revokeObjectURL(x.href),4000);
}
function exportBar(rows,title){
  const runs=[...new Set(rows.map(a=>a.run))], run=runs.length===1?runs[0]:null;
  const label=r=>{ const x=RUNS.find(y=>y.id===r); return x?`${x.project} · ${stamp(x.created)}`:r; };
  const out=[el('button',{class:'tbtn',type:'button',title:'Exactly the alerts in this list, with the AI verdict and your decisions',onclick:()=>rowsCsv(rows,title)},'Export CSV')];
  if(run) out.push(el('button',{class:'tbtn',type:'button',title:'The full HTML report of this scan',onclick:()=>download(`/api/runs/${run}/report.html`)},'Export report'),
    el('button',{class:'tbtn',type:'button',title:'The whole scan as SARIF, for GitHub and other tools',onclick:()=>download(`/api/runs/${run}/export.sarif`)},'Export SARIF'));
  else if(runs.length>1){ const sel=el('select',{class:'sortsel rsel','aria-label':'Report of one scan',onchange:e=>{ const v=e.target.value; e.target.value=''; if(!v) return; const [kind,r]=v.split('|'); download(`/api/runs/${r}/${kind}`); }},
      el('option',{value:'',text:`Report or SARIF of one scan (${runs.length})`}),
      ...runs.map(r=>el('optgroup',{label:label(r)},el('option',{value:'report.html|'+r,text:'Report · '+label(r)}),el('option',{value:'export.sarif|'+r,text:'SARIF · '+label(r)}))));
    out.push(sel); }
  return out;
}
function drill(title, rows){
  const layer=$('#layer'); const close=()=>{ layer.replaceChildren(); removeEventListener('keydown',esc); }; const esc=e=>{if(e.key==='Escape') close();}; addEventListener('keydown',esc);
  rows=rows.slice().sort((a,b)=>SEVW[b.sev]-SEVW[a.sev]||({Confirmed:0,Review:1,Hidden:2}[a.g]-{Confirmed:0,Review:1,Hidden:2}[b.g])||(b.conf||0)-(a.conf||0));
  const desc=[S.proj.size?`projects: ${[...S.proj].join(', ')}`:null,S.sev.size<SEVS().length?`severity: ${[...S.sev].filter(s=>SEVS().includes(s)).join(', ')}`:null,S.onlyNew?'new since last scan':null,S.cwe.size<CW.length?`types: ${[...S.cwe].join(', ')}`:null].filter(Boolean).join(' · ');
  layer.replaceChildren(el('div',{class:'scrim',onclick:close}),el('aside',{class:'drill',role:'dialog','aria-label':title},
    el('div',{class:'drill-h'},el('button',{class:'x',type:'button','aria-label':'Close',onclick:close},'×'),el('span',{class:'crumb',text:'Alerts'}),el('h3',{text:title}),
      el('span',{style:'color:var(--muted);font-size:13px',text:`${rows.length} alert${rows.length===1?'':'s'}${desc?' · '+desc:''}`}),
      el('div',{class:'rv-a'},el('button',{class:'tbtn fsb',type:'button',onclick:e=>{ const d=e.currentTarget.closest('.drill'); d.classList.toggle('wide'); e.currentTarget.textContent=d.classList.contains('wide')?'Side panel':'Full screen'; }},'Full screen'),
        ...(rows.length?exportBar(rows,title):[]))),
    el('div',{class:'drill-b'},...rows.slice(0,200).map(a=>el('div',{class:'r',tabindex:0,role:'button',onclick:()=>openIssue(a,rows,false),onkeydown:e=>{if(e.key==='Enter')openIssue(a,rows,false);}},el('div',{style:'min-width:0'},el('b',{text:a.title}),el('div',{class:'loc',text:`${a.p} · ${a.file}:${a.line}`})),
      el('div',{class:'meta'},el('span',{class:'sev '+a.sev,text:a.sev}),el('span',{class:'pill '+a.g,text:GN[a.g]}),a.mine?el('span',{class:'mtag '+a.mine,text:MINE_N[a.mine]}):el('span',{class:'tag',text:a.conf==null?'–':a.conf.toFixed(2)})))),
      rows.length>200?el('div',{class:'empty',text:`and ${rows.length-200} more: narrow the filters to see them`}):null,
      !rows.length?el('div',{class:'empty',text:'No alerts here.'}):null)));
}

/* ---------------- one alert: code, AI analysis, your decision ---------------- */
let UID=0;
function citedLines(a){ const out=new Set();
  (a.evidence||[]).forEach(([loc])=>{ const k=loc.lastIndexOf(':'); const f=loc.slice(0,k).replace(/\\/g,'/'), spec=loc.slice(k+1);
    if(f&&!(a.file.endsWith(f)||f.endsWith(a.file))) return;
    spec.split(',').forEach(p=>{ const m=p.trim().match(/^(\d+)(?:\s*-\s*(\d+))?$/); if(m){ for(let n=+m[1];n<=+(m[2]||m[1])&&n-m[1]<200;n++) out.add(n); } }); });
  return out; }
function codeDoc(a){
  const uid=a._uid=++UID, cited=citedLines(a), box=el('div',{class:'code'}); let prev=null;
  const gap=t=>el('div',{class:'ln gap'},el('span',{class:'n'}),el('span',{class:'m'}),el('span',{text:t}));
  (a.code||[]).forEach(([n,t])=>{ if(prev!==null&&n>prev+1) box.append(gap(`${n-prev-1} line${n-prev-1>1?'s':''} not shown to the AI`));
    const hl=n>=a.line&&n<=(a.end||a.line), ci=!hl&&cited.has(n);
    box.append(el('div',{class:'ln'+(hl?' hl':ci?' cite':''),id:`ln-${uid}-${n}`},el('span',{class:'n',text:n}),el('span',{class:'m',text:hl?'▶':ci?'•':''}),el('span',{text:t}))); prev=n; });
  if(!(a.code||[]).length) box.append(gap('No code was sent to the AI for this alert.'));
  let pf=null; (a.helpers||[]).forEach(([f,n,t])=>{ if(f!==pf){ box.append(gap(`helper code from ${f}`)); pf=f; } box.append(el('div',{class:'ln'},el('span',{class:'n',text:n}),el('span',{class:'m'}),el('span',{text:t}))); });
  return el('div',{class:'cdoc'},
    el('div',{class:'cdoc-h'},el('span',{class:'loc',text:`${a.p} · ${a.file}`}),el('span',{class:'tag',text:'line '+a.line})),box,
    a.note?el('p',{class:'legend-c',text:a.note}):null,
    el('p',{class:'legend-c'},el('b',{text:'▶'}),' flagged line   ',el('b',{text:'•'}),' evidence the AI cited (tap one on the right to find it here)'));
}
let SAVING=false;
async function decide(a, k, onDone){
  if(SAVING) return; SAVING=true;
  const label=a.mine===k?'clear':k, note=label==='clear'?'':(a._draft!=null?a._draft:(a.review&&a.review.note)||'');
  try{ await api('/api/reviews',{method:'POST',body:{run:a.run,fid:a.fid,label,note}});
    const now=new Date().toISOString().slice(0,19);
    a.review=label==='clear'?null:{label,note,updated:now}; a.mine=label==='clear'?null:label; a._draft=null;
    a.history=a.history.concat([{label:label==='clear'?'cleared':label,note,at:now}]);
    toastMsg(label==='clear'?'Decision cleared':'Saved: '+MINE_N[label]); drawCounts(); onDone&&onDone(a.mine);
  }catch(e){ if(e.message!=='no token') toastMsg(e.message); }
  SAVING=false;
}
async function saveNote(a, text){
  a._draft=text;
  if(!a.mine){ toastMsg('Pick a decision first. The note is saved with it.'); return; }
  try{ await api('/api/reviews',{method:'POST',body:{run:a.run,fid:a.fid,label:a.mine,note:text}});
    const now=new Date().toISOString().slice(0,19); a.review={label:a.mine,note:text,updated:now}; a._draft=null;
    a.history=a.history.concat([{label:a.mine,note:text,at:now}]); toastMsg('Note saved');
  }catch(e){ if(e.message!=='no token') toastMsg(e.message); }
}
function decideBar(a, onDone){
  const note=(a._draft!=null?a._draft:(a.review&&a.review.note))||'';
  const hist=a.history.map((h,i)=>({...h,t:i&&h.label===a.history[i-1].label?'Note edited':MINE_N[h.label]||h.label})).slice(-5);
  return el('div',{class:'dbar'},el('span',{class:'fl',text:'Your decision'}),
    el('div',{class:'opts'},...[['real','Real vulnerability','R'],['fp','False alarm','F'],['unsure','Not sure','U']].map(([k,l,key])=>
      el('button',{type:'button',class:'opt '+k+(a.mine===k?' on':''),'aria-pressed':a.mine===k,onclick:()=>decide(a,k,onDone)},l,el('kbd',{text:key})))),
    el('span',{class:'hint',text:a.mine?'Tap your choice again to clear it.':'Saved as soon as you tap. Kept apart from the AI verdict.'}),
    el('textarea',{class:'nsi',rows:2,maxlength:2000,placeholder:'Note: why? (kept with the decision and in the CSV)','aria-label':'Note for this decision',text:note,oninput:e=>{a._draft=e.target.value;},onchange:e=>saveNote(a,e.target.value.trim())}),
    a.review&&a.review.note?el('span',{class:'hint',text:`Note saved ${stamp(a.review.updated)}`}):null,
    hist.length?el('span',{class:'hint',text:'History: '+hist.map(h=>`${h.t} (${stamp(h.at)})`).join(' → ')}):null);
}
function analysis(a, onDone){
  const thr=STATUS.threshold;
  const find=n=>{ const x=document.getElementById(`ln-${a._uid}-${n}`); if(!x) return; x.scrollIntoView({block:'nearest'}); x.classList.remove('pulse'); void x.offsetWidth; x.classList.add('pulse'); };
  const codeAt=n=>((a.code||[]).find(c=>c[0]===n)||[0,''])[1];
  const yn=(v,y,n)=>v==null?'not judged':v?y:n;
  return el('div',{class:'ana'},
    el('div',{class:'ana-h'},el('span',{class:'fl',text:'AI analysis'}),el('span',{class:'sp'}),el('span',{class:'tag',text:a.policy||RULE[a.cwe]||'no rule'}),el('span',{class:'tag',text:a.cwe}),el('span',{class:'sev '+a.sev,text:a.sev})),
    el('h3',{text:a.title}),
    el('dl',{class:'ana-dl'},
      el('dt',{text:'Verdict'}),el('dd',{},el('span',{class:'pill '+a.g,text:GN[a.g]}),el('span',{class:'vtxt',text:verdictText(a)})),
      el('dt',{text:'Confidence'}),el('dd',{},a.conf==null?el('span',{class:'hint',text:'not judged'}):[el('div',{class:'cm2'},el('div',{class:'cmeter'},el('span',{style:`width:${a.conf*100}%`}),el('i',{style:`left:${thr*100}%`,title:'hide threshold '+thr})),el('b',{text:a.conf.toFixed(2)})),el('span',{class:'hint',text:a.conf>=thr?`At or above the ${thr} line`:`Below the ${thr} line, so a person decides`})]),
      a.verdict?el('dt',{text:'Checks'}):null,
      a.verdict?el('dd',{class:'checks'},...[['Attacker can reach it',yn(a.feasible,'yes, plausibly','no'),a.feasible],['Input checked or cleaned',yn(a.sanitized,'yes','no'),a.sanitized===false],['Cited lines exist',a.verified?'yes, checked':'no',!a.verified]].map(([l,v,bad])=>el('span',{class:'ck'+(bad?' bad':'')},l+': ',el('b',{text:v})))):null,
      (a.evidence||[]).length?el('dt',{text:'Evidence'}):null,
      (a.evidence||[]).length?el('dd',{},...a.evidence.map(([loc,why])=>{ const n=+(loc.split(':').pop().match(/\d+/)||[0])[0]; const t=codeAt(n);
        return el('button',{type:'button',class:'ev',onclick:()=>find(n),onmouseenter:()=>find(n)},el('b',{text:`line ${loc.split(':').pop().replace(/^(\d+)-\1$/,'$1')}${n>=a.line&&n<=(a.end||a.line)?' · flagged':''}`}),t?el('code',{text:t.trim()}):null,why?el('span',{class:'hint',text:why}):null); })):null,
      el('dt',{text:'Why'}),el('dd',{text:a.reason||'This alert was not checked by the AI.'}),
      el('dt',{text:a.g==='Hidden'?'Hidden because':'Kept because'}),el('dd',{text:a.decision||''}),
      el('dt',{text:'Fix'}),el('dd',{text:a.fix||((STATUS.cwes[a.cwe]||{}).title)||'No fix suggested.'})),
    decideBar(a,onDone));
}
function scannerFacts(a){
  return el('div',{class:'sect'},el('h4',{text:'Scanner details'}),el('div',{class:'facts'},...[['Scanner',a.tool],['Rule id',a.rule_full],a.also&&a.also.length?['Also reported by',a.also.join(', ')]:null,
    ['Weakness',`${a.cwe} ${CWE[a.cwe][0]}`],['OWASP Top 10',(STATUS.cwes[a.cwe]||{}).owasp||'not mapped'],['Scan',`${a.p} · ${stamp((RUNS.find(r=>r.id===a.run)||{}).created)||a.run}`]].filter(Boolean).map(([l,v])=>el('div',{class:'fact'},el('span',{text:l}),el('b',{text:v})))),
    a.msg?el('p',{class:'hint',text:'Scanner message: '+a.msg}):null);
}
function merBody(a, list){
  const same=A.filter(x=>x.run===a.run&&x.file===a.file&&x.id!==a.id).slice(0,6);
  const related=el('div',{class:'sect'},el('h4',{text:`Other alerts in ${a.file.split('/').pop()}`}),same.length?el('div',{class:'mini col'},...same.map(x=>el('button',{type:'button',class:'lnk',onclick:()=>openIssue(x,list,true)},`${x.title} · line ${x.line}`,el('span',{class:'pill '+x.g,text:GN[x.g]})))):el('p',{class:'hint',text:'None.'}));
  return el('div',{class:'ibody mer'},el('div',{class:'imain'},codeDoc(a),scannerFacts(a),related),el('div',{class:'iside'},el('div',{class:'anacard'},analysis(a,()=>openIssue(a,list,true)))));
}
let CUR=null, BACK=null;
function issueHead(a, full, list){
  const i=list.indexOf(a), nav=el('div',{class:'inav'},el('button',{class:'tbtn',type:'button',disabled:i<=0,onclick:()=>openIssue(list[i-1],list,full)},'Previous'),el('span',{class:'sub',style:'color:var(--muted);font-size:12.5px',text:`${i+1} of ${list.length}`}),el('button',{class:'tbtn',type:'button',disabled:i>=list.length-1,onclick:()=>openIssue(list[i+1],list,full)},'Next'));
  return el('div',{class:'ihead'},
    el('div',{class:'row'},el('span',{class:'sev '+a.sev,text:a.sev}),el('span',{class:'pill '+a.g,text:GN[a.g]}),el('span',{class:'tag',text:a.cwe}),a.isNew?el('span',{class:'tag',style:'color:var(--accent)',text:'new'}):null,el('span',{class:'sp'}),
      full?el('button',{class:'tbtn',type:'button',onclick:()=>{closeFull();openIssue(a,list,false);}},'Side panel'):el('button',{class:'tbtn',type:'button',title:'Open as a full page with its own link',onclick:()=>openIssue(a,list,true)},'Full page'),
      full?el('button',{class:'tbtn',type:'button',onclick:closeFull},'Back'):el('button',{class:'x2',type:'button','aria-label':'Close',onclick:()=>{$('#layer').replaceChildren();CUR=null;}},'×')),
    el('h3',{text:a.title}),el('div',{class:'loc',text:`${a.p} · ${a.file}:${a.line}`}),list.length>1?nav:null);
}
function closeFull(){ CUR=null; const b=BACK||'issues'; BACK=null; go(b); }
function openIssue(a, list, full){
  list=list&&list.includes(a)?list:[a]; CUR={a,list,full}; tip.hidden=true;
  if(full){ $('#layer').replaceChildren(); const h='#issue/'+encodeURIComponent(a.id);
    if(location.hash!==h){ if(S.view!=='issue') BACK=S.view; ISSUE_NAV=true; location.hash=h; return; }
    S.view='issue'; setTitle('Triage','Issue'); renderBar();
    $('#view').replaceChildren(el('div',{class:'panel ipage'},issueHead(a,true,list),merBody(a,list))); return; }
  const layer=$('#layer'), close=()=>{ layer.replaceChildren(); CUR=null; render(); };
  layer.replaceChildren(el('div',{class:'scrim',onclick:close}),el('aside',{class:'drill iss',role:'dialog','aria-label':'Issue details'},issueHead(a,false,list),
    el('div',{class:'drill-b',style:'padding:16px 22px;display:grid;gap:16px'},codeDoc(a),analysis(a,()=>openIssue(a,list,false)))));
}
let ISSUE_NAV=false;
addEventListener('keydown',e=>{ if(!CUR||e.target.closest('textarea,input,select')||e.metaKey||e.ctrlKey||e.altKey) return; const {a,list,full}=CUR, i=list.indexOf(a), k=e.key.toLowerCase();
  if(S.view==='issues'||S.view==='review') return;
  if(k==='j'&&i<list.length-1) openIssue(list[i+1],list,full); else if(k==='k'&&i>0) openIssue(list[i-1],list,full);
  else if({r:'real',f:'fp',u:'unsure'}[k]) decide(a,{r:'real',f:'fp',u:'unsure'}[k],()=>openIssue(a,list,full));
  else if(k==='escape'&&S.view==='issue') closeFull(); });

/* ---------------- triage inbox: list | code | analysis, like an email app ---------------- */
S.ib={tab:'Review',id:null}; let INBOX=null;
function viewInbox(){
  const rows=F({ignoreGrp:true});
  const T={Review:rows.filter(a=>a.g==='Review'&&!a.mine),Confirmed:rows.filter(a=>a.g==='Confirmed'&&!a.mine),Hidden:rows.filter(a=>a.g==='Hidden'&&!a.mine),Mine:rows.filter(a=>a.mine)};
  const TN={Review:'Needs you',Confirmed:'Confirmed',Hidden:'Auto-ignored',Mine:'Decided'};
  const list=T[S.ib.tab].slice().sort((x,y)=>SEVW[y.sev]-SEVW[x.sev]||(x.conf??1)-(y.conf??1)||x.file.localeCompare(y.file)||x.line-y.line);
  let i=list.findIndex(x=>x.id===S.ib.id); if(i<0) i=0; const a=list[i]; S.ib.id=a?a.id:null;
  INBOX={list,a,next:list[i+1]||list[i-1]||null};
  const done=nv=>{ if(nv&&S.ib.tab!=='Mine'&&INBOX.next) S.ib.id=INBOX.next.id; render(); };
  const tabs=el('div',{class:'ib-tabs',role:'tablist'},...Object.keys(T).map(k=>el('button',{type:'button',role:'tab','aria-selected':S.ib.tab===k,class:S.ib.tab===k?'on':'',onclick:()=>{S.ib.tab=k;S.ib.id=null;render();}},TN[k],el('span',{text:T[k].length}))));
  const rowsEl=el('div',{class:'ib-rows'},...(list.length?list.slice(0,300).map(x=>el('button',{type:'button',class:'ib-row'+(x===a?' on':''),onclick:()=>{ if(innerWidth<760){ openIssue(x,list,true); return; } S.ib.id=x.id; render(); }},
      el('i',{class:'sdot',style:'background:'+SEVC[x.sev],title:x.sev}),
      el('span',{class:'t'},el('b',{text:x.title}),el('small',{text:`${x.p} · ${x.file.split('/').pop()}:${x.line}`})),
      el('span',{class:'c'},x.mine?el('span',{class:'mtag '+x.mine,text:MINE_N[x.mine]}):el('span',{text:x.conf==null?'–':x.conf.toFixed(2)}),x.isNew?el('em',{text:'new'}):null))):[el('div',{class:'empty',text:'Nothing left in this list.'})]));
  const run=S.run||oneRun(rows);
  const stats=el('div',{class:'ibstats'},...[['Needs you',T.Review.length],['Confirmed, to fix',T.Confirmed.length],['You decided',A.filter(x=>x.mine).length],['Auto-ignored by AI',T.Hidden.length]].map(([l,n])=>el('div',{},el('span',{text:l}),el('b',{text:n}))),
    el('div',{class:'keys'},el('kbd',{text:'J'}),el('kbd',{text:'K'}),' move · ',el('kbd',{text:'R'}),el('kbd',{text:'F'}),el('kbd',{text:'U'}),' decide',
      run?el('button',{class:'tbtn',type:'button',style:'margin-left:10px',onclick:()=>download(`/api/runs/${run}/export.csv`)},'CSV'):null,
      run?el('button',{class:'tbtn',type:'button',onclick:()=>download(`/api/runs/${run}/export.sarif`)},'SARIF'):null));
  if(a) CUR={a,list,full:false};
  $('#view').replaceChildren(stats,el('div',{class:'ib'},el('div',{class:'ib-l'},tabs,rowsEl),
      el('div',{class:'ib-m'},a?codeDoc(a):el('div',{class:'empty',text:'Pick an alert on the left.'})),
      el('div',{class:'ib-r'},a?[el('div',{class:'ana-top'},el('button',{class:'tbtn',type:'button',title:'Show this alert on its own page with the full code',onclick:()=>openIssue(a,list,true)},'Open full page')),analysis(a,done)]:null)));
}
addEventListener('keydown',e=>{ if((S.view!=='issues'&&S.view!=='review')||!INBOX||!INBOX.a||e.target.closest('textarea,input,select')||e.metaKey||e.ctrlKey||e.altKey||$('#layer').children.length) return;
  const {list,a}=INBOX, i=list.indexOf(a), k=e.key.toLowerCase();
  if(k==='j'&&i<list.length-1){S.ib.id=list[i+1].id;render();} else if(k==='k'&&i>0){S.ib.id=list[i-1].id;render();}
  else if({r:'real',f:'fp',u:'unsure'}[k]) decide(a,{r:'real',f:'fp',u:'unsure'}[k],nv=>{ if(nv&&S.ib.tab!=='Mine'&&INBOX.next) S.ib.id=INBOX.next.id; render(); }); });

/* ---------------- Projects: code map and one card per project ---------------- */
function stackBar(c,r,h,t,hgt){ t=t||1; return el('div',{class:'sbar',style:`height:${hgt||6}px;min-width:0`,title:`${c} confirmed · ${r} need review · ${h} auto-ignored`},
  el('span',{style:`width:${c/t*100}%;background:var(--k-conf)`}),el('span',{style:`width:${r/t*100}%;background:var(--k-rev)`}),el('span',{style:`width:${h/t*100}%;background:var(--k-hid)`})); }
S.cm={p:null,dir:null};
function tmap(items,x,y,w,h,out){ if(!items.length) return; if(items.length===1){ out.push({...items[0],x,y,w,h}); return; }
  const tot=items.reduce((s,i)=>s+i.v,0); let acc=0,k=0; while(k<items.length-1&&acc+items[k].v<=tot/2){ acc+=items[k].v; k++; } if(k===0){ acc=items[0].v; k=1; }
  const r=acc/tot, a=items.slice(0,k), b=items.slice(k);
  if(w*1.6>=h){ tmap(a,x,y,w*r,h,out); tmap(b,x+w*r,y,w*(1-r),h,out); } else { tmap(a,x,y,w,h*r,out); tmap(b,x,y+h*r,w,h*(1-r),out); } }
function codeMapPanel(){
  const all=F({ignoreGrp:true}); const byP={}; all.forEach(a=>byP[a.p]=(byP[a.p]||0)+1);
  const top=Object.entries(byP).sort((a,b)=>b[1]-a[1]).slice(0,5).map(x=>x[0]);
  if(!S.cm.p||!byP[S.cm.p]){ S.cm.p=top[0]; S.cm.dir=null; }
  const head=el('div',{class:'ph'},el('h2',{text:'Code map'}),el('span',{class:'sub',text:'where in the code the alerts are'}),el('span',{class:'sp'}),
    el('div',{class:'seg'},...top.map(p=>el('button',{type:'button',class:S.cm.p===p?'on':'',onclick:()=>{S.cm.p=p;S.cm.dir=null;render();}},p))),
    Object.keys(byP).length>top.length?el('select',{class:'sortsel cmsel'+(top.includes(S.cm.p)?'':' on'),'aria-label':'Pick any project',onchange:e=>{S.cm.p=e.target.value;S.cm.dir=null;render();}},
      el('option',{value:top.includes(S.cm.p)?'':S.cm.p,text:top.includes(S.cm.p)?`All projects (${Object.keys(byP).length})`:S.cm.p}),
      ...Object.entries(byP).sort((a,b)=>a[0].localeCompare(b[0])).map(([p,n])=>el('option',{value:p,text:`${p} (${n})`}))):null);
  if(!S.cm.p) return el('div',{class:'panel'},head,el('div',{class:'empty',text:'Nothing matches these filters.'}));
  const rows=all.filter(a=>a.p===S.cm.p), rel=a=>a.file.startsWith(a.p+'/')?a.file.slice(a.p.length+1):a.file;
  const dirOf=a=>rel(a).includes('/')?rel(a).split('/')[0]:'(top folder)';
  const sub=S.cm.dir?rows.filter(a=>dirOf(a)===S.cm.dir):rows;
  const key=S.cm.dir?(a=>rel(a).split('/').pop()):dirOf;
  const g={}; sub.forEach(a=>{ const k=key(a); const o=g[k]=g[k]||{name:k,v:0,open:0,crit:0,rows:[]}; o.v++; o.rows.push(a); if(open(a)) o.open++; if(open(a)&&a.sev==='critical') o.crit++; });
  const items=Object.values(g).sort((a,b)=>b.v-a.v); const out=[]; tmap(items,0,0,100,100,out); const mc=Math.max(1,...items.map(i=>i.crit));
  const crumbs=el('div',{class:'cm-crumb'},el('button',{type:'button',class:'lnk',onclick:()=>{S.cm.dir=null;render();}},S.cm.p),S.cm.dir?el('span',{text:' / '+S.cm.dir}):null,
    el('span',{class:'hint',style:'margin-left:auto',text:S.cm.dir?'Tap a file to see its alerts':'Tap a folder to zoom in'}));
  const tm=el('div',{class:'tm'},...out.map(o=>{ const share=o.crit/mc, small=o.w<9||o.h<16;
    return el('button',{type:'button',class:'tmb',title:`${o.name}: ${o.v} alerts, ${o.open} open, ${o.crit} critical`,style:`left:${o.x}%;top:${o.y}%;width:${o.w}%;height:${o.h}%;--t:${Math.round(6+share*40)}%`,
      onclick:()=>{ if(!S.cm.dir&&o.name!=='(top folder)'&&o.rows.some(a=>rel(a).includes('/'))){ S.cm.dir=o.name; render(); } else drill(`${S.cm.p} · ${o.name}`,o.rows); }},
      small?null:el('b',{text:o.name}),small?null:el('small',{text:`${o.v} alerts · ${o.open} open`}),!small&&o.crit?el('small',{class:'cr',text:`${o.crit} critical`}):null); }));
  return el('div',{class:'panel'},head,el('div',{class:'pb',style:'display:grid;gap:10px'},crumbs,tm,
      el('div',{class:'cm-leg'},el('span',{text:'Fewer critical'}),el('i'),el('span',{text:'More critical'}),el('span',{class:'hint',style:'margin-left:auto',text:'Box size = number of alerts'}))));
}
function viewProjects(){
  const v=$('#view'); const rows=F({ignoreGrp:true}); const by={};
  rows.forEach(a=>{ const x=by[a.p]=by[a.p]||{Confirmed:0,Review:0,Hidden:0,t:0,crit:0,mine:0,nw:0,run:a.run}; x[a.g]++; x.t++; if(open(a)&&a.sev==='critical') x.crit++; if(a.mine) x.mine++; if(a.isNew) x.nw++; });
  S.psort=S.psort||'open';
  const list=Object.entries(by).sort((a,b)=>S.psort==='name'?a[0].localeCompare(b[0]):S.psort==='crit'?b[1].crit-a[1].crit:(b[1].Confirmed+b[1].Review)-(a[1].Confirmed+a[1].Review));
  const sort=el('select',{class:'sortsel',id:'pSort','aria-label':'Sort projects',onchange:e=>{S.psort=e.target.value;render();}},...[['open','Most open'],['crit','Most critical'],['name','A to Z']].map(([k,t])=>el('option',{value:k,selected:S.psort===k},t)));
  const grid=el('div',{class:'pgrid'},...list.map(([p,x])=>{ const last=RUNS.find(r=>r.id===x.run), op=x.Confirmed+x.Review;
    return el('div',{class:'pcard'},
      el('div',{class:'pc-h'},el('button',{type:'button',class:'pc-name',onclick:()=>drill(`${p} · open issues`,rows.filter(a=>a.p===p&&open(a)))},p),
        x.crit?el('span',{class:'pc-crit',text:`${x.crit} critical`}):el('span',{class:'pc-ok',text:'no critical'})),
      el('div',{class:'pc-meta',title:last?last.target:'',text:last?`Last scan ${stamp(last.created)} · ${modelName(last.model)} · ${money(last.cost)}`:''}),
      stackBar(x.Confirmed,x.Review,x.Hidden,x.t),
      el('div',{class:'pc-nums'},...[['Confirmed','Confirmed','var(--k-conf)'],['Review','Need review','var(--k-rev)'],['Hidden','Auto-ignored','var(--k-hid)']].map(([g,l,c])=>
        el('button',{type:'button',onclick:()=>drill(`${p} · ${GN[g]}`,rows.filter(a=>a.p===p&&a.g===g))},el('b',{text:x[g]}),el('span',{},el('i',{style:'background:'+c}),l)))),
      el('div',{class:'pc-f'},el('button',{class:'tbtn',type:'button',onclick:()=>drill(`${p} · open issues`,rows.filter(a=>a.p===p&&open(a)))},`View ${op} open`),
        last?el('button',{class:'tbtn',type:'button',onclick:()=>openScan(last.target)},'Scan again'):null,
        x.nw?el('span',{class:'pc-new',text:`${x.nw} new`}):null)); }));
  v.replaceChildren(codeMapPanel(),el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Projects'}),el('span',{class:'sub',text:`${list.length} scanned folder${list.length===1?'':'s'} · ${S.run?'this scan':'latest scan of each'}`}),el('span',{class:'sp'}),sort),
      el('div',{class:'pb'},list.length?grid:el('div',{class:'empty',text:'Nothing matches these filters.'}))));
}

/* ---------------- Scan history: timeline, then scans grouped by day ---------------- */
function modelChips(all){
  const used=[...new Set(all.map(r=>r.model))]; if(used.length<2) return null;
  const pick=m=>{ if(S.models.has(m)) S.models.delete(m); else S.models.add(m); viewScans(); };
  return el('div',{class:'leg'},...used.map(m=>{ const on=!S.models.size||S.models.has(m);
      return el('button',{type:'button',class:'chk mchk'+(on?'':' off')+(S.models.has(m)?' sel':''),'aria-pressed':String(S.models.has(m)),title:S.models.has(m)?'Click to remove from the filter':'Click to show only this model',onclick:()=>pick(m)},
        el('span',{class:'sw',style:'background:'+modelCol(m)}),modelName(m)); }),
    S.models.size?el('button',{type:'button',class:'lnk',style:'font-size:12.5px',onclick:()=>{S.models.clear();viewScans();}},'Show all models'):null);
}
function timelinePanel(runs,all){
  const head=el('div',{class:'ph'},el('h2',{text:'Timeline'}),el('span',{class:'sub',text:'every scan: stick height = alerts checked, dot = model. Click a model to show only its scans.'}));
  const chips=modelChips(all||runs);
  if(!runs.length) return el('div',{class:'panel'},head,el('div',{class:'pb',style:'display:grid;gap:8px'},chips,el('div',{class:'empty',text:'No scans for this choice.'})));
  const ts=runs.map(r=>toDate(r.created).getTime()); let t0=Math.min(...ts), t1=Math.max(...ts);
  const DAY=864e5; t0=new Date(new Date(t0).toDateString()).getTime(); t1=Math.max(t0+DAY*3,new Date(new Date(t1).toDateString()).getTime()+DAY);
  const W=1000, base=150, L=24, R=W-24, x=t=>L+(t-t0)/(t1-t0)*(R-L), days=Math.round((t1-t0)/DAY);
  const svg=sv('svg',{viewBox:`0 0 ${W} ${base+30}`,role:'img','aria-label':`Timeline of ${runs.length} scans`});
  for(let i=0;i<=days;i++){ const xx=x(t0+i*DAY); svg.append(sv('line',{x1:xx,x2:xx,y1:base-(days>40&&i%7?4:8),y2:base,stroke:'var(--line-strong)'})); }
  const every=Math.max(1,Math.ceil(days/6)); for(let i=0;i<=days;i+=every){ svg.append(sv('text',{class:'dl',x:x(t0+i*DAY),y:base+20,'text-anchor':'middle'},dayOf(new Date(t0+i*DAY).toISOString()))); }
  const maxT=Math.max(1,...runs.map(r=>r.alerts));
  runs.forEach(r=>{ const xx=x(toDate(r.created).getTime()), h=14+r.alerts/maxT*100;
    const g=sv('g',{class:'tk',tabindex:0,role:'button','aria-label':`Scan of ${r.project}, ${stamp(r.created)}`},sv('rect',{x:xx-7,y:base-h-8,width:14,height:h+8,fill:'transparent'}),sv('line',{x1:xx,x2:xx,y1:base,y2:base-h,stroke:'var(--muted)','stroke-width':2}),
      sv('circle',{cx:xx,cy:base-h,r:4.5,fill:modelCol(r.model)}),sv('title',{},`${stamp(r.created)} · ${r.project} · ${r.alerts} alerts · ${modelName(r.model)}${r.partial?' · stopped early':''}`));
    g.addEventListener('click',()=>openRun(r.id)); g.addEventListener('keydown',e=>{if(e.key==='Enter') openRun(r.id);}); svg.append(g); });
  return el('div',{class:'panel'},head,el('div',{class:'pb',style:'display:grid;gap:8px'},chips,el('div',{class:'tl'},svg)));
}
function viewScans(){
  const v=$('#view'); v.replaceChildren(); const mOk=r=>!S.models.size||S.models.has(r.model); const runs=RUNS.filter(r=>(!S.proj.size||S.proj.has(r.project))&&mOk(r));
  const active=JOBS.filter(j=>ACTIVE(j.state));
  if(active.length) v.append(el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Running now'})),el('div',{class:'fix'},...active.map(j=>el('button',{type:'button',onclick:()=>openScan(null,j.id)},
    el('span',{class:'pill Review',text:jobLabel(j)}),el('span',{style:'min-width:0'},el('b',{text:j.project}),el('span',{class:'loc',text:j.state==='judging'?`${j.done} of ${j.total} checks · ${j.current||''}`:j.folder})),el('span',{class:'tag',text:'Open'}))))));
  const tc=runs.reduce((s,r)=>s+r.cost,0), ta=runs.reduce((s,r)=>s+r.alerts,0), th=runs.reduce((s,r)=>s+r.hidden,0);
  const strip=el('div',{class:'sstrip'},...[['Scans',runs.length],['Auto-ignored',th+' of '+ta],['Spent',money(tc)]].map(([l,n])=>el('div',{},el('span',{text:l}),el('b',{text:n}))));
  const today=new Date().toISOString().slice(0,10);
  const tb=el('tbody'); let day=null;
  const compare=r=>{ const prev=RUNS.find(x=>x.target===r.target&&x.created<r.created); S.cmp={a:prev?prev.id:'',b:r.id}; go('compare'); };
  runs.forEach(r=>{ const d=r.created.slice(0,10); if(d!==day){ day=d; tb.append(el('tr',{class:'dayrow'},el('td',{colspan:8,text:d===today?'Today · '+dayOf(d):dayOf(d)+' '+d.slice(0,4)}))); }
    const rv=Math.max(0,r.alerts-r.hidden-(r.confirmed||0)), so=r.model==='scanner only';
    tb.append(el('tr',{class:'srow',tabindex:0,onclick:()=>openRun(r.id),onkeydown:e=>{if(e.key==='Enter'&&e.target===e.currentTarget) openRun(r.id);}},
      el('td',{'data-l':'Scan'},el('b',{class:'st',text:timeOf(r.created)})),
      el('td',{'data-l':'Project'},el('b',{style:'color:var(--ink)',title:r.target,text:r.project})),
      el('td',{'data-l':'Model'},el('span',{class:'mchip'},el('i',{style:'background:'+modelCol(r.model)}),modelName(r.model))),
      el('td',{class:'w','data-l':'AI result'},el('div',{style:'display:grid;gap:4px;min-width:140px'},stackBar(r.confirmed||0,rv,r.hidden,r.alerts),el('span',{class:'sub',style:'font-size:12px;color:var(--muted)',text:so?`${r.alerts} alerts, not judged`:`${r.hidden} of ${r.alerts} auto-ignored`}))),
      el('td',{'data-l':'Cost'},el('span',{class:'num',text:money(r.cost)})),
      el('td',{'data-l':'Time'},el('span',{text:dur(r.seconds)})),
      el('td',{'data-l':'Status'},r.partial?el('span',{class:'pill Review',title:r.partial,text:'Stopped early'}):el('span',{class:'okt',text:'Complete'})),
      el('td',{class:'acts','data-l':'Actions'},el('div',{class:'sacts'},...[['Open',()=>openRun(r.id)],['Report',()=>download(`/api/runs/${r.id}/report.html`)],['CSV',()=>download(`/api/runs/${r.id}/export.csv`)],['SARIF',()=>download(`/api/runs/${r.id}/export.sarif`)],['Compare',()=>compare(r)]]
        .map(([t,f])=>el('button',{class:'sact',type:'button',onclick:e=>{e.stopPropagation();f();}},t))))));
  });
  const hp=HIST.filter(h=>!S.proj.size||S.proj.has(h.project)); v.append(timelinePanel(hp.filter(mOk),hp),el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Scan history'}),el('span',{class:'sub',text:'from this app and from the command line'}),el('span',{class:'sp'}),
      el('button',{class:'tbtn',type:'button',onclick:()=>{S.cmp={a:'',b:''};go('compare');}},'Compare two scans')),
      strip,runs.length?el('div',{style:'overflow-x:auto'},el('table',{class:'otab stab'},el('thead',{},el('tr',{},...['Scan','Project','Model','AI result','Cost','Time','Status',''].map(h=>el('th',{text:h})))),tb)):el('div',{class:'empty',text:'No scans yet.'})));
}
async function openRun(id){
  S.run=id||null; S.proj.clear(); S.ib.id=null; S.ib.tab='Review';
  showLoading(); try{ await load(); }catch(e){ if(e.message!=='no token') toastMsg(e.message); }
  if(id&&!A.some(a=>a.g==='Review'&&!a.mine)) S.ib.tab=A.some(a=>a.g==='Confirmed'&&!a.mine)?'Confirmed':'Hidden';
  go(id?'issues':S.view==='issue'?'dashboard':S.view, true);
}

/* ---------------- Your decisions: every decision with its note and history ---------------- */
S.dec={k:'all',q:''};
function viewDecisions(){
  const v=$('#view'), all=A.filter(a=>a.mine), q=S.dec.q.toLowerCase();
  const rows=all.filter(a=>(S.dec.k==='all'||a.mine===S.dec.k)&&(!q||[(a.review&&a.review.note)||'',a.title,a.file,a.p,a.cwe].join(' ').toLowerCase().includes(q)))
    .sort((x,y)=>String(y.review.updated).localeCompare(String(x.review.updated)));
  const cnt=k=>all.filter(a=>a.mine===k).length;
  const chips=el('div',{class:'ib-tabs',style:'border:0;padding:0'},...[['all','All',all.length],['real','Real',cnt('real')],['fp','False alarm',cnt('fp')],['unsure','Not sure',cnt('unsure')]].map(([k,l,n])=>el('button',{type:'button',class:S.dec.k===k?'on':'',onclick:()=>{S.dec.k=k;render();}},l,el('span',{text:n}))));
  const search=el('input',{class:'nsi',type:'search',placeholder:'Search notes, files, types',value:S.dec.q,style:'max-width:280px','aria-label':'Search decisions',oninput:e=>{S.dec.q=e.target.value; const p=e.target.selectionStart; render(); const n=$('#view input[type=search]'); n.focus(); n.setSelectionRange(p,p);}});
  const agree=a=>(a.mine==='real'&&a.g==='Confirmed')||(a.mine==='fp'&&a.g==='Hidden');
  const tb=el('tbody',{},...rows.map(a=>el('tr',{class:'srow',tabindex:0,onclick:()=>openIssue(a,rows,true),onkeydown:e=>{if(e.key==='Enter') openIssue(a,rows,true);}},
    el('td',{class:'w','data-l':'Alert'},el('b',{class:'st',text:a.title}),el('span',{class:'sid',text:`${a.p} · ${a.file.split('/').pop()}:${a.line}`})),
    el('td',{'data-l':'AI said'},el('span',{class:'pill '+a.g,text:GN[a.g]})),
    el('td',{'data-l':'You said'},el('span',{class:'mtag '+a.mine,text:MINE_N[a.mine]}),a.g!=='Review'?el('span',{class:'hint',style:'display:block',text:agree(a)?'agrees with AI':'overrules AI'}):null),
    el('td',{class:'w','data-l':'Note'},a.review.note?el('span',{class:'dnote',text:a.review.note}):el('span',{class:'hint',text:'no note'})),
    el('td',{'data-l':'When'},el('b',{style:'color:var(--ink);font-weight:600',text:stamp(a.review.updated)}),a.history.length>1?el('span',{class:'hint',style:'display:block',text:`changed ${a.history.length-1} time${a.history.length>2?'s':''}`}):null))));
  v.replaceChildren(el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Your decisions'}),el('span',{class:'sub',text:`${all.length} on ${S.run?'this scan':'the latest scans'} · notes are kept with each one`}),el('span',{class:'sp'}),
      el('button',{class:'tbtn',type:'button',title:'Every decision on every scan, with notes',onclick:()=>download('/api/decisions.csv')},'Export CSV')),
    el('div',{class:'pb',style:'display:flex;flex-wrap:wrap;gap:10px;align-items:center;justify-content:space-between'},chips,search),
    el('div',{style:'overflow-x:auto'},el('table',{class:'otab stab dtab'},el('thead',{},el('tr',{},...['Alert','AI said','You said','Note','When'].map(h=>el('th',{text:h})))),rows.length?tb:el('tbody',{},el('tr',{},el('td',{colspan:5,class:'empty',text:all.length?'No decisions match.':'No decisions yet. Open an alert and tap Real, False alarm or Not sure.'})))))));
}

/* ---------------- New scan (a page, so it can be left and come back to) ----------------
   Steps: paste a folder or GitHub link -> Check cost (scanners run, free) -> Start scan (AI check) -> results.
   Cancel works at every step. The spending limit can be changed until the scan starts. */
const NS = {path:'', ref:'', model:null, limit:'1.00', cwes:null, job:null, check:null, checking:0};
let pollTimer = null;
const ACTIVE = s => ['cloning','counting','counted','queued','judging'].includes(s);
const paidModel = m => m === 'claude' || m === 'sonnet';
function jobLabel(j){ return {cloning:'Downloading',counting:'Scanners running',counted:'Cost checked, waiting for you',done:'Done',error:'Stopped',queued:'Queued',judging:'AI checking',cancelled:'Cancelled'}[j.state]||j.state; }

function openScan(path, jobId){            // used by "Scan again", "New scan" buttons and the scan box in the sidebar
  if(jobId){ NS.job = JOBS.find(j => j.id === jobId) || {id: jobId, state: 'counting'}; pollJob(); }
  else if(path !== null && path !== undefined && !(NS.job && ACTIVE(NS.job.state))){ NS.job = null; NS.path = path; NS.ref = ''; NS.check = null; }
  if(location.hash !== '#newscan') go('newscan'); else viewNewScan();
}
async function pollJob(){
  clearTimeout(pollTimer);
  if(!NS.job) return;
  try { NS.job = await api('/api/scans/' + NS.job.id); } catch(e){ return; }
  drawRunBox();
  if(S.view === 'newscan' && !$('#layer').children.length) viewNewScan();
  if(['cloning','counting','queued','judging'].includes(NS.job.state)) pollTimer = setTimeout(pollJob, 900);
  else if(NS.job.state === 'done'){ toastMsg(NS.job.partial ? 'Scan stopped early. Results so far are saved.' : 'Scan finished'); await reloadLive(); }
}
async function checkPath(){
  const text = NS.path.trim(), n = ++NS.checking;
  if(!text){ NS.check = null; drawPathStatus(); return; }
  try { const r = await api('/api/check-folder', {method: 'POST', body: {folder: text}}); if(n === NS.checking){ NS.check = r; drawPathStatus(); } }
  catch(e){ if(n === NS.checking){ NS.check = {ok: false, error: e.message}; drawPathStatus(); } }
}
function drawPathStatus(){
  const s = $('#nsStatus'), refBox = $('#nsRefBox'); if(!s) return;
  const c = NS.check;
  s.className = 'nss' + (c ? (c.ok ? ' good' : ' bad') : '');
  s.textContent = !NS.path.trim() ? (STATUS.demo ? 'Paste a public GitHub link (up to 300 Python files).' : 'Paste a folder path on this computer, or a public GitHub link.')
    : !c ? 'Checking…'
    : c.error ? c.error
    : c.kind === 'github' ? 'Public GitHub repository. It is downloaded first (code is only read, never run), then scanned.'
    : c.ok ? `Folder found: ${c.project} · ${c.py_files >= 20000 ? 'over 20,000' : c.py_files} Python file${c.py_files === 1 ? '' : 's'}.`
    : 'This folder is not on this computer (or not inside Docker\'s /scan folder). Paste where it is now.';
  if(refBox) refBox.hidden = !(c && c.kind === 'github');
}
function viewNewScan(){
  const v = $('#view'); v.replaceChildren();
  if(!NS.cwes) NS.cwes = new Set(Object.keys(STATUS.cwes));
  const DEMO = !!STATUS.demo;
  if(DEMO) NS.model = 'mock';
  if(!NS.model) NS.model = STATUS.anthropic_key ? 'claude' : 'mock';
  const j = NS.job;
  if(j && ['queued','judging','done','cancelled','error'].includes(j.state)){ v.append(runningPanel(j)); return; }
  const locked = j && ['cloning','counting','counted'].includes(j.state);   // settings are fixed once the cost check ran
  const lab = (t, f) => el('label', {class: 'nsl', for: f || null, text: t});
  const invalidate = async () => { if(NS.job && NS.job.state === 'counted'){ try { await api(`/api/scans/${NS.job.id}/cancel`, {method: 'POST'}); } catch(e){} } NS.job = null; drawRunBox(); viewNewScan(); };
  let timer = null;
  const path = el('input', {class: 'nsi mono', id: 'nsPath', autocomplete: 'off', placeholder: DEMO ? 'https://github.com/owner/repo' : 'C:\\Users\\you\\code\\my-project   or   https://github.com/owner/repo', value: NS.path, disabled: locked, 'aria-label': 'Folder path or GitHub link',
    oninput: e => { NS.path = e.target.value; NS.check = null; drawPathStatus(); clearTimeout(timer); timer = setTimeout(checkPath, 350); }});
  const ref = el('input', {class: 'nsi mono', id: 'nsRef', autocomplete: 'off', maxlength: 100, placeholder: 'empty = latest version', value: NS.ref, disabled: locked, oninput: e => { NS.ref = e.target.value; }});
  const checks = el('div', {class: 'nsrow'}, ...Object.entries(STATUS.cwes).map(([c, x]) => el('label', {class: 'chk'},
    el('input', {type: 'checkbox', checked: NS.cwes.has(c), disabled: locked, onchange: e => { e.target.checked ? NS.cwes.add(c) : NS.cwes.delete(c); }}), `${c} ${x.name}`)));
  const model = el('select', {class: 'nsi', id: 'nsModel', disabled: locked, onchange: e => { NS.model = e.target.value; viewNewScan(); }},
    ...[['claude', 'Claude Haiku 5.5 (default, the evaluated model)'], ['sonnet', 'Claude Sonnet 5.5 (stronger, about 20× the cost)'], ['qwen', 'Qwen3 14B on this computer (free, slow, Ollama)'], ['mock', 'Demo model (no AI, free)']].filter(([k]) => !DEMO || k === 'mock')
      .map(([k, t]) => el('option', {value: k, selected: NS.model === k, disabled: paidModel(k) && !STATUS.anthropic_key}, paidModel(k) && !STATUS.anthropic_key ? t + ' · add ANTHROPIC_API_KEY to .env' : t)));
  const paid = paidModel(NS.model);
  const limit = el('input', {class: 'nsi', id: 'nsLimit', type: 'number', min: 0, step: '0.01', inputmode: 'decimal', placeholder: 'no limit', value: NS.limit, disabled: !paid,
    oninput: e => { NS.limit = e.target.value; drawBar(); }});
  const picks = el('div', {class: 'lpick'}, ...['0.10', '0.50', '1.00', '5.00'].map(x => el('button', {type: 'button', class: 'lp', disabled: !paid, onclick: () => { NS.limit = x; limit.value = x; drawBar(); }}, '$' + x)));
  const missing = Object.entries(STATUS.tools).filter(([, ok]) => !ok).map(([t]) => t);

  const bar = el('div', {class: 'nsbar'});
  function drawBar(){
    const job = NS.job, counted = job && job.state === 'counted';
    const lim = paid && NS.limit !== '' ? Number(NS.limit) : null;
    const tiles = [
      ['Alerts to check', counted ? `${job.alerts}` + (job.alerts ? ` in ${job.groups} checks` : '') : '-'],
      ['Expected cost', counted ? (job.estimate ? 'about ' + money(job.estimate) : '$0') : '-'],
      ['Expected time', counted ? (job.est_seconds != null ? 'about ' + dur(job.est_seconds) : 'not known yet') : '-'],
      ['Spending limit', paid ? (lim === null ? 'no limit' : money(lim)) : 'free model']];
    const est = el('div', {class: 'nsest'}, ...tiles.map(([l, x]) => el('div', {}, el('span', {text: l}), el('b', {text: x}))));
    const over = counted && lim !== null && job.estimate > lim;
    const note = job && job.state === 'cloning' ? 'Downloading the repository…'
      : job && job.state === 'counting' ? (job.cancelling ? 'Cancelling…' : 'Semgrep and Bandit are reading the code. No AI yet, so this is free.')
      : counted && !job.alerts ? 'No alerts of these types, so there is nothing for the AI to check.'
      : over ? `The estimate is above your limit, so about ${Math.floor(lim / (job.per_call || 1))} of ${job.groups} checks will run. The rest are kept for you, never hidden.`
      : null;
    const acts = el('div', {class: 'nsact'});
    if(!job) acts.append(el('button', {class: 'tbtn', type: 'button', disabled: missing.length > 0, onclick: startCheck}, 'Check cost'),
      el('button', {class: 'go', style: 'margin-left:0', type: 'button', disabled: true, title: 'Check the cost first'}, 'Start scan'));
    else if(!counted) acts.append(el('button', {class: 'tbtn danger', type: 'button', disabled: !!job.cancelling, onclick: cancelScan}, 'Cancel'));
    else acts.append(el('button', {class: 'tbtn', type: 'button', onclick: invalidate}, 'Change settings'),
      el('button', {class: 'go', style: 'margin-left:0', type: 'button', disabled: !job.alerts, onclick: startScan}, 'Start scan'));
    (job && job.warnings || []).forEach(w => acts.prepend(el('span', {class: 'nswarn', text: w})));
    bar.replaceChildren(est, el('div', {class: 'nsside'}, note ? el('div', {class: 'nsnote' + (over ? ' warn' : ''), text: note}) : null,
      job && !counted ? el('span', {class: 'prog indet'}, el('span')) : null, acts));
  }
  async function startCheck(){
    if(!NS.path.trim()){ toastMsg('Paste a folder path or GitHub link first'); path.focus(); return; }
    if(NS.check && !NS.check.ok){ toastMsg('That folder was not found. Paste where it is now.'); path.focus(); return; }
    if(!NS.cwes.size){ toastMsg('Pick at least one weakness type'); return; }
    const lim = paid && NS.limit !== '' ? Number(NS.limit) : null;
    if(lim !== null && !(lim >= 0)){ toastMsg('The spending limit must be a positive number'); return; }
    try { NS.job = await api('/api/scans', {method: 'POST', body: {folder: NS.path.trim(), ref: NS.ref.trim(), cwes: [...NS.cwes], model: NS.model, max_cost: lim}}); viewNewScan(); pollJob(); }
    catch(e){ if(e.message !== 'no token') toastMsg(e.message); }
  }
  async function startScan(){
    const lim = paid && NS.limit !== '' ? Number(NS.limit) : null;
    if(lim !== null && !(lim >= 0)){ toastMsg('The spending limit must be a positive number'); return; }
    try { NS.job = await api(`/api/scans/${NS.job.id}/start`, {method: 'POST', body: {max_cost: lim}}); viewNewScan(); pollJob(); }
    catch(e){ if(e.message !== 'no token') toastMsg(e.message); }
  }
  const again = RUNS.find(r => r.target && NS.path && r.target === NS.path.trim());
  v.append(el('div', {class: 'panel nsp'},
    el('div', {class: 'ph'}, el('h2', {text: again ? `Scan ${again.project} again` : 'New scan'}), el('span', {class: 'sub', text: DEMO ? 'Paste a public GitHub link. The online demo uses the demo model.' : again ? 'Last folder filled in.' : 'Paste a folder path or GitHub link, then check the cost.'})),
    DEMO ? demoNote() : null,
    missing.length ? el('div', {class: 'runban warnban'}, el('b', {text: 'Not found: ' + missing.join(', ') + '. '}), 'Activate the project\'s virtual environment, then start the app again.') : null,
    el('div', {class: 'nsgrid'},
      el('div', {class: 'nsc'},
        el('div', {class: 'nsf'}, lab(DEMO ? 'Public GitHub link' : 'Folder path or GitHub link', 'nsPath'), path, el('span', {class: 'nss', id: 'nsStatus'})),
        el('div', {class: 'nsf', id: 'nsRefBox', hidden: true}, lab('Branch, tag or commit (optional)', 'nsRef'), ref),
        el('div', {class: 'nsf'}, lab('Scanners'), el('div', {class: 'nsrow'}, ...['Semgrep', 'Bandit'].map(t => el('span', {class: 'lock'}, t, ' ', el('b', {text: STATUS.tools[t.toLowerCase()] ? 'ready' : 'not found'})))) ),
        el('div', {class: 'nsf'}, lab('Weakness types'), checks)),
      el('div', {class: 'nsc'},
        el('div', {class: 'nsf'}, lab('AI model', 'nsModel'), model),
        el('div', {class: 'nsf'}, lab('Spending limit ($)', 'nsLimit'), limit, picks,
          el('span', {class: 'nss', text: paid ? 'The AI check stops before it would go over this. Alerts it did not reach are kept for you.' : 'This model is free, so no limit is needed.'})),
        el('div', {class: 'nsf'}, lab('Judging settings (fixed)'), el('div', {class: 'nsrow'},
          ...[['Threshold', STATUS.threshold], ['Context level', STATUS.context_level], ['Effort', 'low']].map(([l, x]) => el('span', {class: 'lock'}, l + ' ', el('b', {text: x})))),
          el('span', {class: 'nss', text: 'The settings measured in the evaluation, so the results still apply.'})))),
    bar));
  drawBar(); drawPathStatus();
  if(NS.path && !NS.check && !locked) checkPath();
  if(!locked) setTimeout(() => { if(!NS.path && document.activeElement === document.body) path.focus(); }, 30);
}
const STAGES = ['Downloading', 'Running scanners', 'AI checking', 'Saving results'];
function stageOf(j){ return {cloning: 0, counting: 1, counted: 1, queued: 2, judging: 2, done: 4}[j.state] ?? 2; }
function runningPanel(j){
  const st = stageOf(j), over = ['done', 'cancelled', 'error'].includes(j.state);
  const pct = j.state === 'done' ? 100 : j.total ? Math.round(j.done / j.total * 100) : 0;
  const head = j.state === 'done' ? (j.partial ? `Scan of ${j.project} stopped early` : `Scan of ${j.project} finished`)
    : j.state === 'cancelled' ? `Scan of ${j.project} cancelled` : j.state === 'error' ? 'The scan stopped' : `Scanning ${j.project}`;
  const sub = j.state === 'done' ? (j.partial ? `It stopped because ${j.partial}. Alerts it did not reach are kept as "not checked", and the scan is marked partial.` : `${j.alerts} alerts checked.`)
    : j.state === 'cancelled' ? 'Nothing more will be spent.' : j.state === 'error' ? (j.error || '')
    : j.cancelling ? 'Stopping after the current check…' : 'You can leave this page. The scan keeps going and shows in the sidebar.';
  const stages = el('div', {class: 'stg'}, ...STAGES.map((t, k) => (k === 0 && !j.github) ? null :
    el('div', {class: 'st2 ' + (k < st || j.state === 'done' ? 'done' : k === st && !over ? 'now' : '')}, el('i'), el('span', {text: k === 2 && j.total ? `${t} ${Math.min(j.done + (over ? 0 : 1), j.total)} of ${j.total}` : t}))));
  const tiles = el('div', {class: 'nsest'}, ...[['Checked', j.total ? `${j.done} of ${j.total}` : '-'], ['Cost so far', money(j.spent)],
    ['Spending limit', j.max_cost != null ? money(j.max_cost) : 'no limit'], ['Now', j.state === 'judging' ? j.current || 'starting' : jobLabel(j)]].map(([l, x]) => el('div', {}, el('span', {text: l}), el('b', {text: x}))));
  const acts = el('div', {class: 'nsact'});
  if(!over) acts.append(el('button', {class: 'tbtn danger', type: 'button', disabled: !!j.cancelling, onclick: cancelScan}, 'Cancel scan'));
  if(j.state === 'done') acts.append(el('button', {class: 'go', style: 'margin-left:0', type: 'button', onclick: async () => { const p = j.project; NS.job = null; drawRunBox(); S.run = null; await reloadLive(true); S.proj.clear(); if(PROJ.includes(p)) S.proj.add(p); S.ib.id = null; go('issues'); }}, 'See the issues'));
  if(over) acts.append(el('button', {class: 'tbtn', type: 'button', onclick: () => { NS.job = null; NS.check = null; drawRunBox(); viewNewScan(); }}, 'New scan'));
  return el('div', {class: 'panel nsp'}, el('div', {class: 'ph'}, el('h2', {text: head}), el('span', {class: 'sub', text: sub})),
    el('div', {class: 'pb', style: 'display:grid;gap:16px'}, stages, el('span', {class: 'prog', style: 'height:8px'}, el('span', {style: `width:${pct}%`})), tiles, acts));
}
async function cancelScan(){
  if(!NS.job) return;
  try { NS.job = await api(`/api/scans/${NS.job.id}/cancel`, {method: 'POST'}); drawRunBox(); if(S.view === 'newscan') viewNewScan(); if(NS.job.state !== 'cancelled') pollJob(); }
  catch(e){ if(e.message !== 'no token') toastMsg(e.message); }
}
/* the running scan, always visible in the sidebar, with Cancel */
function drawRunBox(){
  const box = $('#runbox'); if(!box) return;
  const j = NS.job && ACTIVE(NS.job.state) ? NS.job : JOBS.find(x => ACTIVE(x.state));
  if(!j){ box.hidden = true; box.replaceChildren(); return; }
  box.hidden = false;
  const pct = j.total ? Math.round(j.done / j.total * 100) : 0;
  box.onclick = () => openScan(null, j.id);
  box.replaceChildren(el('b', {text: j.state === 'counted' ? `Ready to scan ${j.project}` : `Scanning ${j.project}`}),
    el('span', {text: j.state === 'judging' ? `AI check ${j.done} of ${j.total} · ${money(j.spent)} so far` : jobLabel(j)}),
    el('span', {class: 'prog' + (j.state === 'judging' ? '' : ' indet')}, el('span', {style: j.state === 'judging' ? `width:${pct}%` : ''})),
    el('button', {class: 'tbtn danger rbx', type: 'button', disabled: !!j.cancelling, onclick: async e => { e.stopPropagation(); if(!NS.job || NS.job.id !== j.id) NS.job = j; await cancelScan();
      if(j.state === 'counted' && NS.job && NS.job.state === 'cancelled'){ JOBS = JOBS.filter(x => x.id !== j.id); NS.job = null; if(S.view === 'newscan') viewNewScan(); drawRunBox(); } }}, j.state === 'counted' ? 'Discard' : 'Cancel scan'));
}

/* ---------------- Compare two scans ---------------- */
const cmpPill = g => { const k = g === 'Needs review' ? 'Review' : g; return el('span', {class: 'pill ' + k, text: GN[k]}); };
async function viewCompare(){
  const v=$('#view'); v.replaceChildren();
  const judged=RUNS.filter(r=>r.model!=='scanner only');
  if(judged.length<2){ v.append(el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Compare scans'})),el('div',{class:'empty',text:'You need at least two scans to compare. Scan the same project twice, for example with two models.'}))); return; }
  if(!S.cmp.b){ const b=judged[0]; const a=judged.find(r=>r.target===b.target&&r.id!==b.id)||judged[1]; S.cmp={a:a.id,b:b.id}; }
  if(!S.cmp.a){ const b=RUNS.find(r=>r.id===S.cmp.b); const a=judged.find(r=>b&&r.target===b.target&&r.id!==b.id)||judged.find(r=>r.id!==S.cmp.b); S.cmp.a=a.id; }
  const label=r=>`${r.project} · ${modelName(r.model)} · ${stamp(r.created)}${r.partial?' · partial':''}`;
  const pick=(key,text)=>el('select',{class:'sortsel','aria-label':text,onchange:e=>{S.cmp[key]=e.target.value;viewCompare();}},...judged.map(r=>el('option',{value:r.id,selected:S.cmp[key]===r.id},label(r))));
  v.append(el('div',{class:'panel'},el('div',{class:'pb cmp-pick'},el('span',{class:'fl',text:'Before (A)'}),pick('a','Scan A'),el('span',{class:'fl',text:'After (B)'}),pick('b','Scan B'))));
  if(S.cmp.a===S.cmp.b){ v.append(el('div',{class:'panel'},el('div',{class:'empty',text:'Pick two different scans.'}))); return; }
  const out=el('div',{style:'display:grid;gap:20px'},el('div',{class:'panel'},el('div',{class:'empty',text:'Comparing…'}))); v.append(out);
  let c; try{ c=await api(`/api/compare?a=${encodeURIComponent(S.cmp.a)}&b=${encodeURIComponent(S.cmp.b)}`); }catch(e){ out.replaceChildren(el('div',{class:'panel'},el('div',{class:'empty',text:e.message}))); return; }
  if(S.view!=='compare') return;
  out.replaceChildren();
  c.warnings.forEach(w=>out.append(el('div',{class:'runban warnban'},el('b',{text:'Note. '}),w)));
  const kpi=(l,val,f)=>el('div',{class:'kpi',style:'cursor:default'},el('span',{class:'l',text:l}),el('span',{class:'v',text:val}),el('span',{class:'f',text:f}));
  out.append(el('div',{class:'g g-kpi g-4'},kpi('Scan A',`${c.a.hidden} / ${c.a.alerts}`,`hidden / alerts · ${modelName(c.a.model)} · ${c.a.project}`),kpi('Scan B',`${c.b.hidden} / ${c.b.alerts}`,`hidden / alerts · ${modelName(c.b.model)} · ${c.b.project}`),
    kpi('Changed result',c.count.changed,`${c.count.same} the same`),kpi('In one scan only',c.count.only_a+c.count.only_b,`${c.count.only_a} only in A · ${c.count.only_b} only in B`)));
  const chips=el('div',{class:'ib-tabs',style:'border:0;padding:12px 18px 0'},...[['changed','Changed',c.count.changed],['only','In one scan only',c.count.only_a+c.count.only_b],['same','Same',c.count.same],['all','All',c.rows.length]].map(([k,l,n])=>
    el('button',{type:'button',class:S.cmpShow===k?'on':'',onclick:()=>{S.cmpShow=k;viewCompare();}},l,el('span',{text:n}))));
  const rows=c.rows.filter(r=>S.cmpShow==='all'||(S.cmpShow==='only'?r.change.startsWith('only'):r.change===S.cmpShow));
  const res=x=>x?el('div',{class:'cmp-res'},cmpPill(x.group),x.conf!=null?el('span',{class:'hint',text:x.conf.toFixed(2)}):null):el('span',{class:'hint',text:'not in this scan'});
  const tb=el('tbody');
  rows.forEach(r=>{ const why=el('tr',{class:'cmp-why',hidden:true},el('td',{colspan:5},el('div',{class:'g g-11'},
      el('div',{class:'sect'},el('h4',{text:'Scan A said'}),el('p',{text:r.a?(r.a.reason||'no AI reasoning'):'not in this scan'})),
      el('div',{class:'sect'},el('h4',{text:'Scan B said'}),el('p',{text:r.b?(r.b.reason||'no AI reasoning'):'not in this scan'})))));
    tb.append(el('tr',{class:'row',tabindex:0,onclick:()=>{why.hidden=!why.hidden;},onkeydown:e=>{if(e.key==='Enter')why.hidden=!why.hidden;}},
      el('td',{'data-l':'Severity'},el('span',{class:'sev '+r.sev,text:r.sev})),el('td',{class:'w','data-l':'Alert'},el('b',{class:'st',text:`${r.file}:${(r.b||r.a).line}`}),el('span',{class:'sid',text:`${r.cwe} · ${r.tool} ${r.rule}`})),
      el('td',{'data-l':'Scan A'},res(r.a)),el('td',{'data-l':'Scan B'},res(r.b)),el('td',{'data-l':'Change'},el('span',{class:'tag'+(r.change==='changed'?' chg':''),text:{same:'same',changed:'changed',only_a:'only A',only_b:'only B'}[r.change]}))),why); });
  out.append(el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Alerts'}),el('span',{class:'sub',text:'matched by scanner rule, file and code line, so moved code still matches · click a row for both reasons'})),chips,
    rows.length?el('div',{style:'overflow-x:auto'},el('table',{class:'otab cmptab'},el('thead',{},el('tr',{},...['Severity','Alert','Scan A','Scan B','Change'].map(h=>el('th',{text:h})))),tb)):el('div',{class:'empty',text:'Nothing in this group.'})));
}

/* ---------------- Settings / GitHub ---------------- */
const kvPanel=(title,rows,extra)=>el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:title}),el('span',{class:'sp'}),extra||null),el('div',{class:'pb kv'},...rows.flatMap(([k,v])=>[el('span',{text:k}),v instanceof Node?v:el('b',{text:v})])));
function viewConfig(){
  const v=$('#view'); v.replaceChildren();
  const ok=(b,yes,no)=>el('span',{class:'pill '+(b?'okp':'Confirmed'),text:b?yes:no});
  v.append(kvPanel('Models',[['Claude (Anthropic)',el('b',{},ok(STATUS.anthropic_key,'API key found in .env','No API key in .env'),' the key is never shown in the app')],
    ['Cloud model (evaluated)',`${STATUS.models.claude.model} · $0.10 in / $0.50 out per million tokens`],
    ['Stronger cloud model',`${STATUS.models.sonnet.model} · $2 in / $10 out per million tokens · not part of the evaluation`],
    ['Local model (Ollama)',`${STATUS.models.qwen.model} · free and private, but much slower. Ollama must be running.`],
    ['Spending limit','Set one per scan on the New scan page: the check stops before going over it. For a hard monthly cap, also set one in the Claude Console.']]),
  kvPanel('Scanners',[...Object.entries(STATUS.tools).map(([t,b])=>[t[0].toUpperCase()+t.slice(1),el('b',{},ok(b,'Found','Not found: activate the virtual environment'))]),
    ['Rules','The project\'s own rules/ folder plus the Semgrep community Python rules, run offline']]),
  kvPanel('Triage settings',[['Context level',`${STATUS.context_level} · source-to-sink slice with the conditions around it`],
    ['Confidence threshold',`${STATUS.threshold} · alerts are only ignored at or above this, and only when the cited lines exist`],
    ['When the model fails','Keep the alert (fail-open)'],
    ['Why locked','These are the settings measured in the evaluation. Changing them would make the measured results not apply.']],el('span',{class:'tag',text:'locked'})),
  kvPanel('Security of this app',[['Who can open it','Only this computer (127.0.0.1), with a new session key in every request'],
    ['Code, file names, AI text','Always shown as plain text, never as HTML'],['Where results are stored',STATUS.runs_dir+'/results.db']]));
}
function viewIntegrations(){
  const v=$('#view'); v.replaceChildren();
  v.append(el('div',{class:'runban'},el('b',{text:'Planned next.'}),' This page shows how the GitHub Action will be set up. Until then, export SARIF from the Scan history page and upload it to GitHub code scanning.'));
  const yaml=['name: LLM SAST triage','on: [pull_request]','jobs:','  triage:','    runs-on: ubuntu-latest','    permissions:','      security-events: write','    steps:','      - uses: actions/checkout@v4','      - uses: zainab-nooh/llm-sast-triage@v1','        with:','          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}','          changed-files-only: true'];
  const code=el('div',{class:'code'},...yaml.map((l,k)=>el('div',{class:'ln'},el('span',{class:'n',text:k+1}),el('span',{class:'m'}),el('span',{text:l}))));
  v.append(el('div',{class:'g g-11'},
    el('div',{class:'panel'},el('div',{class:'ph'},el('h2',{text:'Check every pull request'})),el('div',{class:'pb',style:'display:grid;gap:12px'},
      el('div',{style:'color:var(--muted);max-width:65ch',text:'Add this file as .github/workflows/triage.yml. Each repository owner stores their own API key as a GitHub secret, so nobody shares a key and no code goes to a server of ours.'}),code)),
    kvPanel('What appears on GitHub',[['Code scanning (SARIF)','Alerts on the changed lines, with the AI verdict and fix'],['Auto-ignored alerts','Uploaded as dismissed, with the AI reason'],['Pull request check','Fails when a confirmed critical or high issue is added']])));
}

/* ---------------- public read-only demo ---------------- */
const REPO='https://github.com/zainab-nooh/llm-sast-triage';
function demoNote(){
  return el('div',{class:'demonote'},
    el('div',{},el('b',{text:'Online demo: the demo model only. '}),el('span',{text:'It runs the real scanners (Semgrep and Bandit) and the full pipeline, but the AI step is replaced by a few fixed rules, so its verdicts are only an example. Scans are shared with other visitors and limited to small public repositories, one at a time. The full app also runs Claude Haiku 5.5, Claude Sonnet 5.5 or a local Qwen model, on your own folders.'})),
    el('a',{class:'go',href:REPO,target:'_blank',rel:'noopener noreferrer'},'Get it on GitHub'));
}
function setDemo(){
  if(document.documentElement.classList.contains('demo')) return;
  document.documentElement.classList.add('demo');
  const b=el('div',{class:'demobar'},el('b',{text:'Online demo.'}),el('span',{text:' Sample results from public projects. Scans use the demo model, and saving decisions is off.'}),
    el('a',{href:REPO,target:'_blank',rel:'noopener noreferrer',text:'Get the app on GitHub'}));
  $('.main').prepend(b);
  const foot=$('.nav-foot'); if(foot&&foot.children[1]) foot.children[1].replaceChildren(el('span',{class:'dot'}),'Public demo, read-only');
}

/* ---------------- routing: every page has its own link (#dashboard, #issues, #issue/<id>, ...) ---------------- */
const PAGES={dashboard:['Overview','Dashboard',viewDash],report:['Overview','OWASP Top 10',viewOwasp],issues:['Triage','Triage inbox',viewInbox],review:['Triage','Needs your review',viewInbox],
  decisions:['Triage','Your decisions',viewDecisions],newscan:['Scans','New scan',viewNewScan],projects:['Scans','Projects',viewProjects],scans:['Scans','Scan history',viewScans],
  compare:['Scans','Compare scans',viewCompare],config:['Setup','Models & settings',viewConfig],integrations:['Setup','GitHub',viewIntegrations]};
const NEEDS_DATA=['dashboard','report','issues','review','projects','decisions'];
const MNAV=[['dashboard','Dashboard'],['issues','Inbox'],['review','Needs review'],['decisions','Decisions'],['newscan','New scan'],['projects','Projects'],['scans','Scans'],['compare','Compare'],['report','OWASP'],['config','Settings'],['integrations','GitHub']];
function setTitle(crumb,title){ $('#crumb').textContent=crumb; $('#title').textContent=title; document.title=title+' · SAST Triage'; }
function navOn(page){
  document.querySelectorAll('.nav a[data-v]').forEach(a=>a.classList.toggle('on',a.dataset.v===page));
  const m=$('#mnav'); m.replaceChildren(...MNAV.map(([k,t])=>el('button',{type:'button',class:k===page?'on':'',onclick:()=>go(k)},t)));
  const on=m.querySelector('.on'); if(on) m.scrollLeft=on.offsetLeft-m.offsetLeft-(m.clientWidth-on.offsetWidth)/2;
}
function go(v, force){ const h='#'+v; if(location.hash!==h) location.hash=h; else if(force) route(); }
function route(){
  if(!STATUS||LOADING) return;
  const h=decodeURIComponent((location.hash||'#dashboard').slice(1));
  if(h.startsWith('issue/')){ const id=h.slice(6), a=A.find(x=>x.id===id); S.view='issue'; navOn(BACK||'issues');
    if(a){ const list=CUR&&CUR.list.some(x=>x.id===id)?CUR.list.map(x=>A.find(y=>y.id===x.id)).filter(Boolean):F({ignoreGrp:true}); openIssue(a,list.includes(a)?list:[a],true); }
    else { setTitle('Triage','Issue'); renderBar(); $('#view').replaceChildren(el('div',{class:'panel'},el('div',{class:'empty'},'This alert is not in the scans shown now. Open its scan from ',el('button',{class:'lnk',type:'button',onclick:()=>go('scans')},'Scan history'),'.'))); }
    return; }
  const page=PAGES[h]?h:'dashboard';
  if(page==='review'&&S.view!=='review'){ S.ib.tab='Review'; S.ib.id=null; }
  if(page==='issues'&&S.view==='review'&&S.ib.tab==='Review'&&!A.some(a=>a.g==='Review'&&!a.mine)) S.ib.tab='Confirmed';
  if(page!=='issue') CUR=null;
  S.view=page; setTitle(PAGES[page][0],PAGES[page][1]); navOn(page); render();
}
function render(){
  if(!STATUS) return;
  if(S.view==='issue'){ if(CUR) openIssue(CUR.a,CUR.list,true); drawCounts(); return; }
  renderBar(); const v=$('#view');
  if(NEEDS_DATA.includes(S.view)&&!A.length&&!S.run) emptyState(v); else PAGES[S.view][2]();
  drawCounts(); drawRunBox();
}
function drawCounts(){ $('#navCount').textContent=A.filter(open).length; $('#navReview').textContent=A.filter(a=>a.g==='Review'&&!a.mine).length; $('#navMine').textContent=A.filter(a=>a.mine).length; }
let LOADING=false;
function showLoading(){ $('#view').replaceChildren(el('div',{class:'panel'},el('div',{class:'empty'},el('span',{class:'prog indet',style:'max-width:220px;margin:0 auto 10px;display:block'},el('span')),'Loading…'))); }
function noToken(){
  $('#view').replaceChildren(el('div',{class:'panel'},el('div',{class:'pb welcome'},el('h2',{text:'Open the app from its start link'}),
    el('p',{text:'For safety, this app only answers requests that carry the session key from the link printed in the terminal when you ran "python -m codereview serve". Open that link again (it starts with http://127.0.0.1).'}))));
}

/* ---------------- live updates: one small request every few seconds; redraw only when something changed ---------------- */
const LIVE={sig:'',at:0,pending:false};
const runSig = runs => runs.map(r=>r.id+':'+r.alerts+':'+(r.partial||'')).join(',');
function liveSig(runs, jobs){ return runSig(runs)+'|'+jobs.map(j=>j.id+':'+j.state).join(','); }
function canRender(){ const f=document.activeElement; return !$('#layer').children.length&&!(f&&f.closest&&f.closest('#view')&&f.matches('input,textarea,select'))&&!['newscan','compare'].includes(S.view); }
async function reloadLive(force){
  const ids=CUR?{a:CUR.a.id,list:CUR.list.map(x=>x.id)}:null;
  try{ await load(); }catch(e){ return; }
  if(ids&&CUR){ CUR.a=A.find(x=>x.id===ids.a)||CUR.a; CUR.list=ids.list.map(id=>A.find(x=>x.id===id)).filter(Boolean); if(!CUR.list.includes(CUR.a)) CUR.list=[CUR.a]; }
  if(force||canRender()){ LIVE.pending=false; render(); } else LIVE.pending=true;
  const l=$('#live'); l.classList.add('flash'); setTimeout(()=>l.classList.remove('flash'),2500);
}
async function liveTick(){
  if(document.hidden||!STATUS||LOADING) return;
  try{ const [runs,jobs]=await Promise.all([api('/api/runs'),api('/api/scans')]);
    const changed=runSig(runs)!==runSig(RUNS); JOBS=jobs; drawRunBox(); LIVE.at=Date.now();
    if(changed) await reloadLive(); else if(LIVE.pending&&canRender()){ LIVE.pending=false; render(); }
  }catch(e){}
  drawLive();
}
function drawLive(){ const s=Math.round((Date.now()-LIVE.at)/1000); $('#liveTxt').textContent='Live · updated '+(s<10?'just now':s<90?s+' s ago':Math.round(s/60)+' min ago'); }

/* ---------------- header: search, light / dark, new scan ---------------- */
$('#gsearch').addEventListener('keydown',e=>{ if(e.key!=='Enter') return; const q=e.target.value.trim().toLowerCase(); if(!q) return;
  const hits=A.filter(a=>[a.file,a.cwe,CWE[a.cwe][0],RULE[a.cwe]||'',a.rule_full,a.title,a.p,a.msg].join(' ').toLowerCase().includes(q)); drill(`Search: ${e.target.value.trim()}`,hits); });
try{ const t=localStorage.getItem('theme'); document.documentElement.dataset.theme=t||(matchMedia('(prefers-color-scheme: dark)').matches?'dark':'light'); }catch(e){ document.documentElement.dataset.theme='light'; }
const isDark=()=>document.documentElement.dataset.theme==='dark';
const drawTheme=()=>{ const b=$('#appTheme'); b.textContent=isDark()?'Light':'Dark'; b.setAttribute('aria-label',isDark()?'Switch to light mode':'Switch to dark mode'); };
$('#appTheme').addEventListener('click',()=>{ const t=isDark()?'light':'dark'; document.documentElement.dataset.theme=t; try{localStorage.setItem('theme',t);}catch(e){} drawTheme(); });
drawTheme();
$('#newScan').addEventListener('click',()=>{ if(STATUS) openScan(NS.job&&ACTIVE(NS.job.state)?null:''); });
document.querySelectorAll('.nav a[data-v]').forEach(a=>a.addEventListener('click',e=>{ e.preventDefault(); if(a.dataset.v==='newscan') $('#newScan').click(); else go(a.dataset.v,true); }));
addEventListener('hashchange',()=>{ $('#layer').replaceChildren(); tip.hidden=true; route(); window.scrollTo(0,0); });
let rw=innerWidth<760; addEventListener('resize',()=>{ const n=innerWidth<760; if(n!==rw){ rw=n; if(canRender()) render(); } });

async function boot(){
  showLoading(); LOADING=true;
  try{ await load(); }catch(e){ LOADING=false; if(e.message!=='no token') $('#view').replaceChildren(el('div',{class:'panel'},el('div',{class:'empty',text:e.message}))); return; }
  LOADING=false; route();
  setInterval(liveTick,5000); setInterval(drawLive,10000);
}
boot();   // a normal install answers 401 without the token, which shows the start-link message; the public demo needs no token

/* SAST Triage web app. Talks only to the local server (/api/...), with this session's token in every request.
   Security rule for this file: code, file names, scanner and AI text are untrusted, so they are only ever put
   on the page with textContent (the el() helper below), never with innerHTML. */
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
  } catch(e) { if (e.message !== 'no token') toast(e.message); }
}

/* ---------------- data ---------------- */
let STATUS = null, RUNS = [], ISSUES = [], JOBS = [];
let CWE = {};                      // filled from /api/status
const SEV_ORDER = {critical:0, high:1, medium:2, low:3};
const GROUP_ORDER = {Confirmed:0, 'Needs review':1, Hidden:2};
const STATUS_PILL = {Confirmed:{cls:'confirmed', label:'Confirmed by AI'}, 'Needs review':{cls:'review', label:'Needs review'}, Hidden:{cls:'ignored', label:'Auto-ignored'}};
const MODEL_NAMES = {'claude-haiku-5-5':'Claude Haiku 5.5', 'claude-sonnet-5-5':'Claude Sonnet 5.5', 'qwen3:14b':'Qwen3 14B (local)', 'mock':'Demo model', 'scanner only':'Scanner only'};
const state = {status:'open', sev:'all', project:'all', cwe:'all', q:'', page:0, sel:null, run:null};

async function load(){
  const runParam = state.run ? '?run=' + encodeURIComponent(state.run) : '';
  [STATUS, RUNS, ISSUES, JOBS] = await Promise.all([api('/api/status'), api('/api/runs'), api('/api/issues' + runParam), api('/api/scans')]);
  CWE = STATUS.cwes;
  ISSUES.forEach(i => { i.title = titleOf(i); });
  const m = STATUS.models.claude.model;
  $('#footModel').textContent = STATUS.anthropic_key ? 'Model: ' + (MODEL_NAMES[m] || m) : 'No Claude API key yet';
}
function titleOf(i){
  const src = ((i.code || []).find(c => c[0] === i.line) || [0, ''])[1];
  const t = {'CWE-502': /dumps?\(/.test(src) ? 'pickle used to write data' : 'Untrusted data passed to a deserializer', 'CWE-95':'Dynamic code run with eval() or exec()',
    'CWE-78':'Process started from program input', 'CWE-89':'SQL statement built from strings', 'CWE-611':'XML parsed with external entities', 'CWE-614':'Cookie sent without Secure flag'};
  return t[i.cwe] || i.rule || i.cwe;
}
const cweName = c => (CWE[c] && CWE[c].name) || c;
const reviewOf = i => i.review && i.review.label ? i.review : null;
const isOpen = i => i.group !== 'Hidden' && !(reviewOf(i) && reviewOf(i).label === 'fp');
const needsReview = i => i.group === 'Needs review' && !reviewOf(i);

/* ---------------- small DOM helpers ---------------- */
const $ = (s, r=document) => r.querySelector(s);
function el(tag, attrs={}, ...kids){ const e=document.createElement(tag); for(const [k,v] of Object.entries(attrs)){ if(k==='class') e.className=v; else if(k==='text') e.textContent=v; else if(k.startsWith('on')) e.addEventListener(k.slice(2),v); else if(v!==null&&v!==undefined&&v!==false) e.setAttribute(k,v===true?'':v);} for(const k of kids.flat()){ if(k===null||k===undefined||k===false) continue; e.append(k instanceof Node?k:document.createTextNode(String(k))); } return e; }
const svgNS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs={}){ const e=document.createElementNS(svgNS,tag); for(const [k,v] of Object.entries(attrs)) e.setAttribute(k,v); return e; }
function toast(msg){ const t=el('div',{class:'toast',role:'status',text:msg}); document.body.append(t); setTimeout(()=>t.remove(),2600); }
function sevBadge(s){ return el('span',{class:'sev '+s,text:s[0].toUpperCase()+s.slice(1)}); }
function statusPill(i){ const d=reviewOf(i); if(d&&d.label!=='unsure') return el('span',{class:'pill human',text:d.label==='real'?'You: real issue':'You: false positive'}); const s=STATUS_PILL[i.group]; return el('span',{class:'pill '+s.cls,text:s.label}); }
function setTitle(crumb,title){ $('#crumb').textContent=crumb; $('#pageTitle').textContent=title; }
const when = s => s ? s.replace('T',' ').slice(0,16) : '';
const mins = s => s < 90 ? Math.round(s) + ' s' : Math.round(s/60) + ' min';
const money = c => c ? '$' + (c < 0.01 ? c.toFixed(4) : c.toFixed(2)) : '$0';
function panel(title, sub, body, extra){ return el('div',{class:'panel'},el('div',{class:'panel-h'},el('h2',{text:title}),sub?el('span',{class:'sub',text:sub}):null,el('div',{class:'spacer'}),extra||null),body); }
function runBanner(){
  if(!state.run) return null;
  const r = RUNS.find(x => x.id === state.run);
  return el('div',{class:'preview-note'},el('b',{text:'Showing one scan: '}),`${r ? r.project : ''} · run ${state.run}. `,
    el('button',{class:'btn small',type:'button',onclick:async()=>{state.run=null; await refresh();}},'Show latest scan of every project'));
}
function emptyState(v){
  v.append(el('div',{class:'panel'},el('div',{class:'panel-b welcome'},
    el('h2',{text:'No scans yet'}),
    el('p',{text:'Pick a folder of Python code. Semgrep and Bandit look for six kinds of security weakness, then the AI checks each alert and hides only the ones it is confident are false alarms. Everything else is kept for you.'}),
    el('button',{class:'btn primary',type:'button',onclick:()=>openScan('')},'Start your first scan'))));
}

/* ---------------- Dashboard ---------------- */
function viewDashboard(){
  setTitle('Workspace','Dashboard');
  const v=$('#view'); v.replaceChildren();
  if(!ISSUES.length && !state.run){ emptyState(v); return; }
  const b=runBanner(); if(b) v.append(b);
  const open=ISSUES.filter(isOpen), crit=open.filter(i=>i.sev==='critical'), hidden=ISSUES.filter(i=>i.group==='Hidden');
  const projects=[...new Set(ISSUES.map(i=>i.project))];
  const reviewed=ISSUES.filter(reviewOf).length;
  const kpi=(label,value,foot)=>el('div',{class:'panel kpi'},el('div',{class:'label',text:label}),el('div',{class:'value',text:value}),el('div',{class:'foot'},...foot));
  v.append(el('div',{class:'kpis'},
    kpi('Open issues',open.length,[`${crit.length} critical · ${open.length-crit.length} other`]),
    kpi('Needs your review',ISSUES.filter(needsReview).length,['The AI was not sure, so a person decides']),
    kpi('Noise removed by AI',ISSUES.length?Math.round(hidden.length/ISSUES.length*100)+'%':'0%',[`${hidden.length} of ${ISSUES.length} alerts auto-ignored in ${projects.length} project${projects.length===1?'':'s'}`]),
    kpi('Your decisions',reviewed,[`of ${ISSUES.length} alerts have a decision from you`])));

  // alerts per project
  const per={}; ISSUES.forEach(i=>{ per[i.project]=per[i.project]||{alerts:0,hidden:0}; per[i.project].alerts++; if(i.group==='Hidden') per[i.project].hidden++; });
  const rows=Object.entries(per).sort((a,b)=>b[1].alerts-a[1].alerts);
  const max=Math.max(...rows.map(r=>r[1].alerts));
  const bars=el('div',{class:'hbars'});
  rows.forEach(([name,p])=>{ const kept=p.alerts-p.hidden;
    bars.append(el('div',{class:'hbar'},el('div',{class:'name',title:name,text:name}),el('div',{},el('div',{class:'track',style:`width:${Math.max(6,p.alerts/max*100)}%`},
      el('span',{style:`width:${kept/p.alerts*100}%;background:var(--accent)`,title:`${kept} kept`}),el('span',{style:`width:${p.hidden/p.alerts*100}%;background:var(--line-strong)`,title:`${p.hidden} auto-ignored`}))),
      el('div',{class:'num',text:`${p.hidden} of ${p.alerts}`})));});
  const noise=panel('Alerts per project','kept for people vs auto-ignored by the AI',el('div',{class:'panel-b'},bars),
    el('div',{class:'legend'},el('span',{},el('i',{style:'background:var(--accent)'}),'Kept'),el('span',{},el('i',{style:'background:var(--line-strong)'}),'Auto-ignored')));

  // donut
  const counts={Confirmed:0,'Needs review':0,Hidden:0}; ISSUES.forEach(i=>counts[i.group]++);
  const cols={Confirmed:'var(--crit)','Needs review':'var(--warn)',Hidden:'var(--line-strong)'};
  const d=svg('svg',{viewBox:'0 0 120 120',role:'img','aria-label':'AI triage outcome'}); let a0=0; const R=46,C=2*Math.PI*R;
  d.append(svg('circle',{cx:60,cy:60,r:R,fill:'none',stroke:'var(--muted-soft)','stroke-width':16}));
  Object.entries(counts).forEach(([k,n])=>{ if(!n) return; const len=n/ISSUES.length*C; d.append(svg('circle',{cx:60,cy:60,r:R,fill:'none',stroke:cols[k],'stroke-width':16,'stroke-dasharray':`${len} ${C-len}`,'stroke-dashoffset':-a0,transform:'rotate(-90 60 60)'})); a0+=len; });
  const tc=svg('text',{x:60,y:58,'text-anchor':'middle','font-size':22,'font-weight':600,fill:'var(--ink)','font-family':'var(--serif)'}); tc.textContent=ISSUES.length; d.append(tc);
  const tl=svg('text',{x:60,y:75,'text-anchor':'middle','font-size':9,fill:'var(--muted)'}); tl.textContent='alerts'; d.append(tl);
  const dl=el('div',{class:'dl'}); Object.entries(counts).forEach(([k,n])=>dl.append(el('div',{},el('i',{style:`background:${cols[k]}`}),el('span',{text:STATUS_PILL[k].label}),el('b',{text:n}))));
  const donut=panel('AI triage outcome',state.run?'this scan':'latest scan of each project',el('div',{class:'panel-b'},el('div',{class:'donut-wrap'},d,dl)));
  v.append(el('div',{class:'grid-2'},noise,donut));

  // start here + by type + trust
  const queue=el('div',{class:'list'});
  const first=ISSUES.filter(i=>isOpen(i)&&!reviewOf(i)).sort((a,b)=>SEV_ORDER[a.sev]-SEV_ORDER[b.sev]||GROUP_ORDER[a.group]-GROUP_ORDER[b.group]||(b.conf||0)-(a.conf||0)).slice(0,6);
  first.forEach(i=>queue.append(el('div',{class:'list-row',tabindex:0,onclick:()=>openIssue(i.id),onkeydown:e=>{if(e.key==='Enter')openIssue(i.id)}},sevBadge(i.sev),
      el('div',{style:'min-width:0'},el('div',{class:'t',text:i.title}),el('div',{class:'s',text:`${i.project} · ${i.file}:${i.line}`})),statusPill(i))));
  if(!first.length) queue.append(el('div',{class:'empty',text:'Nothing open is waiting for you.'}));
  const qp=panel('Start here','most severe first',queue,el('a',{href:'#issues',class:'btn small',text:'View all'}));

  const byType={}; ISSUES.forEach(i=>{byType[i.cwe]=byType[i.cwe]||{open:0,ign:0}; isOpen(i)?byType[i.cwe].open++:byType[i.cwe].ign++;});
  const tb=el('div',{class:'hbars'}); const mx=Math.max(...Object.values(byType).map(x=>x.open+x.ign));
  Object.entries(byType).sort((a,b)=>(b[1].open+b[1].ign)-(a[1].open+a[1].ign)).forEach(([c,x])=>{ const t=x.open+x.ign;
    tb.append(el('div',{class:'hbar'},el('div',{class:'name',title:`${c} · ${(CWE[c]||{}).owasp||''}`,text:cweName(c).replace('Unsafe ','')}),el('div',{},el('div',{class:'track',style:`width:${Math.max(6,t/mx*100)}%`},el('span',{style:`width:${x.open/t*100}%;background:var(--accent)`}),el('span',{style:`width:${x.ign/t*100}%;background:var(--line-strong)`}))),el('div',{class:'num',text:`${x.open} open`})));});
  const tp=panel('By weakness type',null,el('div',{class:'panel-b'},tb),el('a',{href:'#report',class:'btn small',text:'OWASP view'}));

  const checked=hidden.filter(reviewOf), agree=checked.filter(i=>reviewOf(i).label==='fp');
  const trust=panel('Can I trust the auto-ignore?',null,el('div',{class:'panel-b trust'},
    checked.length?el('div',{},el('div',{class:'big',text:`${agree.length} of ${checked.length}`}),el('div',{class:'foot',style:'color:var(--muted);font-size:13px',text:'auto-ignored alerts you checked were really false alarms'}))
      :el('div',{style:'font-size:13px;color:var(--muted)',text:`You have not checked any of the ${hidden.length} auto-ignored alerts yet. Open a few and record your decision.`}),
    checked.length?el('div',{class:'meter'},el('span',{style:`width:${agree.length/checked.length*100}%`})):null,
    el('div',{style:'font-size:13px;color:var(--muted)',text:'An alert is only ignored when the AI is confident and the lines it cites exist. In the evaluation on 7 real projects, all 59 auto-ignored alerts were checked by hand and were correct.'}),
    el('a',{href:'#issues',class:'btn small',onclick:()=>{state.status='ignored';state.page=0;},text:'Review ignored alerts'})));
  v.append(el('div',{class:'grid-3'},qp,tp,trust));
}

/* ---------------- Issues ---------------- */
function filtered(){
  const q=state.q.trim().toLowerCase();
  return ISSUES.filter(i=>{
    if(state.status==='open'&&!isOpen(i)) return false;
    if(state.status==='review'&&!needsReview(i)) return false;
    if(state.status==='ignored'&&i.group!=='Hidden') return false;
    if(state.sev!=='all'&&i.sev!==state.sev) return false;
    if(state.project!=='all'&&i.project!==state.project) return false;
    if(state.cwe!=='all'&&i.cwe!==state.cwe) return false;
    if(q&&!(`${i.file} ${i.rule} ${i.title} ${i.cwe} ${cweName(i.cwe)} ${i.project}`.toLowerCase().includes(q))) return false;
    return true;
  }).sort((a,b)=>SEV_ORDER[a.sev]-SEV_ORDER[b.sev]||GROUP_ORDER[a.group]-GROUP_ORDER[b.group]||(b.conf||0)-(a.conf||0)||a.file.localeCompare(b.file)||a.line-b.line);
}
function exportRun(){
  if(state.run) return state.run;
  const runs=[...new Set(ISSUES.filter(i=>state.project==='all'||i.project===state.project).map(i=>i.run))];
  return runs.length===1?runs[0]:null;
}
function viewIssues(){
  setTitle('Workspace','Issues');
  const v=$('#view'); v.replaceChildren();
  if(!ISSUES.length && !state.run){ emptyState(v); return; }
  const b=runBanner(); if(b) v.append(b);
  const cnt=f=>ISSUES.filter(f).length;
  const chips=[['open','Open',cnt(isOpen)],['review','Needs review',cnt(needsReview)],['ignored','Auto-ignored',cnt(i=>i.group==='Hidden')],['all','All',ISSUES.length]];
  const bar=el('div',{class:'filters'});
  chips.forEach(([k,l,n])=>bar.append(el('button',{type:'button',class:'chip'+(state.status===k?' on':''),onclick:()=>{state.status=k;state.page=0;viewIssues();}},l,el('span',{class:'n',text:n}))));
  bar.append(el('span',{style:'flex:1'}));
  const sel=(id,label,opts,key)=>{ const s=el('select',{class:'sel',id,'aria-label':label,onchange:e=>{state[key]=e.target.value;state.page=0;viewIssues();}}); opts.forEach(([val,txt])=>{const o=el('option',{value:val,text:txt}); if(state[key]===val) o.selected=true; s.append(o);}); return s; };
  bar.append(sel('fSev','Severity',[['all','All severities'],['critical','Critical'],['high','High'],['medium','Medium']],'sev'));
  bar.append(sel('fProj','Project',[['all','All projects'],...[...new Set(ISSUES.map(i=>i.project))].sort().map(p=>[p,p])],'project'));
  bar.append(sel('fCwe','Weakness type',[['all','All types'],...[...new Set(ISSUES.map(i=>i.cwe))].sort().map(c=>[c,cweName(c)])],'cwe'));
  const rows=filtered(), per=25, pages=Math.max(1,Math.ceil(rows.length/per)); state.page=Math.min(state.page,pages-1);
  const tbody=el('tbody');
  rows.slice(state.page*per,(state.page+1)*per).forEach(i=>{
    tbody.append(el('tr',{class:state.sel===i.id?'sel':'',tabindex:0,onclick:()=>openIssue(i.id),onkeydown:e=>{if(e.key==='Enter')openIssue(i.id)}},
      el('td',{},sevBadge(i.sev)),
      el('td',{},el('div',{class:'title-cell'},el('b',{text:i.title}),el('span',{text:`${i.file}:${i.line}`}))),
      el('td',{},el('span',{class:'tag',text:i.cwe})),
      el('td',{text:i.project}),
      el('td',{},statusPill(i)),
      el('td',{},i.conf==null?el('span',{style:'color:var(--faint)',text:'not judged'}):el('div',{class:'conf'},el('div',{class:'meter'},el('span',{style:`width:${i.conf*100}%`})),el('span',{text:i.conf.toFixed(2)})))));});
  const table=rows.length?el('div',{class:'table-wrap'},el('table',{},el('thead',{},el('tr',{},...['Severity','Issue','Type','Project','Status','AI confidence'].map(h=>el('th',{text:h})))),tbody))
    :el('div',{class:'empty',text:'No issues match these filters.'});
  const pager=el('div',{class:'pager'},el('span',{text:`${rows.length} issues · page ${state.page+1} of ${pages}`}),el('span',{style:'flex:1'}),
    el('button',{class:'btn small',type:'button',disabled:state.page===0,onclick:()=>{state.page--;viewIssues();}},'Previous'),
    el('button',{class:'btn small',type:'button',disabled:state.page>=pages-1,onclick:()=>{state.page++;viewIssues();}},'Next'));
  const er=exportRun(); const tip=er?null:'Pick one project first: exports are made per scan';
  const exp=el('div',{class:'panel-h'},el('h2',{text:'Issues'}),el('span',{class:'sub',text:'most severe first'}),el('div',{class:'spacer'}),
    el('button',{class:'btn small',type:'button',disabled:!er,title:tip,onclick:()=>download(`/api/runs/${er}/export.csv`)},'Export CSV'),
    el('button',{class:'btn small',type:'button',disabled:!er,title:tip,onclick:()=>download(`/api/runs/${er}/export.sarif`)},'Export SARIF'));
  v.append(el('div',{class:'panel'},exp,bar,table,pager));
}
function codeBlock(i){
  const box=el('div',{class:'code'}); const inner=el('div',{class:'pad'}); box.append(inner);
  let prev=null;
  (i.code||[]).forEach(([n,t])=>{ if(prev!==null&&n>prev+1) inner.append(el('div',{class:'gap',text:`${n-prev-1} line${n-prev-1>1?'s':''} not shown to the AI`}));
    const hl=n>=i.line&&n<=i.end; inner.append(el('div',{class:'ln'+(hl?' hl':'')},el('span',{class:'m',text:hl?'▶':''}),el('span',{class:'n',text:n}),el('span',{text:t}))); prev=n; });
  if(!(i.code||[]).length) inner.append(el('div',{class:'gap',text:'No code was sent to the AI for this alert.'}));
  let pf=null;
  (i.helpers||[]).forEach(([f,n,t])=>{ if(f!==pf){ inner.append(el('div',{class:'gap',text:`helper code from ${f}`})); pf=f; } inner.append(el('div',{class:'ln'},el('span',{class:'m'}),el('span',{class:'n',text:n}),el('span',{text:t}))); });
  return box;
}
function yesNo(val, yes, no){ return val==null?'not judged':(val?yes:no); }
function openIssue(id){
  const i=ISSUES.find(x=>x.id===id); if(!i) return;
  state.sel=id; const layer=$('#layer'); layer.replaceChildren();
  const close=()=>{layer.replaceChildren(); state.sel=null; document.removeEventListener('keydown',esc); route();};
  const esc=e=>{if(e.key==='Escape')close();}; document.addEventListener('keydown',esc);
  let tab='overview';
  const body=el('div',{class:'drawer-b'});
  const tabs=el('div',{class:'tabs',role:'tablist'});
  const draw=()=>{ body.replaceChildren(); tabs.querySelectorAll('button').forEach(b=>b.classList.toggle('on',b.dataset.t===tab));
    if(tab==='overview'){
      body.append(el('div',{class:'facts'},
        el('div',{class:'fact'},el('span',{text:'AI verdict'}),el('b',{text:i.verdict?i.verdict.replace(/_/g,' '):'not judged'})),
        el('div',{class:'fact'},el('span',{text:'Confidence'}),el('b',{text:i.conf==null?'n/a':i.conf.toFixed(2)})),
        el('div',{class:'fact'},el('span',{text:'Found by'}),el('b',{text:i.tool})),
        el('div',{class:'fact'},el('span',{text:'Policy rule'}),el('b',{text:i.policy||(CWE[i.cwe]||{}).rule||'none'}))));
      if(i.verdict) body.append(el('div',{class:'sect'},el('h4',{text:'Exploitability'}),el('div',{class:'exploit'},
        el('div',{class:i.feasible?'bad':'good'},el('span',{text:'Can an attacker reach it?'}),el('b',{text:yesNo(i.feasible,'Yes, plausibly','No')})),
        el('div',{class:i.sanitized?'good':'bad'},el('span',{text:'Input checked or cleaned first?'}),el('b',{text:yesNo(i.sanitized,'Yes','No')})),
        el('div',{class:i.verified?'good':'bad'},el('span',{text:'Cited lines exist?'}),el('b',{text:i.verified?'Yes, checked':'No'})))));
      body.append(el('div',{class:'sect'},el('h4',{text:i.group==='Hidden'?'Why it was auto-ignored':'Why it was kept'}),el('p',{text:i.decision})));
      body.append(el('div',{class:'sect'},el('h4',{text:'Why the AI decided this'}),el('p',{text:i.reason||'This alert has no AI reasoning.'})));
      if(i.evidence.length){ const ev=el('div',{class:'ev'}); i.evidence.forEach(([l,w])=>ev.append(el('div',{},el('span',{class:'tag',text:'lines '+l.split(':').pop()}),el('span',{text:w})))); body.append(el('div',{class:'sect'},el('h4',{text:'Evidence the AI cited'}),ev)); }
      if(i.fix) body.append(el('div',{class:'sect'},el('h4',{text:'Suggested fix'}),el('p',{text:i.fix})));
      body.append(el('div',{class:'sect'},el('h4',{text:'Code the AI saw'}),codeBlock(i)));
    } else if(tab==='code'){ body.append(el('div',{class:'sect'},el('h4',{text:`${i.file} · ▶ marks line ${i.line}`}),i.note?el('p',{style:'color:var(--muted)',text:i.note}):null,codeBlock(i)));
    } else { const c=CWE[i.cwe]||{};
      body.append(el('div',{class:'sect'},el('h4',{text:'Scanner message'}),el('p',{text:i.msg||'none'})),
        el('div',{class:'kv'},el('span',{text:'Scanner'}),el('b',{text:i.tool}),el('span',{text:'Rule id'}),el('b',{text:i.rule_full}),
          i.also.length?el('span',{text:'Also reported by'}):null,i.also.length?el('b',{text:i.also.join(', ')}):null,
          el('span',{text:'Weakness'}),el('b',{text:`${i.cwe} ${cweName(i.cwe)}`}),el('span',{text:'OWASP Top 10'}),el('b',{text:c.owasp||'not mapped'}),
          el('span',{text:'Scan'}),el('b',{text:`${i.project} · run ${i.run}`}))); }
  };
  [['overview','Overview'],['code','Code'],['scanner','Scanner details']].forEach(([k,l])=>tabs.append(el('button',{type:'button',role:'tab','data-t':k,onclick:()=>{tab=k;draw();}},l)));
  const d={label:(reviewOf(i)||{}).label||null,note:(i.review||{}).note||''};
  const opts=el('div',{class:'opts'});
  const mk=(k,l)=>el('button',{type:'button',class:'opt '+k+(d.label===k?' on':''),onclick:e=>{d.label=k; opts.querySelectorAll('.opt').forEach(b=>b.classList.remove('on')); e.currentTarget.classList.add('on');}},l);
  opts.append(mk('real','Real vulnerability'),mk('fp','False positive'),mk('unsure','Not sure'));
  const note=el('textarea',{id:'note','aria-label':'Note',maxlength:2000,placeholder:'Note for your team (optional)'}); note.value=d.note;
  const save=el('button',{class:'btn primary',type:'button',onclick:async()=>{ if(!d.label){toast('Pick a decision first');return;}
      save.disabled=true;
      try{ await api('/api/reviews',{method:'POST',body:{run:i.run,fid:i.fid,label:d.label,note:note.value}}); i.review={label:d.label,note:note.value}; toast('Decision saved'); close(); }
      catch(e){ save.disabled=false; if(e.message!=='no token') toast(e.message); } }},'Save decision');
  const decide=el('div',{class:'decide'},el('div',{style:'font-weight:700;color:var(--ink)',text:'Your decision'}),
    el('div',{style:'font-size:12.5px;color:var(--muted)',text:'Saved with this scan and kept apart from the AI verdict, so the audit trail shows both.'}),opts,note,
    el('div',{style:'display:flex;gap:8px;justify-content:flex-end'},el('button',{class:'btn',type:'button',onclick:close},'Close'),save));
  const head=el('div',{class:'drawer-h'},el('div',{class:'row'},sevBadge(i.sev),statusPill(i),el('span',{class:'tag',text:i.cwe}),
      el('button',{class:'x',type:'button','aria-label':'Close',onclick:close},'×')),el('h3',{text:i.title}),el('div',{class:'loc',text:`${i.project} · ${i.file}:${i.line}`}));
  layer.append(el('div',{class:'scrim',onclick:close}),el('aside',{class:'drawer',role:'dialog','aria-label':'Issue details'},head,tabs,body,decide));
  draw();
}

/* ---------------- OWASP / CWE report ---------------- */
function viewReport(){
  setTitle('Workspace','OWASP Top 10 view');
  const v=$('#view'); v.replaceChildren();
  if(!ISSUES.length && !state.run){ emptyState(v); return; }
  const b=runBanner(); if(b) v.append(b);
  const cats={};
  ISSUES.forEach(i=>{ const o=(CWE[i.cwe]||{}).owasp||'Not mapped'; cats[o]=cats[o]||{}; cats[o][i.cwe]=cats[o][i.cwe]||{open:0,review:0,ign:0,total:0};
    const x=cats[o][i.cwe]; x.total++; if(i.group==='Hidden') x.ign++; else if(needsReview(i)) x.review++; if(isOpen(i)) x.open++; });
  const t=el('tbody');
  Object.keys(cats).sort().forEach(o=>Object.entries(cats[o]).forEach(([c,x],k)=>t.append(el('tr',{},
    el('td',{text:k===0?o:''}),el('td',{},el('span',{class:'tag',text:c}),' ',cweName(c)),el('td',{text:(CWE[c]||{}).rule||'none'}),
    el('td',{text:x.total}),el('td',{text:x.open}),el('td',{text:x.review}),el('td',{text:x.ign})))));
  v.append(panel('Issues by OWASP Top 10:2025 category and CWE','from the policy file (policy/policy.yaml)',
    el('div',{class:'table-wrap'},el('table',{},el('thead',{},el('tr',{},...['OWASP category','Weakness (CWE)','Policy rule','Alerts','Open','Needs review','Auto-ignored'].map(h=>el('th',{text:h})))),t))));
}

/* ---------------- Projects ---------------- */
function viewProjects(){
  setTitle('Workspace','Projects');
  const v=$('#view'); v.replaceChildren();
  const latest=RUNS.filter(r=>r.latest);
  if(!latest.length){ emptyState(v); return; }
  const g=el('div',{class:'grid-3'});
  latest.forEach(r=>{ const its=ISSUES.filter(i=>i.run===r.id); const c={Confirmed:0,'Needs review':0,Hidden:0}; its.forEach(i=>c[i.group]++); const n=its.length||1;
    g.append(el('div',{class:'panel proj'},
      el('div',{},el('h3',{text:r.project}),el('div',{class:'meta',title:r.target,text:r.target})),
      el('div',{class:'stack'},el('span',{style:`width:${c.Confirmed/n*100}%;background:var(--crit)`}),el('span',{style:`width:${c['Needs review']/n*100}%;background:var(--warn)`}),el('span',{style:`width:${c.Hidden/n*100}%;background:var(--line-strong)`})),
      el('div',{class:'nums'},el('div',{},el('b',{text:c.Confirmed}),'confirmed'),el('div',{},el('b',{text:c['Needs review']}),'need review'),el('div',{},el('b',{text:c.Hidden}),'auto-ignored')),
      el('div',{class:'meta',text:`Last scan ${when(r.created)} · ${MODEL_NAMES[r.model]||r.model} · ${mins(r.seconds)} · ${money(r.cost)}`}),
      el('div',{style:'display:flex;gap:8px;flex-wrap:wrap'},el('a',{class:'btn small',href:'#issues',onclick:()=>{state.project=r.project;state.status='open';state.page=0;},text:'View issues'}),el('button',{class:'btn small',type:'button',onclick:()=>openScan(r.target)},'Scan again'))));});
  if(state.run) v.append(runBanner());
  v.append(g);
}

/* ---------------- Scans ---------------- */
function viewScans(){
  setTitle('Workspace','Scans');
  const v=$('#view'); v.replaceChildren();
  if(JOBS.length){ const list=el('div',{class:'list'});
    JOBS.forEach(j=>list.append(el('div',{class:'list-row',tabindex:0,onclick:()=>openScan(null,j.id),onkeydown:e=>{if(e.key==='Enter')openScan(null,j.id)}},el('span',{class:'pill review',text:jobLabel(j)}),
      el('div',{style:'min-width:0'},el('div',{class:'t',text:j.project}),el('div',{class:'s',text:j.state==='judging'?`${j.done} of ${j.total} groups · ${j.current}`:j.folder})))));
    v.append(panel('Running now',null,list)); }
  const t=el('tbody');
  RUNS.forEach(r=>t.append(el('tr',{},el('td',{},el('span',{class:'tag',text:r.id})),el('td',{title:r.target,text:r.project}),el('td',{text:MODEL_NAMES[r.model]||r.model}),
    el('td',{text:r.alerts}),el('td',{text:r.hidden}),el('td',{text:money(r.cost)}),el('td',{text:mins(r.seconds)}),
    el('td',{},el('div',{class:'row-actions'},
      el('button',{class:'btn small',type:'button',onclick:async()=>{state.run=r.id;state.project='all';state.status='all';state.page=0;await refresh('issues');}},'Open'),
      el('button',{class:'btn small',type:'button',onclick:()=>download(`/api/runs/${r.id}/report.html`)},'Report'),
      el('button',{class:'btn small',type:'button',onclick:()=>download(`/api/runs/${r.id}/export.csv`)},'CSV'),
      el('button',{class:'btn small',type:'button',onclick:()=>download(`/api/runs/${r.id}/export.sarif`)},'SARIF'))))));
  v.append(panel('Scan history','scans from this app and from the command line',
    RUNS.length?el('div',{class:'table-wrap'},el('table',{},el('thead',{},el('tr',{},...['Run','Project','Model','Alerts','Auto-ignored','Cost','Time',''].map(h=>el('th',{text:h})))),t)):el('div',{class:'empty',text:'No scans yet.'}),
    el('button',{class:'btn small primary',type:'button',onclick:()=>openScan('')},'New scan')));
}
function jobLabel(j){ return {cloning:'Downloading',counting:'Scanning',counted:'Waiting for you',queued:'Queued',judging:'AI checking'}[j.state]||j.state; }

let pollTimer=null;
function openScan(path, jobId){
  const layer=$('#layer'); layer.replaceChildren(); clearTimeout(pollTimer);
  let model=STATUS.anthropic_key?'claude':'mock', job=null, busy=false;
  const close=()=>{ clearTimeout(pollTimer); layer.replaceChildren(); };
  const card=el('div',{class:'modal-card',role:'dialog','aria-label':'New scan'}); layer.append(el('div',{class:'modal',onclick:e=>{if(e.target===e.currentTarget)close();}},card));
  const folder=el('input',{class:'input',id:'folder',placeholder:'https://github.com/owner/repo  or  C:\\Users\\you\\my-app',autocomplete:'off'}); folder.value=path||'';
  const ref=el('input',{class:'input',id:'ref',placeholder:'empty = latest version',autocomplete:'off',maxlength:100});
  const chosen=new Set(Object.keys(CWE));
  const step=()=>!job?1:['cloning','counting','counted'].includes(job.state)?2:3;
  const steps=()=>el('div',{class:'steps'},...['1 Choose code','2 Check cost','3 AI triage'].map((s,k)=>el('span',{class:step()===k+1?'on':'',text:s+(k<2?'  ›':'')})));
  const poll=async()=>{ try{ job=await api('/api/scans/'+job.id); }catch(e){ return; } render();
    if(['cloning','counting','queued','judging'].includes(job.state)) pollTimer=setTimeout(poll,800);
    else if(job.state==='done'){ await refreshData(); toast('Scan finished'); } };
  const render=()=>{ card.replaceChildren(steps());
    if(!job){
      const models=el('div',{class:'models'});
      [['claude','Claude Haiku 5.5',STATUS.anthropic_key?'Cloud · the evaluated model':'Add ANTHROPIC_API_KEY to .env first'],['sonnet','Claude Sonnet 5.5',STATUS.anthropic_key?'Cloud · stronger, about 20× the cost, not evaluated':'Add ANTHROPIC_API_KEY to .env first'],['qwen','Qwen3 14B','Local with Ollama · code never leaves'],['mock','Demo model','No AI · free, for trying the app']].forEach(([k,b,s])=>
        models.append(el('button',{type:'button',class:'model'+(model===k?' on':''),disabled:(k==='claude'||k==='sonnet')&&!STATUS.anthropic_key,onclick:()=>{model=k;render();}},el('b',{text:b}),el('span',{text:s}))));
      const checks=el('div',{class:'checks'}); Object.entries(CWE).forEach(([c,x])=>{ const cb=el('input',{type:'checkbox',checked:chosen.has(c),onchange:e=>{e.target.checked?chosen.add(c):chosen.delete(c);}}); checks.append(el('label',{},cb,x.name)); });
      const missing=Object.entries(STATUS.tools).filter(([,ok])=>!ok).map(([t])=>t);
      card.append(el('div',{class:'form'},
        missing.length?el('div',{class:'preview-note',style:'background:var(--crit-soft)'},el('b',{text:'Not found: '+missing.join(', ')+'. '}),'Activate the project\'s virtual environment, then start the app again.'):null,
        el('div',{class:'field'},el('label',{for:'folder',text:'GitHub link or folder'}),folder,el('div',{class:'hint',text:'A public GitHub repository is downloaded to runs/app-repos on this computer (code is only read, never run). Only the small code slice for each alert is sent to the model you pick.'})),
        el('div',{class:'field'},el('label',{for:'ref',text:'Branch, tag or commit (GitHub only, optional)'}),ref),
        el('div',{class:'field'},el('div',{class:'lab',text:'Model'}),models),
        el('div',{class:'field'},el('div',{class:'lab',text:'Weakness types'}),checks),
        el('div',{class:'locked'},el('span',{class:'tag',text:'locked'}),`Context level ${STATUS.context_level} and threshold ${STATUS.threshold}, the settings measured in the evaluation.`)),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Cancel'),el('button',{class:'btn primary',type:'button',disabled:busy||missing.length>0,onclick:async()=>{
          if(!folder.value.trim()){toast('Type a folder first');return;} if(!chosen.size){toast('Pick at least one weakness type');return;}
          busy=true; render();
          try{ job=await api('/api/scans',{method:'POST',body:{folder:folder.value.trim(),ref:ref.value.trim(),cwes:[...chosen],model}}); path=folder.value; render(); poll(); }
          catch(e){ busy=false; render(); if(e.message!=='no token') toast(e.message); } }},busy?'Starting…':'Scan and estimate')));
      setTimeout(()=>folder.focus(),30);
    } else if(job.state==='cloning'){
      card.append(el('div',{class:'form'},el('div',{text:`Downloading ${job.github} from GitHub…`}),el('div',{class:'prog indet'},el('span',{})),
        el('div',{style:'color:var(--muted);font-size:12.5px',text:'Only the chosen version is downloaded, without its history. The code is read by the scanners, never run.'})),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Run in background')));
    } else if(job.state==='counting'){
      card.append(el('div',{class:'form'},el('div',{text:'Semgrep and Bandit are reading the code…'}),el('div',{class:'prog indet'},el('span',{})),
        el('div',{style:'color:var(--muted);font-size:12.5px',text:'A large project can take a few minutes. No AI is used in this step, so it is free.'})),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Run in background')));
    } else if(job.state==='counted'){
      (job.warnings||[]).forEach(w=>card.append(el('div',{class:'preview-note',style:'background:var(--crit-soft);margin:16px 22px 0'},el('b',{text:'Warning. '}),w)));
      if(!job.alerts){ card.append(el('div',{class:'form'},el('div',{class:'estimate'},el('b',{text:'No alerts of these types.'}),el('div',{text:'The scanners found nothing to check, so no AI is needed.'}))),
        el('div',{class:'modal-f'},el('button',{class:'btn primary',type:'button',onclick:close},'Close'))); return; }
      card.append(el('div',{class:'form'},el('div',{class:'estimate'},el('div',{},el('b',{text:`${job.alerts} alerts`}),' found by Semgrep and Bandit in ',el('span',{class:'tag',text:job.project}),job.commit?el('span',{class:'tag',text:'commit '+job.commit}):null),
        el('div',{text:`They form ${job.groups} groups, because alerts with the same weakness in the same function are checked together.`}),
        el('div',{},'Estimated cost: ',el('b',{text:job.estimate?'about '+money(job.estimate):'$0'}),job.estimate?` (${money(job.per_call)} per check, from your earlier runs)`:' (no paid API)'))),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Cancel'),el('button',{class:'btn primary',type:'button',onclick:async()=>{
          try{ job=await api(`/api/scans/${job.id}/start`,{method:'POST'}); render(); poll(); }catch(e){ if(e.message!=='no token') toast(e.message); } }},'Start AI triage')));
    } else if(job.state==='queued'||job.state==='judging'){
      const pct=job.total?Math.round(job.done/job.total*100):0;
      card.append(el('div',{class:'form'},el('div',{text:job.state==='queued'?'Waiting for another scan to finish…':`Checking group ${job.done+1} of ${job.total} · ${job.current}`}),el('div',{class:'prog'},el('span',{style:`width:${pct}%`})),
        el('div',{style:'color:var(--muted);font-size:12.5px',text:'You can close this window. The scan keeps running and appears under Scans.'})),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Run in background')));
    } else if(job.state==='done'){
      card.append(el('div',{class:'form'},el('div',{class:'estimate'},el('b',{text:'Done.'}),el('div',{text:`${job.alerts} alerts checked in ${job.project}.`}))),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Close'),el('button',{class:'btn primary',type:'button',onclick:async()=>{ close(); state.run=null; state.project=job.project; state.status='open'; state.page=0; await refresh('issues'); }},'See the issues')));
    } else {
      card.append(el('div',{class:'form'},el('div',{class:'preview-note',style:'background:var(--crit-soft)'},el('b',{text:'The scan stopped. '}),job.error||'')),
        el('div',{class:'modal-f'},el('button',{class:'btn',type:'button',onclick:close},'Close')));
    }};
  if(jobId){ job={id:jobId,state:'counting',github:''}; poll(); } else render();
}

/* ---------------- Settings / GitHub ---------------- */
function viewConfig(){
  setTitle('Setup','Models & settings');
  const v=$('#view'); v.replaceChildren();
  const ok=(b,yes,no)=>el('span',{class:'pill '+(b?'human':'confirmed'),text:b?yes:no});
  v.append(panel('Models',null,el('div',{class:'panel-b kv'},
    el('span',{text:'Claude (Anthropic)'}),el('b',{},ok(STATUS.anthropic_key,'API key found in .env','No API key in .env'),' the key is never shown in the app'),
    el('span',{text:'Cloud model (evaluated)'}),el('b',{text:`${STATUS.models.claude.model} · $0.10 in / $0.50 out per million tokens`}),
    el('span',{text:'Stronger cloud model'}),el('b',{text:`${STATUS.models.sonnet.model} · $2 in / $10 out per million tokens · not part of the evaluation`}),
    el('span',{text:'Local model (Ollama)'}),el('b',{text:`${STATUS.models.qwen.model} · free and private, but much slower. Ollama must be running.`}),
    el('span',{text:'Spending limit'}),el('b',{text:'Set it in the Claude Console. The app shows an estimate before every AI check.'}))));
  v.append(panel('Scanners',null,el('div',{class:'panel-b kv'},
    ...Object.entries(STATUS.tools).flatMap(([t,b])=>[el('span',{text:t[0].toUpperCase()+t.slice(1)}),el('b',{},ok(b,'Found','Not found: activate the virtual environment'))]),
    el('span',{text:'Rules'}),el('b',{text:'The project\'s own rules/ folder plus the Semgrep community Python rules, run offline'}))));
  v.append(panel('Triage settings',null,el('div',{class:'panel-b kv'},
    el('span',{text:'Context level'}),el('b',{text:`${STATUS.context_level} · source-to-sink slice with the conditions around it`}),
    el('span',{text:'Confidence threshold'}),el('b',{text:`${STATUS.threshold} · alerts are only ignored at or above this, and only when the cited lines exist`}),
    el('span',{text:'When the model fails'}),el('b',{text:'Keep the alert (fail-open)'}),
    el('span',{text:'Why locked'}),el('b',{text:'These are the settings measured in the evaluation. Changing them would make the measured results not apply.'})),el('span',{class:'tag',text:'locked'})));
  v.append(panel('Security of this app',null,el('div',{class:'panel-b kv'},
    el('span',{text:'Who can open it'}),el('b',{text:'Only this computer (127.0.0.1), with a new session key in every request'}),
    el('span',{text:'Code, file names, AI text'}),el('b',{text:'Always shown as plain text, never as HTML'}),
    el('span',{text:'Where results are stored'}),el('b',{text:STATUS.runs_dir+'/results.db'}))));
}
function viewIntegrations(){
  setTitle('Setup','GitHub');
  const v=$('#view'); v.replaceChildren();
  v.append(el('div',{class:'preview-note'},el('b',{text:'Planned next.'}),' This page shows how the GitHub Action will be set up. Until then, export SARIF from the Scans page and upload it to GitHub code scanning.'));
  const yaml=['name: LLM SAST triage','on: [pull_request]','jobs:','  triage:','    runs-on: ubuntu-latest','    permissions:','      security-events: write','    steps:','      - uses: actions/checkout@v4','      - uses: zainab-nooh/llm-sast-triage@v1','        with:','          anthropic-api-key: ${{ secrets.ANTHROPIC_API_KEY }}','          changed-files-only: true'];
  const code=el('div',{class:'code'},el('div',{class:'pad'},...yaml.map((l,k)=>el('div',{class:'ln'},el('span',{class:'m'}),el('span',{class:'n',text:k+1}),el('span',{text:l})))));
  v.append(el('div',{class:'grid-2'},
    panel('Check every pull request',null,el('div',{class:'panel-b',style:'display:grid;gap:12px'},
      el('div',{style:'color:var(--muted);max-width:65ch',text:'Add this file as .github/workflows/triage.yml. Each repository owner stores their own API key as a GitHub secret, so nobody shares a key and no code goes to a server of ours.'}),code)),
    panel('What appears on GitHub',null,el('div',{class:'panel-b kv'},
      el('span',{text:'Code scanning (SARIF)'}),el('b',{text:'Alerts on the changed lines, with the AI verdict and fix'}),
      el('span',{text:'Auto-ignored alerts'}),el('b',{text:'Uploaded as dismissed, with the AI reason'}),
      el('span',{text:'Pull request check'}),el('b',{text:'Fails when a confirmed critical or high issue is added'})))));
}

/* ---------------- routing ---------------- */
const PAGES={dashboard:viewDashboard,issues:viewIssues,report:viewReport,projects:viewProjects,scans:viewScans,config:viewConfig,integrations:viewIntegrations};
function route(){
  if(!STATUS) return;
  const p=(location.hash||'#dashboard').slice(1); const page=PAGES[p]?p:'dashboard';
  document.querySelectorAll('.nav a[data-page]').forEach(a=>a.classList.toggle('on',a.dataset.page===page||(page==='report'&&a.dataset.page==='dashboard')));
  const m=$('#mnav'); m.replaceChildren(...['dashboard','issues','projects','scans','config','integrations'].map(k=>el('a',{href:'#'+k,class:k===page?'on':'',text:{dashboard:'Dashboard',issues:'Issues',projects:'Projects',scans:'Scans',config:'Settings',integrations:'GitHub'}[k]})));
  $('#navOpen').textContent=ISSUES.filter(isOpen).length;
  PAGES[page]();
}
async function refreshData(){ try{ await load(); }catch(e){ if(e.message!=='no token') toast(e.message); } if(!$('#layer').children.length) route(); }
async function refresh(page){ await refreshData(); if(page&&location.hash!=='#'+page) location.hash='#'+page; else route(); $('.main').scrollTop=0; }
function noToken(){
  $('#view').replaceChildren(el('div',{class:'panel'},el('div',{class:'panel-b welcome'},el('h2',{text:'Open the app from its start link'}),
    el('p',{text:'For safety, this app only answers requests that carry the session key from the link printed in the terminal when you ran "python -m codereview serve". Open that link again (it starts with http://127.0.0.1).'}))));
}
window.addEventListener('hashchange',()=>{ $('#layer').replaceChildren(); route(); $('.main').scrollTop=0; });
$('#q').addEventListener('input',e=>{ state.q=e.target.value; state.page=0; if(location.hash!=='#issues') location.hash='#issues'; else viewIssues(); });
$('#newScan').addEventListener('click',()=>{ if(STATUS) openScan(''); });

/* ---------------- light / dark ---------------- */
try{ const t=localStorage.getItem('theme'); if(t) document.documentElement.dataset.theme=t; }catch(e){}
function isDark(){ const t=document.documentElement.dataset.theme; return t? t==='dark' : matchMedia('(prefers-color-scheme: dark)').matches; }
function drawThemeBtn(){ const b=$('#themeBtn'); const d=isDark(); b.setAttribute('aria-label',d?'Switch to light mode':'Switch to dark mode'); b.title=b.getAttribute('aria-label');
  b.replaceChildren(); const s=svg('svg',{width:16,height:16,viewBox:'0 0 24 24',fill:'none',stroke:'currentColor','stroke-width':2,'aria-hidden':'true'});
  if(d){ s.append(svg('circle',{cx:12,cy:12,r:4}),svg('path',{d:'M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4'})); }
  else s.append(svg('path',{d:'M21 12.8A9 9 0 1111.2 3a7 7 0 009.8 9.8z'}));
  b.append(s); }
$('#themeBtn').addEventListener('click',()=>{ const t=isDark()?'light':'dark'; document.documentElement.dataset.theme=t; try{localStorage.setItem('theme',t);}catch(e){} drawThemeBtn(); });
drawThemeBtn();

if(TOKEN) refresh(); else noToken();

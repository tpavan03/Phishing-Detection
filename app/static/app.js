const $ = id => document.getElementById(id);
let current = null;
const labels = {awaiting_review:'Awaiting review',analysis_complete:'Analysis complete',reviewed:'Reviewed',escalated:'Escalated'};
const decisions = {likely_legitimate:'Likely legitimate',suspicious:'Suspicious',needs_investigation:'Needs further investigation'};
function el(tag,className,text){const n=document.createElement(tag);if(className)n.className=className;if(text!==undefined)n.textContent=text;return n;}
async function api(path,body){const response=await fetch(path,body===undefined?{}:{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify(body)});const data=await response.json();if(!response.ok)throw new Error(data.error||'Request failed.');return data;}
function showError(id,error){$(id).textContent=error.message;$(id).hidden=false;}
function render(result){
  current=result;$('results').hidden=false;
  const unified=result.unified_decision||{label:result.risk==='high'?'likely_malicious':result.risk==='moderate'?'needs_review':'low_concern',title:result.risk==='high'?'Likely malicious':result.risk==='moderate'?'Needs review':'Low concern',explanation:'Legacy case: this decision was derived from the saved local rule score.'};
  $('score').textContent=result.score;$('risk').textContent=result.risk+' concern';$('risk').className='risk-badge '+result.risk;
  $('verdict').textContent=result.review_required?'Context needs a closer look.':'Few lexical warning signals.';
  $('unified-title').textContent=unified.title;$('unified-title').className=unified.label;
  $('unified-explanation').textContent=unified.explanation;
  $('host').textContent=result.host;$('case-url').textContent=result.url;
  $('tool-count').textContent=(result.agent_count||result.tools.length)+' CHECKS EXECUTED';$('evidence-count').textContent=result.evidence.length+' signals';
  $('stages').replaceChildren(...result.stages.map((s,i)=>{const li=el('li');li.append(el('span','step-icon '+(s.status==='completed'?'':'pending'),s.status==='completed'?'✓':String(i+1)));const d=el('div');d.append(el('strong','',s.name),el('p','',s.detail));li.append(d);return li;}));
  $('evidence').replaceChildren(...result.evidence.map(e=>{const row=el('div','evidence-item');const d=el('div');d.append(el('strong','',e.title),el('p','',e.detail));const marker=e.source==='external_reputation'?'R':(e.weight?'!':'i');row.append(el('span','evidence-icon',marker),d,el('span','weight',e.weight?'+'+e.weight:(e.status||'signal')));return row;}));
  $('review-form').hidden=!!result.review;$('review-result').hidden=!result.review;$('review-error').hidden=true;$('review-form').reset();
  if(result.review)$('review-result').replaceChildren(el('strong','',decisions[result.review.decision]),el('p','',result.review.note),el('p','',new Date(result.review.reviewed_at).toLocaleString()));
}
async function history(){const data=await api('/api/cases');$('history-count').textContent=data.cases.length;$('empty').hidden=data.cases.length>0;$('history-body').replaceChildren(...data.cases.map(c=>{const row=el('tr');row.append(el('td','',c.host));const concern=el('td');concern.append(el('span','risk-badge '+c.risk,c.risk));row.append(concern,el('td','',c.score+'/100'),el('td','',labels[c.status]),el('td','',new Date(c.created_at).toLocaleString(undefined,{month:'short',day:'numeric',hour:'2-digit',minute:'2-digit'})));const cell=el('td');const button=el('button','','Open →');button.type='button';button.setAttribute('aria-label','Open case for '+c.host);button.addEventListener('click',()=>{render(c);$('results').scrollIntoView({behavior:'smooth',block:'start'});});cell.append(button);row.append(cell);return row;}));}
$('analyze-form').addEventListener('submit',async event=>{event.preventDefault();const b=$('analyze-button');b.disabled=true;b.textContent='Analyzing…';$('error').hidden=true;try{const providers={};if($('vt-key').value)providers.virustotal=$('vt-key').value;if($('gsb-key').value)providers.google_safe_browsing=$('gsb-key').value;const result=await api('/api/analyze',{url:$('url').value,providers});render(result);await history();$('results').scrollIntoView({behavior:'smooth',block:'start'});}catch(error){showError('error',error);}finally{b.disabled=false;b.textContent='Analyze URL →';}});
document.querySelectorAll('.sample').forEach(b=>b.addEventListener('click',()=>{$('url').value=b.dataset.url;$('analyze-form').requestSubmit();}));
$('review-form').addEventListener('submit',async event=>{event.preventDefault();if(!current)return;const b=event.currentTarget.querySelector('button');b.disabled=true;$('review-error').hidden=true;try{render(await api('/api/cases/'+current.id+'/review',{decision:$('decision').value,note:$('note').value}));await history();}catch(error){showError('review-error',error);}finally{b.disabled=false;}});
$('export-button').addEventListener('click',()=>{if(!current)return;const url=URL.createObjectURL(new Blob([JSON.stringify(current,null,2)],{type:'application/json'}));const a=el('a');a.href=url;a.download='phishscope-'+current.id+'.json';a.click();setTimeout(()=>URL.revokeObjectURL(url),1000);});
history().catch(error=>showError('error',error));

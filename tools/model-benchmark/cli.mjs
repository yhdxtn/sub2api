import fs from 'node:fs';
import path from 'node:path';
import http from 'node:http';
import {fileURLToPath} from 'node:url';
import {setTimeout as sleep} from 'node:timers/promises';
import {models,qualityPrompt,score,scoreBank,classify,totals,report,esc} from './core.mjs';
import {advancedQuestions,advancedPrompt} from './advanced.mjs';
import {execFileSync} from 'node:child_process';

const root=path.resolve(path.dirname(fileURLToPath(import.meta.url)),'../..');
const args=process.argv.slice(2);const option=(name,def)=>{const i=args.indexOf('--'+name);return i<0?def:args[i+1]};
const flags=new Set(['--serve','--idle','--resume','--continue-stopped']);
const valued=new Set(['--origin','--out','--secrets','--admin','--models','--accounts','--minutes','--port']);
for(let i=0;i<args.length;i++){if(flags.has(args[i]))continue;if(!valued.has(args[i]))throw Error('Unknown option '+args[i]);if(!args[i+1]||args[i+1].startsWith('--'))throw Error('Missing value for '+args[i]);i++;}
const origin=option('origin','http://127.0.0.1:8080');
if(new URL(origin).hostname!=='127.0.0.1'&&new URL(origin).hostname!=='localhost')throw Error('Only a local administrator server is allowed');
const baseOut=path.resolve(option('out',path.join(root,'output/model-benchmark')));
let out=baseOut;fs.mkdirSync(out,{recursive:true});
const secretFile=option('secrets',path.join(root,'backend/data/local-run-secrets.env'));
let token='',accounts=[],state=null,running=false,stopRequested=false;
function redact(s){return String(s).replace(/Bearer\s+\S+|eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/gi,'[REDACTED]').replace(/[\w.+-]+@[\w.-]+\.[a-z]{2,}/gi,'[email]');}
async function api(p,body,retried=false){const response=await fetch(origin+'/api/v1'+p,{method:body?'POST':'GET',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:body?JSON.stringify(body):undefined,signal:AbortSignal.timeout(30000)});if(response.status===401&&!retried){await login();return api(p,body,true)}if(!response.ok)throw Error('Local API status '+response.status);const j=await response.json();if(j.code!==0)throw Error('Local API rejected request');return j.data;}
async function login(){const s=Object.fromEntries(fs.readFileSync(secretFile,'utf8').split(/\r?\n/).filter(l=>l.includes('=')&&!l.startsWith('#')).map(l=>[l.slice(0,l.indexOf('=')),l.slice(l.indexOf('=')+1).trim()]));const response=await fetch(origin+'/api/v1/auth/login',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({email:option('admin',s.ADMIN_EMAIL||'admin'),password:s.ADMIN_PASSWORD}),signal:AbortSignal.timeout(10000)});const j=await response.json();token=j.data?.access_token;if(!token)throw Error('Administrator login failed');accounts=(await api('/admin/accounts?page=1&page_size=100')).items;}
function save(){state.updatedAt=new Date().toISOString();fs.writeFileSync(path.join(out,'checkpoint.tmp'),JSON.stringify(state,null,2));fs.renameSync(path.join(out,'checkpoint.tmp'),path.join(out,'checkpoint.json'));fs.writeFileSync(path.join(out,'report.html'),report(state));}
async function snapshot(id){try{const a=await api('/admin/accounts/'+id);const e=a.extra||{};return {at:new Date().toISOString(),status:a.status,plan:a.credentials?.plan_type,used5h:e.codex_5h_used_percent,used7d:e.codex_7d_used_percent,reset5h:e.codex_5h_reset_at,reset7d:e.codex_7d_reset_at,rateLimitReset:a.rate_limit_reset_at};}catch{return {unavailable:true};}}
async function request(run,kind,prompt,deadline){
 const started=Date.now();const r={kind,prompt,time:new Date().toISOString(),targetLines:kind==='capacity'?run.targetLines:null,success:false,text:'',usage:null,elapsedMs:0,firstTokenMs:null};
 const timeoutMs=Math.max(1,Math.min(180000,deadline-Date.now()));
 const controller=new AbortController();const timeout=setTimeout(()=>controller.abort(),timeoutMs);
 try{
  const response=await fetch(`${origin}/api/v1/admin/accounts/${run.accountId}/test`,{method:'POST',headers:{Authorization:'Bearer '+token,'Content-Type':'application/json'},body:JSON.stringify({model_id:run.model,prompt,mode:'normal'}),signal:controller.signal});
  if(!response.ok){r.httpStatus=response.status;r.error='Local HTTP '+response.status;}
  else{let pending='';const decoder=new TextDecoder();for await(const chunk of response.body){pending+=decoder.decode(chunk,{stream:true});let i;while((i=pending.indexOf('\n\n'))>=0){const frame=pending.slice(0,i);pending=pending.slice(i+2);for(const line of frame.split('\n')){if(!line.startsWith('data:'))continue;let e;try{e=JSON.parse(line.slice(5).trim())}catch{continue}
    if(e.type==='content'){if(r.firstTokenMs===null)r.firstTokenMs=Date.now()-started;r.text+=e.text||'';}
    if(e.type==='telemetry'){r.httpStatus=e.data?.http_status;r.quotaHeaders=e.data?.quota_headers;r.sentModel=e.model;}
    if(e.type==='usage'){r.usage=e.data?.usage;r.responseModel=e.model;r.responseStatus=e.data?.status;r.incompleteDetails=e.data?.incomplete_details;}
    if(e.type==='error')r.error=redact(e.error||'Unknown upstream error');
    if(e.type==='test_complete')r.success=e.success===true;
  }}}}
 }catch(e){r.error=redact(e.name==='AbortError'?`Request timeout at ${Math.round(timeoutMs/1000)} seconds`:e.message);if(Date.now()>=deadline)r.deadlineReached=true;}
 finally{clearTimeout(timeout);r.elapsedMs=Date.now()-started;}
 if(r.success&&!r.text.trim()){r.success=false;r.error='Completed without visible output';}
 if(!r.success)r.classification=classify(r.error||'No completion event',r.httpStatus,r.responseStatus);
 run.requests.push(r);save();console.log(JSON.stringify({model:run.model,accountId:run.accountId,kind,success:r.success,tokens:r.usage?.output_tokens,ms:r.elapsedMs,error:r.classification}));return r;
}
async function worker(run,deadline){
 if(run.phase==='finished')return;
 run.before??=await snapshot(run.accountId);let failures=0;run.targetLines??=state.settings.targetLines;
 while(Date.now()<deadline&&!stopRequested&&!fs.existsSync(path.join(out,'STOP'))){
  const quality=!run.quality&& !run.requests.some(r=>r.kind==='quality'&&r.success);
  const advanced=!quality&&!run.advanced;
  run.phase=quality?'基础答题测试':advanced?'进阶答题测试':'持续输出测试';save();
  const prompt=quality?qualityPrompt:advanced?advancedPrompt:`Quota benchmark request ${run.requests.length}. Produce exactly ${run.targetLines} numbered lines. Each line must contain its number and one original concise English sentence (12 to 20 words) describing a distinct everyday object, observation or engineering fact. Do not summarize, use placeholders, write code, or shorten the list. Continue generating until the list is complete or the response output limit is reached. Start immediately with line 1.`;
  const r=await request(run,quality?'quality':advanced?'quality_advanced':'capacity',prompt,deadline);
  if(r.success){failures=0;if(quality){run.quality={...score(r.text),raw:r.text};}if(advanced){run.advanced={...scoreBank(r.text,advancedQuestions),raw:r.text};run.basic=run.quality;run.quality={correct:run.basic.correct+run.advanced.correct,total:run.basic.total+run.advanced.total,formatValid:run.basic.formatValid&&run.advanced.formatValid,items:[...run.basic.items,...run.advanced.items]};}save();await sleep(1000);continue;}
  if(advanced&&r.classification==='transient'){run.advanced={unavailable:true,error:r.error,total:advancedQuestions.length};failures=0;save();await sleep(8000);continue;}
  if(r.deadlineReached){run.stopReason='time_limit';break;}
  if(r.classification==='transient'&&r.text.length>0&&run.targetLines>100){run.targetLines=Math.max(100,Math.floor(run.targetLines/2));failures=0;save();await sleep(8000);continue;}
  if(r.classification==='transient'&&failures++<2){await sleep(8000);continue;}
  run.stopReason=r.classification;break;
 }
 run.stopReason??=(stopRequested||fs.existsSync(path.join(out,'STOP')))?'user_stopped':'time_limit';run.after=await snapshot(run.accountId);run.phase='finished';run.finishedAt=new Date().toISOString();save();
}
async function start(selectedModels,ids,minutes,resume=false){
 if(running)throw Error('A benchmark is already running');
 if(!Number.isFinite(minutes)||minutes<=0||minutes>360)throw Error('Minutes must be 1 to 360');
 if(selectedModels.length<1||selectedModels.length>6||new Set(ids).size!==ids.length||ids.length!==selectedModels.length)throw Error('Use one distinct account per model (1 to 6 models)');
 for(const id of ids){const a=accounts.find(a=>a.id===id);if(!a||a.platform!=='openai'||a.type!=='oauth'||a.status!=='active')throw Error('Account #'+id+' is not an active OpenAI OAuth account');}
 if(new Set(ids.map(id=>accounts.find(a=>a.id===id).credentials?.chatgpt_account_id||id)).size!==ids.length)throw Error('Accounts must represent distinct upstream identities');
 running=true;stopRequested=false;
 if(resume){state=JSON.parse(fs.readFileSync(path.join(out,'checkpoint.json'),'utf8'));if(state.status==='complete'&&!args.includes('--continue-stopped'))throw Error('This run is complete; use a new output directory');
  if(args.includes('--continue-stopped')){state.resumeHistory??=[];state.resumeHistory.push({at:new Date().toISOString(),reason:'Continue stopped runs with adaptive request sizes'});for(const r of state.runs){if(r.stopReason==='user_stopped'||r.stopReason==='transient'){r.phase='pending';delete r.stopReason;delete r.finishedAt;delete r.after;r.targetLines=300;}}state.status='running';}
 }
 else{if(fs.existsSync(path.join(out,'checkpoint.json')))throw Error('Output already contains a run; use --resume or a new --out directory');state={version:1,status:'running',startedAt:new Date().toISOString(),minutes,settings:{targetLines:4000,timeoutSeconds:180,perAccountConcurrency:1},runs:selectedModels.map((model,i)=>({model,accountId:ids[i],phase:'pending',requests:[]}))};}
 save();try{await Promise.all(state.runs.map(r=>worker(r,new Date(state.startedAt).getTime()+state.minutes*60000)));state.status='complete';save();execFileSync(process.execPath,[path.join(root,'tools/model-benchmark/finalize.mjs'),out],{stdio:'ignore'});}finally{running=false;}
 console.log(JSON.stringify({status:state.status,report:path.join(out,'report.html'),summary:state.runs.map(r=>({model:r.model,accountId:r.accountId,stop:r.stopReason,...totals(r.requests)}))}));
}
await login();
const selectedModels=option('models',models.join(',')).split(',');
let candidates=accounts.filter(a=>a.platform==='openai'&&a.type==='oauth'&&a.status==='active'&&a.schedulable).sort((a,b)=>a.id-b.id);
const ids=option('accounts',candidates.slice(0,selectedModels.length).map(a=>a.id).join(',')).split(',').map(Number);
if(args.includes('--serve')){
 if(args.includes('--idle')&&fs.existsSync(path.join(out,'checkpoint.json')))state=JSON.parse(fs.readFileSync(path.join(out,'checkpoint.json'),'utf8'));
 const port=Number(option('port','8091'));
 const server=http.createServer(async(req,res)=>{
  res.setHeader('Cache-Control','no-store');
  if(!running){try{accounts=(await api('/admin/accounts?page=1&page_size=100')).items;candidates=accounts.filter(a=>a.platform==='openai'&&a.type==='oauth'&&a.status==='active'&&a.schedulable).sort((a,b)=>a.id-b.id)}catch{res.writeHead(503);res.end('本地系统暂不可用，请稍后刷新');return;}}
  if(req.method==='POST'){
   if(req.headers.origin!==`http://127.0.0.1:${port}`){res.writeHead(403);res.end();return;}
   if(req.url==='/stop'){stopRequested=true;res.end('停止请求已收到');return;}
   if(req.url==='/start'){try{let body='';for await(const c of req){body+=c;if(body.length>4000)throw Error('Too large');}const j=JSON.parse(body);
    if(running)throw Error('当前测试尚未结束');
    if(!Array.isArray(j.models)||!Array.isArray(j.ids)||j.models.length!==1||j.ids.length!==1||!models.includes(j.models[0])||!candidates.some(a=>a.id===j.ids[0])||!Number.isFinite(Number(j.minutes))||Number(j.minutes)<=0||Number(j.minutes)>360)throw Error('请选择一个可用账号、模型及 1 到 360 分钟');
    out=path.join(baseOut,'run-'+new Date().toISOString().replace(/[:.]/g,'-'));fs.mkdirSync(out,{recursive:true});
    start(j.models,j.ids,Number(j.minutes)).catch(e=>console.error(redact(e.message)));res.end('已启动');}catch(e){res.writeHead(400);res.end(redact(e.message));}return;}
  }
  res.setHeader('Content-Type','text/html; charset=utf-8');
  res.end(`<div style="font:16px system-ui;margin:24px"><b>测试工具</b> <button onclick="fetch('/stop',{method:'POST'})">停止当前测试</button><form onsubmit="event.preventDefault();fetch('/start',{method:'POST',body:JSON.stringify({models:[this.model.value],ids:[Number(this.account.value)],minutes:Number(this.minutes.value)})}).then(async r=>{if(!r.ok)alert(await r.text());else location.reload()})"><select name="account">${candidates.map(a=>`<option value="${a.id}">账号 #${a.id}</option>`).join('')}</select><select name="model">${models.map(m=>`<option>${esc(m)}</option>`).join('')}</select>分钟：<input name="minutes" type="number" value="30" min="1" max="360"><button ${running?'disabled':''}>启动单账号测试（会消耗额度）</button></form></div>`+(state?(state.status==='complete'&&fs.existsSync(path.join(out,'report.html'))?fs.readFileSync(path.join(out,'report.html'),'utf8'):report(state)):'<p>等待启动</p>'));
 });server.listen(port,'127.0.0.1',()=>console.log(`Dashboard http://127.0.0.1:${port}`));
}
if(!args.includes('--idle'))await start(selectedModels,ids,Number(option('minutes','120')),args.includes('--resume'));

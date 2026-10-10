export const models = ['gpt-6-luna','gpt-reserve','gpt-5.6-terra','gpt-5.6-luna','gpt-5.5','codex-auto-review'];
export const questions = [
 ['arithmetic','17*23+41',432],
 ['modular','What is 7^2026 modulo 13?',4],
 ['probability','Two fair six-sided dice are rolled. Given that their sum is even, what is the probability the sum is 8? Return a fraction.','5/18'],
 ['combinatorics','How many distinct permutations of BANANA are there?',60],
 ['paths','How many shortest grid paths from (0,0) to (4,4) do not pass through (2,2)?',34],
 ['logic','A says: B is a liar. B says: exactly one of us is truthful. Each person always tells the truth or always lies. Who is truthful? Return A or B.','B'],
 ['code','Python: x=[[]]*3; x[0].append(7); return x as JSON.',[[7],[7],[7]]],
 ['recurrence','f(0)=0,f(1)=1,f(n)=2*f(n-1)+f(n-2). Find f(8).',408],
 ['counting','How many integers from 1 to 1000 inclusive are divisible by neither 3 nor 5?',533],
 ['optimization','0/1 knapsack capacity 10, items (weight,value): (6,30),(3,14),(4,16),(2,9). Maximum value?',46],
 ['graph','Undirected edges A-B:4, A-C:2, C-B:1, B-D:5, C-D:8, D-E:2, B-E:10. Shortest distance from A to E?',10],
 ['instruction','Return exactly the string zeta and no other text in this answer value.','zeta'],
];
export const qualityPrompt = 'Solve all tasks independently. Return ONLY a JSON object mapping the following task IDs to their answer values; no markdown or explanations.\n'+questions.map(([id,q])=>`${id}: ${q}`).join('\n');
export function scoreBank(text,bank) {
 let parsed; try { parsed=JSON.parse(text.trim().replace(/^```(?:json)?\s*|\s*```$/g,''));if(!parsed||typeof parsed!=='object'||Array.isArray(parsed))throw Error('Expected answer object'); } catch { return {correct:0,total:bank.length,formatValid:false,items:bank.map(([id])=>({id,correct:false,answer:null}))}; }
 const items=bank.map(([id,,answer])=>({id,expected:answer,answer:parsed[id]??null,correct:JSON.stringify(parsed[id])===JSON.stringify(answer)}));
 return {correct:items.filter(x=>x.correct).length,total:items.length,formatValid:true,items};
}
export const score=text=>scoreBank(text,questions);
export function classify(error='',status=0,usageStatus='') {
 const e=error.toLowerCase();
 if (/usage_limit_reached|insufficient_quota|quota.{0,20}(exhaust|exceed)|limit reached/.test(e)) return 'quota_exhausted';
 if (status===429 || /rate.?limit|too many requests/.test(e)) return 'rate_limited';
 if (status===401 || /unauthorized|access token|authentication/.test(e)) return 'authentication';
 if (status===403) return 'forbidden';
 if (/not supported|unsupported|model.{0,20}(not found|not exist)|invalid model/.test(e) || status===404) return 'model_unavailable';
 if (usageStatus==='incomplete' || /response incomplete|max_output_tokens/.test(e)) return 'incomplete_output';
 if (/timeout|aborted|fetch failed|connection|stream ended|stream read|terminated|socket|econnreset|econnrefused|enotfound/.test(e) || status>=500) return 'transient';
 return 'request_error';
}
export function totals(requests) {
 const t={requests:requests.length,successful:0,inputTokens:0,outputTokens:0,totalTokens:0,reasoningTokens:0,cachedInputTokens:0,usageMissing:0,outputCharacters:0};
 for(const r of requests){if(r.success)t.successful++; t.outputCharacters+=r.text?.length||0; if(!r.usage){t.usageMissing++;continue;} for(const [key,path] of [['inputTokens','input_tokens'],['outputTokens','output_tokens']]) t[key]+=r.usage[path]||0; t.totalTokens+=r.usage.total_tokens??((r.usage.input_tokens||0)+(r.usage.output_tokens||0));t.reasoningTokens+=r.usage.output_tokens_details?.reasoning_tokens||0;t.cachedInputTokens+=r.usage.input_tokens_details?.cached_tokens||0;}
 return t;
}
export const esc = value => String(value??'').replace(/[&<>"']/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c]));
export const stopLabels={quota_exhausted:'明确额度耗尽',rate_limited:'触发限流，未证明总额度耗尽',authentication:'凭据无效',forbidden:'访问被拒绝',model_unavailable:'模型不支持',incomplete_output:'输出被截断',transient:'连续临时故障',request_error:'请求失败',time_limit:'到达时限，额度下限',user_stopped:'用户停止，额度下限'};
export function performance(run){
 const requests=run.requests.filter(r=>r.kind==='capacity'&&r.success);
 const mean=key=>requests.length?requests.reduce((a,r)=>a+(r[key]||0),0)/requests.length:null;
 const output=requests.reduce((a,r)=>a+(r.usage?.output_tokens||0),0);
 const visible=requests.reduce((a,r)=>a+(r.usage?.output_tokens||0)-(r.usage?.output_tokens_details?.reasoning_tokens||0),0);
 const seconds=requests.reduce((a,r)=>a+r.elapsedMs,0)/1000;
 const last=run.requests.findLast(r=>Object.keys(r.quotaHeaders||{}).length)?.quotaHeaders;
 return {capacityRequests:requests.length,averageFirstTokenMs:mean('firstTokenMs'),averageRequestMs:mean('elapsedMs'),outputTokensPerSecond:seconds?output/seconds:null,visibleTokensPerSecond:seconds?visible/seconds:null,maxSingleOutputTokens:requests.length?Math.max(...requests.map(r=>r.usage?.output_tokens||0)):null,observedModels:[...new Set(run.requests.map(r=>r.responseModel).filter(Boolean))],lastQuotaHeaders:last};
}
export function report(state){
 const rows=state.runs.map(r=>{const t=totals(r.requests);const q=r.quality;return `<tr><td>${esc(r.model)}</td><td>#${r.accountId}</td><td>${esc(r.phase==='finished'?'已结束':r.phase)}</td><td>${t.successful}/${t.requests}</td><td>${t.inputTokens.toLocaleString()}</td><td>${t.outputTokens.toLocaleString()}</td><td>${t.reasoningTokens.toLocaleString()}</td><td>${q?`${q.correct}/${q.total}`:'—'}</td><td>${esc(stopLabels[r.stopReason]||r.stopReason||'进行中')}</td></tr>`}).join('');
 return `<!doctype html><html lang="zh"><meta charset="utf-8"><title>模型额度与能力实测</title><style>body{font:15px system-ui;background:#f3f7fa;margin:28px;color:#123}table{border-collapse:collapse;width:100%;background:white}td,th{padding:12px;text-align:left;border-bottom:1px solid #dde}th{background:#e1eef4}article,details{background:white;padding:20px;margin:18px 0;border-radius:10px}pre{white-space:pre-wrap;overflow-wrap:anywhere}small{color:#567}</style><h1>模型额度与能力实测</h1><p>开始：${esc(state.startedAt)}　状态：${esc(state.status)}　更新：${esc(state.updatedAt)}</p><table><tr><th>模型</th><th>独立账号</th><th>当前步骤</th><th>成功/请求</th><th>输入 tokens</th><th>输出 tokens</th><th>其中推理 tokens</th><th>答题</th><th>停止原因</th></tr>${rows}</table><article><h2>测量口径</h2><p>先运行基础 12 题与进阶 10 题（数学、逻辑、代码、指令遵循），再持续请求长文本。每个模型固定一个账号，每个账号仅一个在途请求，六个账号并行。使用本系统管理员测试接口，沿用账号代理和模型映射；不自动切换账号、不绕过限制。</p><p>token 数取上游 usage，输出包含推理 token，推理 token 不再重复相加。没有 usage 的请求标记缺失，不按字符猜算。题目小样本、每题一次，并非智商或标准化基准；账号和模型因素没有交叉随机化，排名仅供参考。</p><p>累计 token 是本次实际消耗量。限流、凭据问题、不支持模型、网络失败与额度耗尽分开记录。即便明确额度耗尽，也只代表该账号该时间窗口的剩余额度，不能推算全新账号固定额度、单次输出上限或上下文容量。时限内未耗尽只能报告下限。不会等待额度重置后继续消耗。</p><p>GPT-Reserve 在当前模型目录没有同名条目，以 gpt-reserve 进行一次实际探测；失败不能当成额度为零。停止文件 STOP 或页面“停止”将在当前请求结束后停止，不关闭用户浏览器。</p><small>时限 ${state.minutes} 分钟；独立请求超时 180 秒；长文本初始目标 4000 行，断点续测目标 300 行；超时逐次缩短至最低 100 行；无输出的临时故障最多连续重试两次，间隔 8 秒。</small></article>${state.runs.map(r=>`<details><summary>${esc(r.model)} / #${r.accountId} 详细证据 (${r.requests.length} 次)</summary><h3>开始与结束额度快照</h3><pre>${esc(JSON.stringify({before:r.before,after:r.after},null,2))}</pre><h3>答题记录</h3><pre>${esc(JSON.stringify(r.quality,null,2))}</pre>${r.requests.map(a=>`<details><summary>${esc(a.kind)} | ${esc(a.time)} | ${Math.round(a.elapsedMs)} ms | ${a.success?'成功':esc(a.classification)}</summary><pre>${esc(JSON.stringify({...a,text:a.text?.slice(0,12000)},null,2))}</pre></details>`).join('')}</details>`).join('')}${state.status==='running'?'<script>setTimeout(()=>location.reload(),5000)</script>':''}</html>`;
}

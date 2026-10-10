// Small deterministic algorithmic tasks with locally computed reference answers.
const items=[[9,21],[6,13],[7,17],[3,7],[8,19],[5,10],[4,9],[11,25],[2,4],[10,22],[1,1],[12,28]];
let knapsack=0;for(let mask=0;mask<2**items.length;mask++){let w=0,v=0;items.forEach(([weight,value],i)=>{if(mask&(1<<i)){w+=weight;v+=value}});if(w<=37)knapsack=Math.max(knapsack,v);}
let automaton=new Map([['',1]]);for(let i=0;i<30;i++){const next=new Map();for(const [s,n] of automaton)for(const c of ['0','1']){const word=s+c;if(word.includes('000')||word.includes('11'))continue;const suffix=word.slice(-2);next.set(suffix,(next.get(suffix)||0)+n)}automaton=next;}
const strings=[...automaton.values()].reduce((a,b)=>a+b,0);
let polynomial=[1];for(let i=0;i<12;i++){const next=Array(polynomial.length+2).fill(0);polynomial.forEach((n,j)=>{for(let k=0;k<3;k++)next[j+k]+=n});polynomial=next;}
let a=2,b=5;for(let n=2;n<=40;n++){[a,b]=[b,(3*b+2*a+n*n)%1000003]}
const crt=Array.from({length:3150},(_,i)=>i).find(x=>x%9===4&&x%14===11&&x%25===7);
const matrix=[[0,7,12,6,15,9,11,8],[7,0,5,13,6,14,9,10],[12,5,0,8,11,7,6,15],[6,13,8,0,9,12,14,5],[15,6,11,9,0,4,8,13],[9,14,7,12,4,0,10,6],[11,9,6,14,8,10,0,7],[8,10,15,5,13,6,7,0]];
let tsp=Infinity;function tour(vertex,remaining,cost){if(!remaining.length){tsp=Math.min(tsp,cost+matrix[vertex][0]);return;}for(const v of remaining)tour(v,remaining.filter(x=>x!==v),cost+matrix[vertex][v]);}tour(0,[1,2,3,4,5,6,7],0);
let satisfiable=0;for(let mask=0;mask<32;mask++){const [p,q,r,s,t]=[0,1,2,3,4].map(i=>!!(mask&(1<<i)));if(p===([p,q,r,s,t].filter(Boolean).length>=3)&&q===!p&&r===(q&&s)&&s===(r===t)&&t===(p||s))satisfiable++;}
const ways=Array(11).fill(0);ways[0]=1;for(let i=0;i<10;i++)for(let j=i+1;j<=10;j++)if((i+j)%3!==0)ways[j]+=ways[i];
export const advancedQuestions=[
 ['hard_binary','How many binary strings of length 30 contain neither substring 000 nor substring 11?',strings],
 ['hard_knapsack',`0/1 knapsack capacity 37; items (weight,value) are ${JSON.stringify(items)}. Return the maximum total value.`,knapsack],
 ['hard_polynomial','What is the coefficient of x^12 in (1+x+x^2)^12?',polynomial[12]],
 ['hard_recurrence','a0=2,a1=5. For n>=2, an=(3*a(n-1)+2*a(n-2)+n^2) modulo 1000003. Return a40.',b],
 ['hard_crt','Return the least nonnegative integer x satisfying x mod 9 = 4, x mod 14 = 11, and x mod 25 = 7.',crt],
 ['hard_tsp',`Find the minimum total weight of a Hamiltonian cycle starting and ending at vertex 0, visiting each other vertex exactly once. Complete undirected weighted graph distance matrix: ${JSON.stringify(matrix)}. Return only its total weight.`,tsp],
 ['hard_logic','Count Boolean assignments (p,q,r,s,t) satisfying all: p iff at least 3 of the 5 variables are true; q iff NOT p; r iff (q AND s); s iff (r equals t); t iff (p OR s).',satisfiable],
 ['hard_paths','DAG vertices 0 through 10. Edge i->j exists exactly when i<j and (i+j) mod 3 is not 0. How many directed paths from 0 to 10?',ways[10]],
 ['hard_python','Python: def f(x,b=[]): b.append(x); return len(b)*sum(b). Return [f(1),f(2),f(3,[]),f(4)] as a JSON array.',[1,6,3,21]],
 ['hard_probability','Urn has 3 red,2 blue,4 green balls. Draw 3 without replacement, order ignored. Given at least one red is drawn, probability all three colors are present? Return a reduced fraction string.','3/8'],
];
export const advancedPrompt='Solve each task without external tools. Return ONLY a JSON object mapping task IDs to answer values (numbers unless an array or fraction string is requested). No explanations.\n'+advancedQuestions.map(([id,q])=>`${id}: ${q}`).join('\n');

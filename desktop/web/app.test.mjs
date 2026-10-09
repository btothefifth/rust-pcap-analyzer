// Exercise the actual app controller with a small DOM/transport double. This
// proves request/render binding, not browser layout or live HTTP qualification.
import nodeTest from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import * as model from './model.mjs';
const test=(name,fn)=>nodeTest(name,{timeout:3000},fn);

class Element {
  constructor(tag='div',text=''){this.tag=tag;this.children=[];this.events=new Map();this.attrs={};this.style={};this.dataset={};this._text=text;this._value='';this.classList={toggle(){},add(){}};}
  append(...nodes){for(const n of nodes){n.parent=this;this.children.push(n);}}
  replaceChildren(...nodes){this.children=[];this._text='';this._value='';this.append(...nodes);}
  setAttribute(k,v){this.attrs[k]=String(v);if(k==='value')this._value=String(v);if(k==='data-seq')this.dataset.seq=v;}
  addEventListener(k,fn){const handlers=this.events.get(k)??[];handlers.push(fn);this.events.set(k,handlers);}
  get textContent(){return this._text+this.children.map(n=>n.textContent).join('');}
  set textContent(v){this.children=[];this._text=String(v);}
  get options(){return this.children.filter(n=>n.tag==='option');}
  get value(){return this._value||(this.tag==='select'?this.options[0]?.value??'':'');}
  set value(v){this._value=String(v);}
  get selectedIndex(){return this.options.findIndex(n=>n.value===this.value);}
  set selectedIndex(i){this.value=this.options[i]?.value??'';}
  remove(){if(this.parent)this.parent.children=this.parent.children.filter(n=>n!==this);}
}
function walk(n){return [n,...n.children.flatMap(walk)];}
function harness(reply){
  const intervals=[];
  const roots=new Map();for(const id of ['nav','notice','inspector','stats','footer-source','binding','run-label','cancel','jobs','start','capture','mode','profile','main','title'])roots.set(id,new Element());
  const document={createElement:t=>new Element(t),createTextNode:t=>new Element('#text',String(t)),querySelector(selector){const id=selector.slice(1);return [...roots.values()].flatMap(walk).find(n=>n.attrs.id===id)??roots.get(id)??null;},querySelectorAll(){return [];}};
  const context=vm.createContext({...model,document,Node:Element,URLSearchParams,location:{hash:'',pathname:'/'},sessionStorage:{getItem(){return null;}},history:{replaceState(){}},reply,requestAnimationFrame:fn=>fn(),setInterval:fn=>intervals.push(fn)});
  let source=readFileSync(new URL('./app.js',import.meta.url),'utf8');source=source.slice(source.indexOf('\n')+1);source=source.replace('\nsafe(init);','\n');
  vm.runInContext(source+'\napi=reply;',context);
  return {roots,run:code=>vm.runInContext(code,context),interval:()=>intervals[0](),button(root,name){const b=walk(roots.get(root)).find(n=>n.tag==='button'&&n.textContent===name);assert.ok(b,'Missing button '+name);return b;},click:b=>b.events.get('click')[0]()};
}
function detail(job){return {event:{sequence:'1',kind:'packet.observed',status:'observed',evidence:{packets:[{frame:'1'}],spans:[],reconstructed_sha256:job}},parents:[],children:[],spans:[],truncated:false};}
function packet(job){return {hex:job==='A'?'41':'42',source_start:'0',captured_length:'1'};}
function deferred(){let resolve,reject;const promise=new Promise((yes,no)=>{resolve=yes;reject=no;});return {promise,resolve,reject};}
function barrier(){const entered=deferred(),reply=deferred();return {entered:entered.promise,wait(){entered.resolve();return reply.promise;},resolve:reply.resolve,reject:reply.reject};}
const caseData={cases:[{id:'case-A',layer:'container',kind:'research',rationale:'Synthetic case',specifications:['spec-A']}],specifications:{'spec-A':{title:'Synthetic specification'}}};
function caseReply(path){if(path==='audit')return {family_count:1,case_count:1,maintenance_status:'registered',qualification_status:'unqualified'};if(path==='catalog')return caseData;}
async function openCase(ui){await ui.run("S.view='Case catalog'; render()");const row=walk(ui.roots.get('main')).find(n=>n.attrs.tabindex=== '0'&&n.textContent.includes('case-A'));assert.ok(row,'Missing catalog case');await ui.click(row);}
function pairControls(ui){const nodes=walk(ui.roots.get('main'));return {left:nodes.find(n=>n.attrs.id==='left-view'),right:nodes.find(n=>n.attrs.id==='right-view')};}
function choosePair(ui,left,right){const controls=pairControls(ui);controls.left.value=left;controls.right.value=right;for(const n of [controls.left,controls.right])for(const handler of n.events.get('change')??[])handler();}
function researchReply(path){if(path==='research/list')return {interpretations:['a','b','c','d'].map(id=>({id,producer:{id:'parser-'+id,version:'1'}})),errors:[],examined:4,next:'d',has_more:false};}
function report(pair){return {rows:[{layer:'packet',key:pair,field:'pair',result:'equal',left:pair,right:pair}],first_semantic_divergence:null};}
function status(state='running'){return {state,mode:'rust',source_name:'fixture',source_binding:'bytes_and_spans_checked',packets:'1',events:'1',source_bytes:'1'};}

test('same-job status callers share one pending read and later complete status remains current',async()=>{
  const cut=barrier();let calls=0;
  const ui=harness((path,args)=>{assert.equal(path,'status');calls++;return calls===1?cut.wait():Promise.resolve(status('complete'));});
  const first=ui.run("selectJob('A'); safe(()=>poll())");await cut.entered;const second=ui.run("safe(()=>poll())");assert.equal(calls,1);
  cut.resolve(status());await Promise.all([first,second]);assert.equal(ui.run('S.status.state'),'running');
  await ui.run('poll()');assert.equal(calls,2);assert.equal(ui.run('S.status.state'),'complete');assert.equal(ui.roots.get('cancel').disabled,true);
});
test('overview and actual background interval share pending status without suppressing valid rendering',async()=>{
  for(const state of ['running','complete']){
    const cut=barrier();let calls=0;
    const ui=harness((path,args)=>{if(path==='status'){calls++;return calls===1?cut.wait():Promise.resolve(status(state));}assert.equal(path,'overview');return Promise.resolve({first_ns:null,last_ns:null,states:{},protocols:{}});});
    ui.run("selectJob('A')");ui.run(`S.status=${JSON.stringify(status())}`);
    const rendering=ui.run('safe(()=>render())');await cut.entered;const background=ui.interval();assert.equal(calls,1);
    cut.resolve(status(state));await Promise.all([rendering,background]);
    assert.match(ui.roots.get('main').textContent,/Capture identity & coverage/);assert.match(ui.roots.get('main').textContent,/Evidence states/);assert.equal(ui.run('S.status.state'),state);assert.equal(ui.roots.get('cancel').disabled,state==='complete');assert.equal(ui.roots.get('notice').textContent,'');
  }
});
test('status sharing rechecks each render binding and isolates job generations',async()=>{
  const cut=barrier();const calls=[];
  const ui=harness((path,args)=>{calls.push([path,args.job]);return args.job==='A'?cut.wait():Promise.resolve(status('complete'));});
  const old=ui.run("selectJob('A'); S.renderRequest=1; safe(()=>poll(jobBinding(null,1)))");await cut.entered;
  await ui.run("selectJob('B'); poll()");ui.run("notice('Current job')");cut.reject(new Error('Old status failed'));await old;
  assert.equal(ui.run('S.status.state'),'complete');assert.equal(ui.roots.get('notice').textContent,'Current job');assert.deepEqual(calls,[['status','A'],['status','B']]);
});
test('a superseded render cannot publish shared status or its error; the current caller still progresses',async()=>{
  for(const outcome of ['success','error']){
    const cut=barrier();let held=true;
    const ui=harness((path,args)=>caseReply(path)??(held?cut.wait():Promise.resolve(status('complete'))));
    const old=ui.run("selectJob('A'); safe(()=>render())");await cut.entered;
    await ui.run("S.view='Case catalog'; render()");ui.run("notice('Current catalog')");held=false;
    if(outcome==='error')cut.reject(new Error('Superseded render failed'));else cut.resolve(status('complete'));await old;
    assert.equal(ui.run('S.status'),null);assert.equal(ui.roots.get('notice').textContent,'Current catalog');assert.match(ui.roots.get('main').textContent,/Specification & adversarial case ledger/);
    await ui.run('poll()');assert.equal(ui.run('S.status.state'),'complete');
  }
});
test('current shared status errors remain visible and clear the request for a valid retry',async()=>{
  const cut=barrier();let held=true;const ui=harness(()=>held?cut.wait():Promise.resolve(status('complete')));
  const pending=ui.run("selectJob('A'); safe(()=>poll())");await cut.entered;cut.reject(new Error('Current status failed'));await pending;
  assert.equal(ui.roots.get('notice').textContent,'Current status failed');held=false;await ui.run('poll()');assert.equal(ui.run('S.status.state'),'complete');
});

test('opening a case rejects delayed event and packet inspection replies; later inspection works',async()=>{
  for(const delayed of ['event','packet']){
    const cut=barrier(),calls=[];let hold=true;
    const ui=harness((path,args)=>{calls.push(path);return caseReply(path)??(hold&&path===delayed?cut.wait():Promise.resolve(path==='event'?detail('A'):packet('A')));});
    const pending=ui.run("selectJob('A'); safe(()=>inspect('1'))");await cut.entered;
    await openCase(ui);const before=ui.roots.get('inspector').textContent;assert.match(before,/Research casecase-A/);
    hold=false;cut.resolve(delayed==='event'?detail('A'):packet('A'));await pending;
    assert.equal(ui.roots.get('inspector').textContent,before);assert.equal(ui.roots.get('notice').textContent,'');
    if(delayed==='event')assert.equal(calls.filter(p=>p==='packet').length,0);
    await ui.run("inspect('1')");assert.match(ui.roots.get('inspector').textContent,/EVENT 1 · RUN A/);assert.match(ui.roots.get('inspector').textContent,/41 /);
  }
});
test('opening a case suppresses late inspection errors and retained inspector controls',async()=>{
  const cut=barrier(),calls=[];let hold=false;
  const ui=harness((path,args)=>{calls.push(path);return caseReply(path)??(hold&&path==='packet'?cut.wait():Promise.resolve(path==='event'?detail('A'):packet('A')));});
  await ui.run("selectJob('A'); inspect('1')");const oldFrame=ui.button('inspector','Frame 1');hold=true;
  const pending=ui.click(oldFrame);await cut.entered;await openCase(ui);ui.run("notice('Current case')");
  cut.reject(new Error('Old packet failed'));await pending;const count=calls.length;await ui.click(oldFrame);
  assert.equal(calls.length,count);assert.equal(ui.roots.get('notice').textContent,'Current case');assert.match(ui.roots.get('inspector').textContent,/Research case/);
});
test('catalog navigation preserves the current inspector until a case is opened',async()=>{
  const ui=harness((path,args)=>Promise.resolve(caseReply(path)??(path==='event'?detail('A'):packet('A'))));
  await ui.run("selectJob('A'); inspect('1')");const before=ui.roots.get('inspector').textContent;
  await ui.run("S.view='Case catalog'; render()");assert.equal(ui.roots.get('inspector').textContent,before);
  await ui.click(ui.button('inspector','Frame 1'));assert.match(ui.roots.get('inspector').textContent,/41 /);
});
test('superseded packet and reverse replies and errors cannot replace current hex or notices',async()=>{
  for(const delayed of ['packet','reverse'])for(const outcome of ['success','error']){
    const cut=barrier();let hold=false;
    const ui=harness((path,args)=>{if(hold&&path===delayed)return cut.wait();if(path==='event'){const d=detail('A');d.event.evidence.packets.push({frame:'2'});return Promise.resolve(d);}return Promise.resolve(path==='reverse'?{rows:[]}:packet('A'));});
    await ui.run("selectJob('A'); inspect('1')");hold=true;
    const pending=ui.click(ui.button('inspector',delayed==='packet'?'Frame 2':'Derived from viewport'));await cut.entered;
    hold=false;await ui.click(ui.button('inspector','Frame 1'));ui.run("notice('Current viewport')");const before=ui.roots.get('inspector').textContent;
    if(outcome==='error')cut.reject(new Error('Superseded request failed'));else cut.resolve(delayed==='packet'?packet('B'):{rows:[{sequence:'99'}]});await pending;
    assert.equal(ui.roots.get('notice').textContent,'Current viewport');assert.equal(ui.roots.get('inspector').textContent,before);assert.match(before,/Packet 1/);
  }
});
test('current packet and reverse errors remain visible and the next valid request works',async()=>{
  for(const path of ['packet','reverse']){
    let fail=false;const ui=harness((name,args)=>{if(fail&&name===path)return Promise.reject(new Error('Current request failed'));return Promise.resolve(name==='event'?detail('A'):name==='reverse'?{rows:[]}:packet('A'));});
    await ui.run("selectJob('A'); inspect('1')");fail=true;await ui.click(ui.button('inspector',path==='packet'?'Frame 1':'Derived from viewport'));
    assert.equal(ui.roots.get('notice').textContent,'Current request failed');fail=false;await ui.click(ui.button('inspector',path==='packet'?'Frame 1':'Derived from viewport'));assert.match(ui.roots.get('inspector').textContent,path==='packet'?/41 /:/No direct source-span derivatives/);
  }
});
test('research comparisons suppress older success and failure; newest pair remains usable',async()=>{
  for(const outcome of ['success','error']){
    const cut=barrier();const ui=harness((path,args)=>researchReply(path)??(args.left==='a'?cut.wait():Promise.resolve(report(args.left+'/'+args.right))));
    await ui.run("selectJob('A'); research(document.querySelector('#main'),jobBinding())");
    const pending=ui.click(ui.button('main','Compare fields'));await cut.entered;choosePair(ui,'c','d');await ui.click(ui.button('main','Compare fields'));
    ui.run("notice('Current comparison')");const before=ui.roots.get('main').textContent;assert.match(before,/c\/d/);
    if(outcome==='error')cut.reject(new Error('Old comparison failed'));else cut.resolve(report('a/b'));await pending;
    assert.equal(ui.roots.get('main').textContent,before);assert.equal(ui.roots.get('notice').textContent,'Current comparison');assert.equal(ui.run('S.report.rows[0].left'),'c/d');
  }
});
test('changing a research pair invalidates pending responses even after changing it back',async()=>{
  for(const outcome of ['success','error']){
    const cut=barrier();const ui=harness((path,args)=>researchReply(path)??cut.wait());
    await ui.run("selectJob('A'); research(document.querySelector('#main'),jobBinding())");const pending=ui.click(ui.button('main','Compare fields'));await cut.entered;
    choosePair(ui,'c','d');choosePair(ui,'a','b');ui.run("notice('Pair changed')");
    if(outcome==='error')cut.reject(new Error('Obsolete pair failed'));else cut.resolve(report('a/b'));await pending;
    assert.equal(ui.run('S.report'),null);assert.equal(ui.roots.get('notice').textContent,'Pair changed');assert.ok(!ui.roots.get('main').textContent.includes('No differences within compared fields'));
  }
});
test('a rendered research report exports its compared pair after controls change',async()=>{
  const calls=[];const ui=harness((path,args)=>{calls.push([path,args]);if(path==='research/export')throw new Error('Export transport boundary');return Promise.resolve(researchReply(path)??report(args.left+'/'+args.right));});
  await ui.run("selectJob('A'); research(document.querySelector('#main'),jobBinding())");await ui.click(ui.button('main','Compare fields'));choosePair(ui,'c','d');
  const ack=walk(ui.roots.get('main')).find(n=>n.attrs.id==='raw-ack');ack.checked=true;await ui.click(ui.button('main','Export adjudication bundle'));
  const [,args]=calls.find(([path])=>path==='research/export');assert.equal(args.left,'a');assert.equal(args.right,'b');assert.equal(args.job,'A');assert.equal(args.include_raw_capture,true);
  assert.match(ui.roots.get('main').textContent,/Compared interpretation AaCompared interpretation Bb/);
});

test('retained inspector buttons cannot read the next job; same-frame new job works',async()=>{
  const calls=[];const ui=harness(async(path,args)=>{calls.push([path,args.job]);return path==='event'?detail(args.job):packet(args.job);});
  await ui.run("selectJob('A'); inspect('1')");const oldFrame=ui.button('inspector','Frame 1');
  assert.match(ui.roots.get('inspector').textContent,/RUN A/);
  ui.run("selectJob('B')");assert.equal(ui.roots.get('inspector').children.length,0);
  await ui.click(oldFrame);assert.deepEqual(calls,[['event','A'],['packet','A']]);
  await ui.run("inspect('1')");assert.match(ui.roots.get('inspector').textContent,/RUN B/);assert.match(ui.roots.get('inspector').textContent,/42 /);
  assert.deepEqual(calls.slice(-2),[['event','B'],['packet','B']]);
});
test('late event and packet responses cannot repopulate a changed job',async()=>{
  for(const delayed of ['event','packet']){
    let release;const ui=harness((path,args)=>args.job==='A'&&path===delayed?new Promise(resolve=>{release=()=>resolve(path==='event'?detail('A'):packet('A'));}):Promise.resolve(path==='event'?detail(args.job):packet(args.job)));
    const pending=ui.run("selectJob('A'); safe(()=>inspect('1'))");
    // Allow the event reply to reach the packet request when that is the cut.
    for(let i=0;i<8&&!release;i++)await Promise.resolve();assert.ok(release);
    await ui.run("selectJob('B'); inspect('1')");const before=ui.roots.get('inspector').textContent;
    release();await pending;assert.equal(ui.roots.get('inspector').textContent,before);assert.match(before,/RUN B/);
  }
});
test('late failures from a changed job do not replace current notices',async()=>{
  let reject;const ui=harness((path,args)=>args.job==='A'?new Promise((_resolve,no)=>{reject=no;}):Promise.resolve(path==='event'?detail(args.job):packet(args.job)));
  const pending=ui.run("selectJob('A'); safe(()=>inspect('1'))");await ui.run("selectJob('B'); inspect('1')");
  reject(new Error('Old job failed'));await pending;assert.equal(ui.roots.get('notice').textContent,'');assert.match(ui.roots.get('inspector').textContent,/RUN B/);
});
test('research receipt paging preserves selected interpretations and reports errors',async()=>{
  const calls=[];const row=(id)=>({id,producer:{id:'parser-'+id,version:'1'}});
  const ui=harness(async(path,args)=>{calls.push([path,args]);if(path==='research/list')return args.after?{interpretations:[row('b')],errors:[{id:'bad',status:'UNREADABLE'}],examined:2,next:'bad',has_more:false}:{interpretations:[row('a')],errors:[],examined:1,next:'a',has_more:true};return {rows:[],first_semantic_divergence:null};});
  await ui.run("selectJob('A'); research(document.querySelector('#main'),jobBinding())");
  const next=ui.button('main','Next receipts →');await ui.click(next);
  const left=walk(ui.roots.get('main')).find(n=>n.attrs.id==='left-view');
  assert.deepEqual(left.options.map(o=>o.value),['b','a']);assert.equal(left.value,'a');
  assert.match(ui.roots.get('main').textContent,/Unreadable research receipt/);assert.match(ui.roots.get('main').textContent,/End of listing/);
  assert.deepEqual(calls.filter(c=>c[0]==='research/list').map(c=>[c[1].job,c[1].after,c[1].limit]),[['A','',100],['A','a',100]]);
  left.value='b';await ui.click(ui.button('main','Compare fields'));
  assert.equal(calls.at(-1)[1].left,'b');assert.equal(calls.at(-1)[1].job,'A');assert.ok(left.options.length<=101);
});

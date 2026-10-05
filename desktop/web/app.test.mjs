// Exercise the actual app controller with a small DOM/transport double. This
// proves request/render binding, not browser layout or live HTTP qualification.
import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
import vm from 'node:vm';
import * as model from './model.mjs';

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
  const roots=new Map();for(const id of ['nav','notice','inspector','stats','footer-source','binding','run-label','cancel','jobs','start','capture','mode','profile','main','title'])roots.set(id,new Element());
  const document={createElement:t=>new Element(t),createTextNode:t=>new Element('#text',String(t)),querySelector(selector){const id=selector.slice(1);return [...roots.values()].flatMap(walk).find(n=>n.attrs.id===id)??roots.get(id)??null;},querySelectorAll(){return [];}};
  const context=vm.createContext({...model,document,Node:Element,URLSearchParams,location:{hash:'',pathname:'/'},sessionStorage:{getItem(){return null;}},history:{replaceState(){}},reply,requestAnimationFrame:fn=>fn()});
  let source=readFileSync(new URL('./app.js',import.meta.url),'utf8');source=source.slice(source.indexOf('\n')+1);source=source.slice(0,source.lastIndexOf('\nsafe(init);'));
  vm.runInContext(source+'\napi=reply;',context);
  return {roots,run:code=>vm.runInContext(code,context),button(root,name){const b=walk(roots.get(root)).find(n=>n.tag==='button'&&n.textContent===name);assert.ok(b,'Missing button '+name);return b;},click:b=>b.events.get('click')[0]()};
}
function detail(job){return {event:{sequence:'1',kind:'packet.observed',status:'observed',evidence:{packets:[{frame:'1'}],spans:[],reconstructed_sha256:job}},parents:[],children:[],spans:[],truncated:false};}
function packet(job){return {hex:job==='A'?'41':'42',source_start:'0',captured_length:'1'};}

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

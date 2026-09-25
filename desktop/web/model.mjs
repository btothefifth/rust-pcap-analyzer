// Integer-safe, independently testable UI model. No packet interpretation here.
export const STATES=['observed','candidate','ambiguous','incomplete','unsupported','rejected'];
export function count(value){try{return BigInt(value??0).toLocaleString('en-US');}catch{return 'Unknown';}}
export function timestamp(ns){if(ns===null||ns===undefined)return 'Unknown';try{let n=BigInt(ns),sign=n<0n?'-':'';if(n<0n)n=-n;return `${sign}${n/1000000000n}.${(n%1000000000n).toString().padStart(9,'0')} s Unix`;}catch{return 'Unknown';}}
export function virtualRange(scroll,height,total,rowHeight=36,overscan=6){if(!Number.isFinite(scroll)||!Number.isFinite(height)||total<0||rowHeight<=0)throw Error('invalid viewport');const start=Math.max(0,Math.floor(Math.max(0,scroll)/rowHeight)-overscan);const end=Math.min(total,Math.ceil((Math.max(0,scroll)+Math.max(0,height))/rowHeight)+overscan);return {start:Math.min(start,total),end:Math.max(Math.min(start,total),end),top:Math.min(start,total)*rowHeight,bottom:Math.max(0,total-end)*rowHeight};}
export function shortValue(v,max=160){const s=typeof v==='string'?v:JSON.stringify(v);return (s??'Unknown').length>max?(s??'').slice(0,max)+'…':s??'Unknown';}
export function packetRefs(event){return event?.evidence?.packets??[];}
export function bytes(hex){if(typeof hex!=='string'||hex.length%2||!/^[0-9a-f]*$/i.test(hex))throw Error('invalid hex');return Array.from({length:hex.length/2},(_,i)=>parseInt(hex.slice(i*2,i*2+2),16));}
export function overlaps(a,b,c,d){return BigInt(a)<BigInt(d)&&BigInt(c)<BigInt(b);}

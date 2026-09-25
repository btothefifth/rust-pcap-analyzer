"""Offline UI renderer test with recorded real backend responses.

Uses about:blank plus an in-memory fetch/storage transport. This does NOT bypass
browser network restrictions and is NOT a live browser-to-server qualification.
Live local HTTP is tested independently in test_desktop_http.py.
"""
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import argparse,json,tempfile
from playwright.sync_api import sync_playwright
from tools.desktop import worker,store
from tools.research import cases,adapters,contract
from scripts.product_fixtures import pcap,packet
ROOT=Path(__file__).resolve().parents[1]

def main():
    p=argparse.ArgumentParser();p.add_argument('--receipts',type=Path,required=True);p.add_argument('--browser',default='/usr/bin/chromium');a=p.parse_args();a.receipts.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory()as td:
        root=Path(td);source=root/'synthetic-inspection.pcap';source.write_bytes(pcap([packet(b'example','udp')for _ in range(400)]));job=root/('a'*32);job.mkdir();assert worker.run(job,source,'container')==0
        status=json.loads((job/'state.json').read_text());db=job/'events.sqlite';rows=store.query(db,{'limit':200})['rows'];packet_row=next(r for r in rows if r['kind']=='packet.observed')
        left=adapters.container_normalize(source);right=json.loads(json.dumps(left));right['producer']['id']='synthetic-test-interpretation';right['producer']['origin']='manual_research';right['observations'][1]['value']['sha256']='f'*64;right['notes'].append('Intentionally altered fixture, not an observed external parser defect.')
        dataset={'config':{'engine_available':False},'captures':{'files':[{'path':source.name,'bytes':str(source.stat().st_size)}]},'jobs':{'jobs':[status]},'status':status,'overview':store.overview(db),'query':{'rows':rows,'next':rows[-1]['sequence'],'has_more':True,'limit':200},'event':store.detail(db,packet_row['sequence']),'packet':store.packet_bytes(db,source,'1'),'audit':cases.audit(ROOT),'catalog':json.loads((ROOT/'product/research/catalog.json').read_text()),'timeline':store.timeline(db),'research/list':{'interpretations':[{'id':'1'*32,'producer':left['producer']},{'id':'2'*32,'producer':right['producer']}]},'research/compare':contract.compare_fields(left,right)}
        html=(ROOT/'desktop/web/index.html').read_text();html=html.replace('<link rel="stylesheet" href="/style.css">','').replace('<script type="module" src="/app.js"></script>','')
        model=(ROOT/'desktop/web/model.mjs').read_text().replace('export ','')
        app=(ROOT/'desktop/web/app.js').read_text();app=app[app.index('\n')+1:]
        setup='''const FIXTURE=DATASET;
Object.defineProperty(window,'sessionStorage',{value:{getItem:()=>"renderer-test-token",setItem:()=>{}}});
window.history.replaceState=()=>{};
window.fetch=async(url,init)=>{const u=new URL(url,'http://fixture.invalid');const key=u.pathname.replace('/api/','');let value=FIXTURE[key];
if(key==='query'){value=structuredClone(value);const kind=u.searchParams.get('kind');if(kind)value.rows=value.rows.filter(r=>r.kind===kind);const limit=Number(u.searchParams.get('limit')||200);value.rows=value.rows.slice(0,limit);}
if(value===undefined)return new Response(JSON.stringify({error:'Not part of renderer fixture: '+key}),{status:400});
return new Response(JSON.stringify(value),{status:200,headers:{'Content-Type':'application/json'}});};
'''.replace('DATASET',json.dumps(dataset))
        with sync_playwright()as pw:
            browser=pw.chromium.launch(executable_path=a.browser,headless=True,args=['--no-sandbox']);page=browser.new_page(viewport={'width':1600,'height':1050});errors=[];requests=[]
            page.on('pageerror',lambda e:errors.append(str(e)));page.on('request',lambda r:requests.append(r.url));page.set_content(html);page.add_style_tag(content=(ROOT/'desktop/web/style.css').read_text());page.add_script_tag(content=setup+'\n'+model+'\n'+app)
            page.wait_for_function("document.querySelector('#jobs').options.length===2");page.select_option('#jobs','a'*32);page.wait_for_function("document.querySelector('#binding').textContent==='Source bytes checked'")
            page.screenshot(path=str(a.receipts/'gui-container-overview.png'),full_page=True)
            page.locator('[data-view="Packets & events"]').click();page.locator('tr[data-seq]').first.wait_for();assert page.locator('tr[data-seq]').count()<35
            page.locator('tr[data-seq]').filter(has_text='packet.observed').first.click();page.locator('#hex-block').wait_for();page.screenshot(path=str(a.receipts/'gui-evidence-inspector.png'),full_page=True)
            page.locator('[data-view="Research"]').click();page.get_by_role('button',name='Compare fields',exact=True).click();page.get_by_role('button',name='Jump to source witness').wait_for();page.screenshot(path=str(a.receipts/'gui-research-synthetic-disagreement.png'),full_page=True)
            page.locator('[data-view="Case catalog"]').click();page.get_by_label('Case filter').fill('bgp.framing-kat');page.locator('.case').first.click();assert 'bgp.framing-kat'in page.locator('#inspector').inner_text()
            page.set_viewport_size({'width':880,'height':1000});page.screenshot(path=str(a.receipts/'gui-responsive-layout.png'),full_page=True)
            assert not errors,errors;assert not requests,requests;browser.close()
        receipt={'status':'PASS','scope':'offline_renderer_with_recorded_real_backend_responses','full_live_browser_to_server':'BLOCKED_BY_MANAGED_BROWSER_POLICY','native_rust_analysis_tested':False,'synthetic_comparison_is_not_external_parser_bug':True,'javascript_errors':errors,'browser_network_requests':len(requests),'viewports':[[1600,1050],[880,1000]],'tests':['overview','bounded virtual rows','source hex inspector','differential view','case filtering','responsive layout']}
        (a.receipts/'gui-render-smoke.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
if __name__=='__main__':main()

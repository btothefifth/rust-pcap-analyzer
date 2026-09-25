"""Optional developer smoke test of the real loopback UI using synthetic captures.

Requires Playwright and an installed Chromium. No installed Rust tool is mocked:
without --engine this smoke proves container inspection + research/UI paths only.
With an explicit --engine, it also requires native BGP metadata in the fixture run.
"""
from __future__ import annotations
import argparse
import copy
import json
import os
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import subprocess
import sys
import tempfile
from urllib.parse import urlsplit
from playwright.sync_api import sync_playwright
ROOT=Path(__file__).resolve().parents[1]

def main(argv=None):
    p=argparse.ArgumentParser();p.add_argument('--browser',default='/usr/bin/chromium');p.add_argument('--receipts',type=Path,required=True);p.add_argument('--engine',type=Path);a=p.parse_args(argv);a.receipts.mkdir(parents=True,exist_ok=True)
    with tempfile.TemporaryDirectory(prefix='pcap-gui-test-')as td:
        workspace=Path(td)/'workspace'
        proc=subprocess.Popen([sys.executable,'-m','tools.desktop.server','--capture-root',str(ROOT/'product/tests/fixtures'),'--workspace',str(workspace)]+(['--engine',str(a.engine.resolve(strict=True))]if a.engine else []),cwd=ROOT,stdout=subprocess.PIPE,stderr=subprocess.PIPE,text=True,env={**os.environ,'PYTHONPATH':str(ROOT)})
        try:
            url=proc.stdout.readline().strip()
            if not url.startswith('http://127.0.0.1:'):raise RuntimeError('local GUI did not start')
            with sync_playwright()as pw:
                browser=pw.chromium.launch(executable_path=a.browser,headless=True,args=['--no-sandbox'])
                page=browser.new_page(viewport={'width':1600,'height':1050},device_scale_factor=1)
                errors=[];origins=set()
                page.on('pageerror',lambda e:errors.append(str(e)))
                page.on('request',lambda r:origins.add(urlsplit(r.url).hostname))
                page.goto(url);page.locator('#capture').fill('bgp.pcap');page.select_option('#mode','rust'if a.engine else 'container');page.locator('#start').click()
                page.wait_for_function("document.querySelector('#binding').textContent==='Source bytes checked'",timeout=15000)
                page.screenshot(path=str(a.receipts/'gui-container-overview.png'),full_page=True)
                if a.engine:
                    page.locator('[data-view="Protocols"]').click();page.locator('tr[data-seq]').filter(has_text='bgp').first.wait_for()
                page.locator('[data-view="Packets & events"]').click();page.locator('tr[data-seq]').first.wait_for()
                page.locator('tr[data-seq]').filter(has_text='packet.observed').first.click();page.locator('#hex-block').wait_for()
                assert 'hash checked' in page.locator('#hex-block').inner_text()
                page.screenshot(path=str(a.receipts/'gui-evidence-inspector.png'),full_page=True)
                page.locator('[data-view="Case catalog"]').click();page.get_by_label('Case filter').fill('bgp.framing-kat');page.locator('.case').first.click()
                assert 'bgp.framing-kat' in page.locator('#inspector').inner_text()
                page.locator('[data-view="Research"]').click();page.get_by_role('button',name='Run independent container',exact=True).click();page.locator('#left-view option').first.wait_for(state='attached')
                # Deliberately alter a *separately attributed synthetic* view to
                # test first-divergence navigation; never claim a real parser bug.
                from tools.research.adapters import container_normalize
                from tools.product.comparison import canonical
                snap=container_normalize(ROOT/'product/tests/fixtures/bgp.pcap');snap['producer']['id']='synthetic-test-interpretation';snap['producer']['origin']='manual_research';snap['observations'][1]['value']['sha256']='f'*64;snap['notes'].append('Intentionally altered test interpretation, not a real external parser defect.')
                imported=Path(td)/'synthetic.interpretation.json';imported.write_bytes(canonical(snap))
                page.get_by_label('Import attributed interpretation').set_input_files(str(imported));page.wait_for_function("document.querySelectorAll('#right-view option').length===2")
                page.get_by_role('button',name='Compare fields',exact=True).click();page.get_by_role('button',name='Jump to source witness').wait_for()
                page.get_by_role('button',name='Jump to source witness').click();page.locator('#hex-block').wait_for()
                page.screenshot(path=str(a.receipts/'gui-research-synthetic-disagreement.png'),full_page=True)
                page.check('#raw-ack')
                with page.expect_download()as download:page.get_by_role('button',name='Export adjudication bundle',exact=True).click()
                local=Path(td)/'export.zip';download.value.save_as(local)
                from tools.research.bundle import verify
                result=verify(local);assert result['status']=='PASS'
                page.set_viewport_size({'width':880,'height':1000});page.screenshot(path=str(a.receipts/'gui-responsive-layout.png'),full_page=True)
                assert not errors,errors
                assert origins=={'127.0.0.1'},origins
                browser.close()
                receipt={'status':'PASS','tested':'real_loopback_gui_native_and_research_paths'if a.engine else 'real_loopback_gui_container_reference_and_research_paths','browser':'Chromium','screenshots':['gui-container-overview.png','gui-evidence-inspector.png','gui-research-synthetic-disagreement.png','gui-responsive-layout.png'],'native_rust_analysis_tested':bool(a.engine),'synthetic_disagreement_not_vulnerability':True,'export_independently_verified':True,'page_errors':errors,'off_box_requests':False}
                (a.receipts/'gui-smoke.json').write_text(json.dumps(receipt,indent=2)+'\n');print(json.dumps(receipt))
        finally:
            proc.terminate()
            try:proc.wait(timeout=5)
            except subprocess.TimeoutExpired:proc.kill();proc.wait()
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Actual browser -> HTTP manager -> worker -> Rust engine -> index -> hex check.

Requires an already built local native product and installed Playwright/Chromium.
Does not mock fetch, substitute container mode, download tools or disable browser
security. Native/renderer absence is BLOCKED, not a screenshot-based pass.
"""
from __future__ import annotations
import argparse
import hashlib
import json
from pathlib import Path
import platform
import shutil
import sys
import threading
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))

def check(output,engine):
    output=Path(output).resolve();output.mkdir()
    receipt={'schema':'pcap-evidence.browser-native-check.v1','status':'BLOCKED',
             'platform':platform.platform(),'mocked_responses':False,'container_fallback':False}
    def finish():
        (output/'receipt.json').write_text(json.dumps(receipt,indent=2)+'\n')
        return {'PASS':0,'FAIL':1,'BLOCKED':2}[receipt['status']]
    if not engine or not Path(engine).is_file():
        receipt['reason']='Compiled native product executable unavailable';return finish()
    try:from playwright.sync_api import sync_playwright
    except ImportError:
        receipt['reason']='Optional Playwright unavailable';return finish()
    from tools.desktop.server import Manager,Server
    captures=output/'captures';captures.mkdir();source=captures/'reorder.pcap'
    shutil.copyfile(ROOT/'history/fixtures/reorder.pcap',source)
    receipt['source_sha256']=hashlib.sha256(source.read_bytes()).hexdigest()
    receipt['engine_sha256']=hashlib.sha256(Path(engine).read_bytes()).hexdigest()
    manager=Manager(captures,output/'workspace',Path(engine).resolve())
    server=Server(('127.0.0.1',0),manager);thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    try:
        with sync_playwright()as pw:
            try:browser=pw.chromium.launch()
            except Exception as error:
                receipt['reason']='Installed browser unavailable: '+str(error)[:256];return finish()
            with browser:
                page=browser.new_page(viewport={'width':1440,'height':1000});errors=[]
                page.on('pageerror',lambda error:errors.append(str(error)))
                try:page.goto(server.origin+'/#token='+server.token,wait_until='networkidle',timeout=30000)
                except Exception as error:
                    receipt['reason']='Actual loopback browser navigation blocked/unavailable: '+str(error)[:256];return finish()
                page.wait_for_function("document.querySelector('#mode').value==='rust' && !document.querySelector('#mode option[value=rust]').disabled")
                page.locator('#capture').fill(source.name);page.locator('#start').click()
                page.wait_for_function("document.querySelector('#run-label').textContent.includes('Independent Rust engine · complete')",timeout=120000)
                jobs=manager.jobs()
                if len(jobs)!=1 or jobs[0]['mode']!='rust' or jobs[0]['state']!='complete' or jobs[0].get('source_sha256')!=receipt['source_sha256']:
                    raise AssertionError('Native source binding differs from browser status')
                page.locator('#nav button[data-view="Packets & events"]').click()
                page.get_by_label('Event kind',exact=True).fill('packet.observed')
                page.get_by_role('button',name='Apply',exact=True).click()
                row=page.locator('tr[data-seq]').first;row.wait_for();row.focus();page.keyboard.press('Enter')
                page.locator('#hex-block').wait_for()
                if 'hash checked' not in page.locator('#hex-block').inner_text():raise AssertionError('No checked source-byte view')
                if errors:raise AssertionError('Browser errors: '+str(errors))
                page.screenshot(path=str(output/'browser-native.png'),full_page=True)
                receipt.update(status='PASS',packets=jobs[0]['packets'],source_binding=jobs[0]['source_binding'],
                               keyboard_evidence_navigation=True,accessibility_scope='keyboard activation and labeled controls only; not full WCAG',
                               semantic_replay_verified=False)
    except Exception as error:receipt.update(status='FAIL',reason=str(error)[:512])
    finally:
        manager.close();server.shutdown();server.server_close();thread.join(timeout=5)
    return finish()
if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__);p.add_argument('--output',type=Path,required=True);p.add_argument('--engine',type=Path);a=p.parse_args();raise SystemExit(check(a.output,a.engine))

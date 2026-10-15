#!/usr/bin/env python3
"""The page with a NOSTR extension, in headless Chromium, against the mock.

    python3 tool/build.py && /usr/bin/python3 test/ext_smoke.py

A stand-in `window.nostr` (a BIP-340 signer holding a toy key, and a nip04) is
injected before the page loads. The test proves the page offers it, adopts the
account (the callsign the key derives), sends a packet whose 80-character sig a
separate pure-Python BIP-340 verifier accepts for the rebuilt NOSTR event, seals
a DM through the extension's nip04, and opens one the same way.
"""
import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import sys
import time
import urllib.request

import websockets

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import bip340_ref as ref  # noqa: E402

ROOT = os.path.dirname(HERE)
PROF = os.path.expanduser('~/snap/chromium/common/webchat-ext-prof')
PORT, CDP = 8792, 9466
D = 7
fails = 0

EXT = r"""
(function(){
  var d=7n;
  function tg(tag,m){var th=sha256(s2b(tag));return sha256(cat(th,th,m));}
  var pub=null;
  window.nostr={
    getPublicKey:function(){pub=pubkeyX(n2b(d,32));return Promise.resolve(hex(pub));},
    signEvent:function(ev){
      pub=pubkeyX(n2b(d,32));var ph=hex(pub);
      var ser='[0,"'+ph+'",'+ev.created_at+','+ev.kind+',[],"'+ev.content+'"]';
      var id=sha256(u8(ser)),dd=d,P=mulG(dd);if(P[1]&1n){dd=N-dd;P=mulG(dd);}
      var t=n2b(dd^b2n(tg('BIP0340/aux',new Uint8Array(32))),32);
      var k=mod(b2n(tg('BIP0340/nonce',cat(t,pub,id))),N),R=mulG(k);
      if(R[1]&1n){k=N-k;R=mulG(k);}
      var rx=n2b(R[0],32),e=mod(b2n(tg('BIP0340/challenge',cat(rx,pub,id))),N);
      var sig=cat(rx,n2b(mod(k+e*dd,N),32));
      return Promise.resolve({kind:ev.kind,created_at:ev.created_at,tags:[],content:ev.content,
        pubkey:ph,id:hex(id),sig:hex(sig)});},
    nip04:{
      encrypt:function(pk,text){
        var key=ecdhX(n2b(d,32),unhexBytes(pk)),iv=new Uint8Array(16).fill(9);
        return Promise.resolve(b64sEnc(cbcEncrypt(key,iv,u8(text)))+'?iv='+b64sEnc(iv));},
      decrypt:function(pk,c){
        var p=c.split('?iv='),key=ecdhX(n2b(d,32),unhexBytes(pk));
        var out=cbcDecrypt(key,b64sDec(p[1]),b64sDec(p[0]));
        return Promise.resolve(utf8Dec(out));}}
  };
})();
"""


def check(ok, what):
    global fails
    print(('  [PASS] ' if ok else '  [FAIL] ') + what)
    fails += 0 if ok else 1


async def main():
    mock = subprocess.Popen([sys.executable, os.path.join(ROOT, 'contract', 'mock_station.py'), str(PORT)])
    shutil.rmtree(PROF, ignore_errors=True)   # the page keeps its room and key in localStorage
    os.makedirs(PROF, exist_ok=True)
    chrome = subprocess.Popen(['chromium', '--headless=new', '--no-sandbox', '--disable-gpu',
                               '--user-data-dir=' + PROF, '--remote-debugging-port=%d' % CDP, 'about:blank'],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        ws_url = None
        for _ in range(60):
            time.sleep(0.5)
            try:
                tabs = json.load(urllib.request.urlopen('http://127.0.0.1:%d/json' % CDP))
                ws_url = next(t['webSocketDebuggerUrl'] for t in tabs if t['type'] == 'page')
                break
            except Exception:
                pass
        async with websockets.connect(ws_url, max_size=None) as ws:
            n = 0

            async def send(method, params=None):
                nonlocal n
                n += 1
                await ws.send(json.dumps({'id': n, 'method': method, 'params': params or {}}))
                while True:
                    m = json.loads(await ws.recv())
                    if m.get('id') == n:
                        return m.get('result', {})

            async def ev(js):
                r = await send('Runtime.evaluate', {'expression': js, 'awaitPromise': True, 'returnByValue': True})
                return r.get('result', {}).get('value')

            # The stand-in extension is installed once the page has loaded (it
            # borrows the page's own curve helpers to sign), the way a real one
            # injects window.nostr a moment after the page starts.
            await send('Page.enable')
            await send('Page.navigate', {'url': 'http://127.0.0.1:%d/' % PORT})
            await asyncio.sleep(3)
            check(await ev("document.getElementById('extbtn').style.display==='none'"),
                  'with no extension the page does not offer one')
            await ev(EXT + "1")
            await ev("showExtButton(),1")
            check(await ev("document.getElementById('extbtn').style.display!=='none'"),
                  'with one it offers "Use my NOSTR extension"')
            await ev("(toggleExtension(),1)")
            await asyncio.sleep(2)
            expect = await ev("callsignFromNpub(npubEncode(pubkeyX(n2b(7n,32))))")
            check(await ev("extMode") is True and await ev("mycall") == expect,
                  'the page adopts the account: callsign %s from the extension key' % expect)
            check(await ev("sess!==''"), 'a session is proven through the extension')
            await ev("(document.getElementById('txt').value='signed by the extension',sendMsg(),1)")
            await asyncio.sleep(2)
            sent = json.load(urllib.request.urlopen('http://127.0.0.1:%d/__sent' % PORT))
            msg = [w for w in sent if w.startswith('t:message')]
            check(len(msg) == 1, 'the message was posted once')
            if msg:
                w = msg[0]
                sig = w.split(' sig:')[1].split(' ')[0]
                check(len(sig) == 80, 'its sig: is 80 characters (the second form)')
                canon = w.replace(' sig:' + sig, '')
                ts = canon.split(' ts:')[1].split(' ')[0]
                import calendar
                created = calendar.timegm(time.strptime(ts, '%Y-%m-%d_%H:%M:%S'))
                px = ref.mul(D)[0].to_bytes(32, 'big')
                m = hashlib.sha256(canon.encode()).digest()
                event = json.dumps([0, px.hex(), created, 24767, [], m.hex()], separators=(',', ':'))
                eid = hashlib.sha256(event.encode()).digest()
                raw = b''
                v = 0
                # base85 decode with the spec alphabet
                for i in range(0, 80, 5):
                    v = 0
                    for c in sig[i:i + 5]:
                        v = v * 85 + ref.B85.index(c)
                    raw += v.to_bytes(4, 'big')
                check(ref.verify(eid, raw, px), 'a separate BIP-340 verifier accepts it for the rebuilt event')
                check(w.split(' f:')[1].split(' ')[0] == expect, 'and it is written as the account\'s callsign')
            # A DM sealed through the extension's nip04, and one opened by it.
            await ev("""(async()=>{
              var peer=n2b(0x1234567890abcdef1234567890abcdefn,32), pp=pubkeyX(peer);
              var post=(p,b)=>fetch(p,{method:'POST',body:JSON.stringify(b)});
              await post('/__row',{ts:1790000000,bearer:'lan',rssi:0,from:'X1PEER',to:'',type:'identity',sig:'verified',own:false,
                wire:'t:identity f:X1PEER ts:2026-10-15_12:00:00 k:'+npubEncode(pp)});
              var x=sealBody(peer,pubkeyX(n2b(7n,32)),'a secret for the extension');
              await post('/__inject',{from:'X1PEER',to:mycall,wire:'t:message f:X1PEER d:'+mycall+' ts:2026-10-15_12:00:01 x:'+x});
              return 1;})()""")
            await ev("(load(),1)")
            await asyncio.sleep(2)
            await ev("(openDm('X1PEER'),1)")
            await asyncio.sleep(3)
            check('a secret for the extension' in (await ev("document.getElementById('msgs').innerText") or ''),
                  'a sealed message is opened by the extension\'s nip04')
            await ev("(document.getElementById('txt').value='sealed by the extension',sendMsg(),1)")
            await asyncio.sleep(3)
            sent = json.load(urllib.request.urlopen('http://127.0.0.1:%d/__sent' % PORT))
            dm = [w for w in sent if ' d:X1PEER' in w]
            check(len(dm) == 1 and ' x:' in dm[0] and ' m:' not in dm[0], 'the reply goes out sealed')
            if dm:
                x = dm[0].split(' x:')[1].split(' ')[0]
                back = await ev("openBody(n2b(0x1234567890abcdef1234567890abcdefn,32),pubkeyX(n2b(7n,32)),%s)" % json.dumps(x))
                check(back == 'sealed by the extension', 'and the peer\'s key opens what the extension sealed')
                check(len(dm[0].split(' sig:')[1].split(' ')[0]) == 80, 'signed in the second form too')
    finally:
        chrome.terminate()
        mock.terminate()


asyncio.run(main())
sys.exit(1 if fails else 0)

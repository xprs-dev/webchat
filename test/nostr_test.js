// The NOSTR-signer path of the page (XPRS.md 6.1.3, 6.2) against a stand-in
// extension: it must produce the specification's worked packet byte for byte,
// refuse a signer that signed something else, and convert nip04 to `x:` and
// back. Also the UTF-8 fix to the short signature.
//   node test/nostr_test.js
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'page');
const src = ['xprs_crypto.js', 'xprs_seal.js', 'xprs_nostr.js']
  .map(f => fs.readFileSync(path.join(dir, f), 'utf8')
    .split('// ---- node test against the spec 9.1.2 worked example ----')[0]).join('\n');
const nodeCrypto = require('crypto');
const win = {};
const api = new Function('window', src + `
  return {xprsSign, u8, sha256, s2b, cat, n2b, b2n, mod, mulG, N, hex, b85enc, pubkeyX,
          nostrEventFor, nostrSignWire, nip04ToX, xToNip04, nostrSeal, nostrOpen,
          sealBody, openBody, ecdhX, cbcEncrypt, cbcDecrypt, b64sEnc, b64sDec, tsEpoch};`)(win);

let fails = 0;
function check(ok, what) { console.log((ok ? '  [PASS] ' : '  [FAIL] ') + what); if (!ok) fails++; }

// A stand-in NIP-07 extension holding key d: BIP-340 signEvent with aux zero.
function extension(d, opts = {}) {
  const tagged = (tag, m) => { const th = api.sha256(api.s2b(tag)); return api.sha256(api.cat(th, th, m)); };
  const pub = api.pubkeyX(api.n2b(d, 32));
  const pubHex = api.hex(pub);
  return {
    pubHex,
    getPublicKey: async () => pubHex,
    signEvent: async (ev) => {
      const created = opts.created ?? ev.created_at;
      const content = opts.content ?? ev.content;
      const ser = `[0,"${pubHex}",${created},${ev.kind},[],"${content}"]`;
      const id = api.sha256(api.u8(ser));
      let dd = d; let P = api.mulG(dd); if (P[1] & 1n) { dd = api.N - dd; P = api.mulG(dd); }
      const t = api.n2b(dd ^ api.b2n(tagged('BIP0340/aux', new Uint8Array(32))), 32);
      let k = api.mod(api.b2n(tagged('BIP0340/nonce', api.cat(t, pub, id))), api.N);
      let R = api.mulG(k); if (R[1] & 1n) { k = api.N - k; R = api.mulG(k); }
      const rx = api.n2b(R[0], 32);
      const e = api.mod(api.b2n(tagged('BIP0340/challenge', api.cat(rx, pub, id))), api.N);
      const sig = api.cat(rx, api.n2b(api.mod(k + e * dd, api.N), 32));
      return { ...ev, created_at: created, content, pubkey: pubHex, id: api.hex(id), sig: api.hex(sig) };
    },
    nip04: opts.nip04,
  };
}

(async () => {
  // 1. The worked example of 6.1.3, byte for byte.
  const canon = 't:message f:X1QZ3N d:LISBOA ts:2026-08-08_14:26:40 m:net starts in ten minutes';
  const want = 't:message f:X1QZ3N d:LISBOA ts:2026-08-08_14:26:40 sig:QPxg^#t7^xDBU$s1pg.d.u^UZ$B0qYj%c.(I[)FY?%WouV6?)^xS[jf,ftorZ=$fRs>JwXM_GfY&bYO@ m:net starts in ten minutes';
  const ext = extension(7n);
  win.nostr = ext;
  const ev = api.nostrEventFor(ext.pubHex, canon);
  check(ev.id === 'a61fa6b5694b2696babb94cbaa1d0bcf43d4093e731893fc59ebfd7dcd31fb5e', 'the event id matches the spec');
  const got = await new Promise(r => api.nostrSignWire(canon, ext.pubHex, (w, why) => r(w || 'ERR ' + why)));
  check(got === want, 'the signed packet is the spec\'s, byte for byte (' + got.length + ' bytes)');

  // 2. A signer that changed what it signed is refused.
  for (const [name, opts] of [['time', { created: 1 }], ['content', { content: '00'.repeat(32) }]]) {
    win.nostr = extension(7n, opts);
    const r = await new Promise(res => api.nostrSignWire(canon, ext.pubHex, (w, why) => res(w ? 'SIGNED' : why)));
    check(r === 'the signer returned something else', `a signer that altered the ${name} is refused`);
  }
  win.nostr = { getPublicKey: async () => ext.pubHex, signEvent: async () => { throw new Error('User denied'); } };
  check(await new Promise(r => api.nostrSignWire(canon, ext.pubHex, (w, why) => r(why))) === 'User denied',
    'a refusal by the user is passed on');
  check(await new Promise(r => api.nostrSignWire('t:message f:X1QZ3N m:hi', ext.pubHex, (w, why) => r(why)))
        === 'this packet has no time to sign', 'a packet with no ts: is not sent to be signed');

  // 3. A packet with no m: gets sig: at the end; accents are hashed as UTF-8.
  win.nostr = ext;
  const noM = await new Promise(r => api.nostrSignWire('t:reaction f:X1QZ3N ts:2026-08-08_14:26:40 add:like r:399227', ext.pubHex, w => r(w)));
  check(/ r:399227 sig:\S{80}$/.test(noM), 'with no m: the signature goes last');
  const ac = 't:message f:X1QZ3N ts:2026-08-08_14:26:40 m:héllo ✓';
  const evA = api.nostrEventFor(ext.pubHex, ac);
  check(JSON.stringify(evA.event.content) === JSON.stringify(
    nodeCrypto.createHash('sha256').update(Buffer.from(ac, 'utf8')).digest('hex')),
    'the content digest is over the UTF-8 bytes');

  // 4. The short form hashes UTF-8 too (it used to take the low byte of each
  // unit): the signature below is the Dart implementation's, aux zero, d = 7.
  const aux = new Uint8Array(32);
  check(api.b85enc(api.xprsSign(ac, 7n, aux)) === '+1>#x20q<j7y,G[!KaE&RjGns0nq8cC;qucl47lQ>%]Krl1<uXKxApQp;QxA',
    'the short signature of a message with accents is the one Dart makes');

  // 5. nip04 <-> x: is the same bytes in another wrapping, and opens from either end.
  const a = api.n2b(7n, 32), b = api.n2b(0x1234567890abcdef1234567890abcdefn, 32);
  const pubA = api.pubkeyX(a), pubB = api.pubkeyX(b);
  const dart = 'mzGToeRSvhF6bPE9Wy7LhElQ5t1F4lpI19X0SiyRoGzunbynMvZ7Rgtr2J19fw7m';
  const nip = api.xToNip04(dart);
  check(/^[A-Za-z0-9+/]+=*\?iv=[A-Za-z0-9+/]+=*$/.test(nip), 'x: becomes nip04 content');
  check(api.nip04ToX(nip) === dart, 'and back to the same x:');
  const peer = {
    nip04: {
      // an extension holding b: nip04 with the same cipher
      encrypt: async (pk, t) => {
        const key = api.ecdhX(b, unhex(pk)); const iv = new Uint8Array(16).fill(5);
        const ct = api.cbcEncrypt(key, iv, api.u8(t));
        return api.b64sEnc(ct) + '?iv=' + api.b64sEnc(iv);
      },
      decrypt: async (pk, c) => {
        const [ct, iv] = c.split('?iv=');
        const out = api.cbcDecrypt(api.ecdhX(b, unhex(pk)), api.b64sDec(iv), api.b64sDec(ct));
        return Buffer.from(out).toString('utf8');
      },
    },
  };
  const unhex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));
  win.nostr = peer;
  const opened = await new Promise(r => api.nostrOpen(api.hex(pubA), dart, r));
  check(opened === 'héllo from a to b ✓', 'the extension opens an x: the app sealed');
  const sealedByExt = await new Promise(r => api.nostrSeal(api.hex(pubA), 'sealed by the extension', r));
  check(api.openBody(a, pubB, sealedByExt) === 'sealed by the extension',
    'what the extension seals opens with the page\'s own sealing (and so with Dart\'s)');
  win.nostr = { getPublicKey: async () => 'x' };
  check(await new Promise(r => api.nostrSeal(api.hex(pubA), 'x', r)) === null, 'no nip04: it says so instead of failing');
  process.exit(fails ? 1 : 0);
})();

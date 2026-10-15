// The sealing in page/xprs_seal.js against known answers: FIPS-197's AES-256
// vector, and an `x:` produced by the app's Dart implementation (so the two
// agree byte for byte, which is what a sealed DM between them needs).
//   node test/seal_test.js
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'page');
const src = ['xprs_crypto.js', 'xprs_seal.js']
  .map(f => fs.readFileSync(path.join(dir, f), 'utf8')
    .split('// ---- node test against the spec 9.1.2 worked example ----')[0]).join('\n');
const api = new Function('window', src + `
  return {aesExpand, aesBlock, cbcEncrypt, cbcDecrypt, ecdhX, sealBody, openBody,
          b64uEnc, b64uDec, n2b, pubkeyX, hex};`)({});

let fails = 0;
function check(ok, what) { console.log((ok ? '  [PASS] ' : '  [FAIL] ') + what); if (!ok) fails++; }
const unhex = h => Uint8Array.from(h.match(/../g).map(x => parseInt(x, 16)));

// FIPS-197 C.3: AES-256, key 00..1f, plaintext 00112233..ff.
const key = Uint8Array.from({length: 32}, (_, i) => i);
const pt = unhex('00112233445566778899aabbccddeeff');
const w = api.aesExpand(key);
const enc = api.aesBlock(w, Uint8Array.from(pt), true);
check(api.hex(enc) === '8ea2b7ca516745bfeafc49904b496089', 'AES-256 encrypts the FIPS-197 block');
check(api.hex(api.aesBlock(w, Uint8Array.from(enc), false)) === api.hex(pt), 'and decrypts it');

// CBC round trip with padding at every length.
for (let n = 0; n <= 40; n += 7) {
  const data = Uint8Array.from({length: n}, (_, i) => (i * 37) & 255);
  const iv = Uint8Array.from({length: 16}, (_, i) => 255 - i);
  const back = api.cbcDecrypt(key, iv, api.cbcEncrypt(key, iv, data));
  check(back && api.hex(back) === api.hex(data), `CBC round trip, ${n} bytes`);
}
check(api.cbcDecrypt(key, new Uint8Array(16), new Uint8Array(15)) === null, 'a ragged ciphertext is refused');

// ECDH and the seal against the Dart implementation (private keys 7 and 0x1234...).
const a = api.n2b(7n, 32);
const b = api.n2b(0x1234567890abcdef1234567890abcdefn, 32);
const pubA = api.pubkeyX(a), pubB = api.pubkeyX(b);
check(api.hex(pubB) === '9377c312145a5afb911bf9e8c067bcf6094c533603687850df502b61290bbf5e', 'public key matches Dart');
check(api.hex(api.ecdhX(a, pubB)) === '4246db82d37da24d249e3aa885abbc655b343cdf7001d05930b09ce2cd1ab421',
  'the ECDH secret matches Dart');
check(api.hex(api.ecdhX(b, pubA)) === api.hex(api.ecdhX(a, pubB)), 'and is the same from the other end');
const dart = 'mzGToeRSvhF6bPE9Wy7LhElQ5t1F4lpI19X0SiyRoGzunbynMvZ7Rgtr2J19fw7m';
check(api.openBody(a, pubB, dart) === 'héllo from a to b ✓', 'opens what Dart sealed, accents and all');
check(api.openBody(b, pubA, dart) === 'héllo from a to b ✓', 'from either end');
const mine = api.sealBody(a, pubB, 'sealed in the page');
check(api.openBody(b, pubA, mine) === 'sealed in the page', 'opens what it sealed itself');
check(api.openBody(api.n2b(9n, 32), pubB, mine) === null, 'a third key does not open it');
check(api.sealBody(a, pubB, 'x'.repeat(15)).length === 43, 'a body of up to 15 bytes seals to 43 characters (6.2)');
check(api.sealBody(a, pubB, 'x'.repeat(16)).length === 64, 'and 16 bytes to 64');
process.exit(fails ? 1 : 0);

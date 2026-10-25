// The Traffic tab's merge (page/chat_page.html trafficGroups): copies of one
// packet that differ only in bearer, via: or sig: are one entry, with a tag
// per direction and bearer.
//   node test/traffic_test.js
const fs = require('fs');
const path = require('path');
const dir = path.join(__dirname, '..', 'page');
const crypto = fs.readFileSync(path.join(dir, 'xprs_crypto.js'), 'utf8')
  .split('// ---- node test against the spec 9.1.2 worked example ----')[0];
const page = fs.readFileSync(path.join(dir, 'chat_page.html'), 'utf8');
const pick = name => {
  const i = page.indexOf('function ' + name + '(');
  if (i < 0) throw new Error('no ' + name + ' in the page');
  let depth = 0, j = page.indexOf('{', i);
  for (; j < page.length; j++) {
    if (page[j] === '{') depth++;
    else if (page[j] === '}' && --depth === 0) break;
  }
  return page.slice(i, j + 1);
};
const api = new Function('window', crypto + pick('wireId') + pick('trafficGroups') +
  'return {trafficGroups};')({});

let fails = 0;
function check(ok, what) { console.log((ok ? '  [PASS] ' : '  [FAIL] ') + what); if (!ok) fails++; }

const w = 't:message f:X1LC7H d:X3SEP2 ts:2026-10-23_18:40:27 m:hi';
const row = (bearer, own, extra, rssi) => ({ts: 1792780827, bearer, rssi: rssi || 0,
  from: 'X1LC7H', to: 'X3SEP2', type: 'message', sig: 'none', own, wire: w + (extra || '')});
const rows = [
  row('lan', true), row('espnow', true), row('lan', true), row('ble', true),
  row('espnow', false, ' via:X3SQS6', -61), row('espnow', false, ' via:X3SQS6', -48),
  {ts: 1792780800, bearer: 'lora', rssi: -90, from: 'MT1', to: '', type: 'message',
   sig: 'none', own: false, wire: 't:message f:MT1 ts:2026-10-23_18:40:00 m:other'},
];
const gs = api.trafficGroups(rows);
check(gs.length === 2, 'seven copies of two packets are two entries');
const g = gs[0];
check(g.own, 'the merged entry is ours: we sent it');
check(g.tagOrder.join(' ') === 'sent|lan sent|espnow sent|ble heard|espnow',
      'one tag per direction and bearer, in the order first seen');
check(g.tags['sent|lan'].n === 2, 'a repeated copy on one bearer is counted, not listed twice');
check(g.tags['heard|espnow'].rssi === -48, 'the loudest copy gives the signal');
check(gs[1].tagOrder.join() === 'heard|lora', 'a packet heard once keeps its one tag');
process.exit(fails ? 1 : 0);

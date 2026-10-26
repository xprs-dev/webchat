// The Devices tab's Distance cell (page/chat_page.html distCell): a relayed
// station is as far as the relay plus the relay's own reading of it, which
// the station sums into dist_m; without that reading the leg to the relay is
// shown as a floor.
//   node test/devices_test.js
const fs = require('fs');
const path = require('path');
const page = fs.readFileSync(path.join(__dirname, '..', 'page', 'chat_page.html'), 'utf8');
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
const api = new Function(pick('esc') + pick('distCell') + 'return {distCell};')();

let fails = 0;
function check(ok, what) { console.log((ok ? '  [PASS] ' : '  [FAIL] ') + what); if (!ok) fails++; }

let h = api.distCell({call: 'X3SEP2', dist_m: 12, hops: 0});
check(h === '<span>~12 m</span>', 'a neighbour is its distance: ' + h);
h = api.distCell({call: 'X3SEP2', dist_m: -1, hops: 0});
check(h === '-', 'a neighbour on a link with no signal: ' + h);
h = api.distCell({call: 'MT1234', dist_m: 19, hops: 1, via: 'X3SEP2', near_m: 12, far_m: 7});
check(/~19 m<\/span> <span class="dim">via X3SEP2<\/span>$/.test(h) && /12 m to X3SEP2, ~7 m from there/.test(h),
      'relayed and said: the sum, the relay, the legs in the title: ' + h);
h = api.distCell({call: 'MT1234', dist_m: -1, hops: 1, via: 'X3SEP2', near_m: 12, far_m: -1});
check(/&gt;~12 m<\/span> <span class="dim">via X3SEP2<\/span>$/.test(h) && /has not said how far MT1234/.test(h),
      'relayed, unsaid: the first leg as a floor: ' + h);
h = api.distCell({call: 'MT1234', dist_m: -1, hops: 2, via: 'X1LAP', near_m: -1, far_m: -1});
check(h === '- <span class="dim">via X1LAP</span>', 'relayed over a link with no signal: ' + h);
h = api.distCell({call: 'X', dist_m: 3, hops: 1, via: '<b>', near_m: 1, far_m: 2});
check(h.indexOf('<b>') < 0 && h.indexOf('&lt;b&gt;') >= 0, 'the relay name is escaped');

console.log(fails ? fails + ' FAILED' : 'all passed');
process.exit(fails ? 1 : 0);

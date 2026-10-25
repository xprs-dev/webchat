# Reusable pieces in the web chat

- **`wireId(w)`** (`page/chat_page.html`): the XPRS.md 5 identifier in the
  browser, `via:` and `sig:` left out. Use it wherever two rows may be copies of
  one packet: chat bubbles and the Traffic merge both key on it.
- **`trafficGroups(rows)`**: folds history rows into one entry per packet with
  a tag per direction (`sent`/`heard`) and bearer, the loudest RSSI per tag and
  a copy count. Any list of archive rows that should read as packets rather
  than copies can reuse it.
- **`backfillRooms()`**: asks a list of `/api/xprs/history` questions one after
  another on the shared `getJSON`, never in parallel, because a board has one
  HTTP worker. Reuse the chained shape for any one-off series of reads.
- **`pick(name)` in `test/traffic_test.js`**: lifts one function out of the
  page source by brace matching, so a page function is unit-tested in Node
  without a browser.

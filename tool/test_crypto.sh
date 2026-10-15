#!/bin/sh
# The crypto the page ships must reproduce the XPRS.md 9.1.2 worked example.
cd "$(dirname "$0")/.." && node page/xprs_crypto.js

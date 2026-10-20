import test from 'node:test';
import assert from 'node:assert/strict';
import {readFileSync} from 'node:fs';
const read=f=>readFileSync(new URL('../'+f,import.meta.url),'utf8');
const html=read('index.html'),js=read('src/app.mjs'),
  src=read('src/intent-compare.mjs'),css=read('style.css'),README=read('README.md');

test('visible optional intended spend in own browser, canonical Base Circle USDC only',()=>{
  assert(html.includes('id="intended-spend"'));
  assert(html.includes('for="intended-spend"'));
  assert(html.includes('inputmode="decimal"'));
  assert(html.includes('50'));
  assert(html.includes('native Circle USDC on Base'));
  assert(html.includes('This is NOT the current onchain allowance'));
});
test('optional new input actually reaches pure local comparison, preserving old signer analysis',()=>{
  assert(js.includes('import {compareUnsignedApprovalIntent} from "./intent-compare.mjs"'));
  assert(js.includes('compareUnsignedApprovalIntent(result,$("intended-spend").value.trim())'));
  assert(js.includes('addDetail("Intended spend on Base (Circle USDC)"'));
  assert(js.includes('addDetail("Approval / intended amount"'));
});
test('sample ERC20 approval loads fictional $50, other samples do not silently inherit it',()=>{
  assert(js.includes('id==="sample-calldata"?"50":""'));
  assert(js.includes('value="";$("expected-spender").value="";$("expected-contract").value="";$("intended-spend").value=""'));
});
test('editing amount invalidates stale report; download remains disabled until recalculation',()=>{
  assert(js.includes('$("intended-spend").addEventListener("input"'));
  assert(js.includes('previous scope receipt is stale'));
  assert(js.includes('$("download").disabled=true'));
});
test('new helper and frontend make zero network, wallet, signer or tracking calls',()=>{
  for(const source of [js,src]){
    assert(!/\bfetch\s*\(|XMLHttpRequest|navigator\.sendBeacon|localStorage|sessionStorage|eth_sendTransaction|eth_signTypedData|window\.ethereum|eth_requestAccounts/.test(source));
  }
  assert(html.includes("connect-src 'none'"));
  assert(html.includes("form-action 'none'"));
});
test('cache bust has one local module but separate static helper import',()=>{
  assert.deepEqual([...html.matchAll(/<script\b[^>]*src="([^"]+)"/g)].map(x=>x[1]),
    ['./src/app.mjs?v=20261020-intended-base-usdc-spend']);
  assert(js.includes('from "./analysis.mjs?v=20261020-sigtransfer"'));
  assert(js.includes('from "./intent-compare.mjs"'));
});
test('human-readable risk warnings never claim actual allowance or safe signature',()=>{
  for(const warning of ['UNLIMITED_APPROVAL_FOR_LIMITED_INTENT',
    'UNVERIFIED_USDC_TOKEN','INTENT_COMPARISON_CHAIN_UNKNOWN',
    'APPROVAL_EQUALS_INTENDED','NOT_ERC20_APPROVAL']){
    assert(src.includes(warning));
  }
  assert(src.includes('does NOT inspect a previously granted allowance') ||
         src.includes('does NOT inspect a previously granted allowance'.replace('does','It does')) ||
         src.includes('does NOT inspect a previously granted allowance'));
  assert(README.includes('NOT any existing onchain token allowance'));
  assert(README.includes('not evidence they'));
});
test('small screens show a separate visible intended amount panel',()=>{
  assert(css.includes('.intent-panel{'));
  assert(css.includes('.intent-panel input{'));
  assert(css.includes('@media(max-width:520px)'));
});

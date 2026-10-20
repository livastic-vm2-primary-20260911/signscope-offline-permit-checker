import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {SAMPLE_BROKEN_ALLOWANCE,SAMPLE_SIGNATURE_TRANSFER,analyzePlan}
 from "../permit2-debug/analyze.mjs";
const text=file=>readFileSync(new URL(file,import.meta.url),"utf8");
const html=text("../permit2-debug/index.html");
const app=text("../permit2-debug/app.mjs");
const engine=text("../permit2-debug/analyze.mjs");
const main=text("../index.html");
const sitemap=text("../sitemap.xml");
const css=text("../permit2-debug/debug.css");
const docs=text("../README.md");
const llms=text("../llms.txt");
const path="https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/permit2-debug/";
const price="https://clawlancer.ai/marketplace/26905668-717a-41d7-9cc1-5d7ea1c331b1";
test("free Permit2 debugger SEO canonical matches the actual planned GitHub Pages URL",()=>{
 assert.ok(html.includes('rel="canonical" href="'+path+'"'));
 assert.ok(html.includes("<title>SignScope Permit2 Debug Lab"));
});
test("CSP strict same-origin scripts, no external requests or browser forms",()=>{
 const v=html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 assert.ok(v?.includes("default-src 'none'"));
 assert.ok(v.includes("script-src 'self'"));
 assert.ok(v.includes("connect-src 'none'"));
 assert.ok(v.includes("form-action 'none'"));
 assert.ok(!v.includes("unsafe-inline"));
});
test("one client-side JS module, no third-party bundles",()=>{
 const v=[...html.matchAll(/<script\b[^>]+src="([^"]+)"/g)].map(x=>x[1]);
 assert.deepEqual(v,["./app.mjs"]);
 assert.ok(html.includes('href="./debug.css"'));
});
test("no wallet provider, blockchain RPC or signing code",()=>{
 const source=engine+"\n"+app;
 for(const marker of ["window.ethereum","eth_requestAccounts","eth_sendTransaction",
   "eth_signTypedData","personal_sign","new WebSocket","sendBeacon","localStorage","sessionStorage","document.cookie"]){
   assert.ok(!source.includes(marker),marker);
 }
});
test("no fetch / XHR anywhere in the new analysis or web app",()=>{
 const source=engine+"\n"+app;
 assert.ok(!/\bfetch\s*\(/.test(source));
 assert.ok(!/XMLHttpRequest/.test(source));
});
test("two sample buttons are accessible",()=>{
 for(const id of ["sample-broken","sample-signature"]){
  assert.ok(html.includes('id="'+id+'"'),id);
  assert.ok(app.includes(id),id);
 }
});
test("action buttons, result, input and status IDs are wired",()=>{
 for(const id of ["plan","expected-chain","inspect","reset","kind","summary",
  "blurb","warning-count","money-cost","details","findings","status","download"]){
   assert.ok(html.includes('id="'+id+'"'),id);
   assert.ok(app.includes('"'+id+'"'),id);
 }
});
test("no input is automatically transmitted or submitted",()=>{
 assert.ok(!html.includes("<form"));
 assert.ok(!app.includes("navigator.sendBeacon"));
 assert.ok(!app.includes("fetch("));
});
test("result rendering uses textContent, not untrusted innerHTML",()=>{
 assert.ok(app.includes("textContent"));
 assert.ok(!app.includes("innerHTML"));
 assert.ok(!app.includes("insertAdjacentHTML"));
 assert.ok(!app.includes("eval("));
});
test("download remains disabled until local inspection",()=>{
 assert.ok(html.includes('id="download" type="button" class="btn secondary wide" disabled'));
});
test("no browser wallet transaction is claimed through output",()=>{
 assert.ok(engine.includes("walletConnected:false"));
 assert.ok(engine.includes("transfersSent:false"));
 assert.ok(engine.includes("chargedNativeUSDC:\"0\""));
});
test("real outside public user context documented but not misrepresented as a buyer",()=>{
 assert.ok(html.includes("https://github.com/Uniswap/permit2/issues/268"));
 assert.ok(html.includes("No affiliation, endorsement"));
});
test("original official interface links, not dubious third party ABI",()=>{
 assert.ok(html.includes("Uniswap/permit2/blob/main/src/interfaces/IAllowanceTransfer.sol"));
 assert.ok(html.includes("Uniswap/permit2/blob/main/src/interfaces/ISignatureTransfer.sol"));
});
test("separate free tool and genuine optional 15 USDC original seller",()=>{
 assert.ok(html.includes('href="../#analyzer"'));
 assert.ok(html.includes(price));
 assert.ok(html.includes("15 Circle Base USDC"));
 assert.ok(html.toLowerCase().includes("no independent paid customer"));
});
test("no actual financial assets are manipulated",()=>{
 assert.ok(html.includes("No wallet"));
 assert.ok(html.toLowerCase().includes("no payment"));
});
test("sitemap now advertises actual new public URL",()=>{
 assert.ok(sitemap.includes(path));
 assert.ok(sitemap.includes("signscope-offline-permit-checker/sample-report/"));
});
test("parent tool links new separate Permit2 debugger",()=>{
 assert.ok(main.includes('href="./permit2-debug/"'));
 assert.ok(main.includes("Debug a Permit2 call locally"));
});
test("README and machine llms.txt describe limitations and new local route",()=>{
 assert.ok(docs.includes(path));
 assert.ok(docs.includes("not endorsed"));
 assert.ok(llms.includes(path));
 assert.ok(llms.includes("no RPC"));
});
test("mobile layouts are implemented",()=>{
 assert.ok(css.includes("@media(max-width:840px)"));
 assert.ok(css.includes("@media(max-width:500px)"));
});
test("public examples have meaningful deterministic diagnostic differences",()=>{
 const x=analyzePlan(SAMPLE_BROKEN_ALLOWANCE,{nowSeconds:1790000000});
 const y=analyzePlan(SAMPLE_SIGNATURE_TRANSFER,{nowSeconds:1790000000});
 assert.equal(x.observed.shape,"AllowanceTransfer");
 assert.equal(y.observed.shape,"SignatureTransfer");
 assert.ok(x.findings.some(f=>f.code==="WRONG_FUNCTION_NAME"));
 assert.ok(y.findings.some(f=>f.code==="RECIPIENT_NOT_SIGNED"));
});
test("unknown critical risk stays unknown and never claims safe to sign",()=>{
 const x=analyzePlan(SAMPLE_BROKEN_ALLOWANCE);
 assert.ok(x.verdict.includes("NOT_A_SAFE_TO_SIGN_VERDICT"));
 assert.ok(x.limitations.some(z=>z.toLowerCase().includes("not")));
});
test("no unearned revenue or guaranteed settlement claimed",()=>{
 assert.ok(html.includes("Published price does not equal realized earnings"));
 assert.ok(html.includes("no independent paid customer")||html.includes("No independent paid customer"));
});

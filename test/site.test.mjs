import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {BASE_USDC} from "../src/analysis.mjs";

const h=readFileSync(new URL("../index.html",import.meta.url),"utf8");
const app=readFileSync(new URL("../src/app.mjs",import.meta.url),"utf8");
const engine=readFileSync(new URL("../src/analysis.mjs",import.meta.url),"utf8");
const feedback=readFileSync(new URL("../.github/ISSUE_TEMPLATE/feedback.yml",import.meta.url),"utf8");
const llms=readFileSync(new URL("../llms.txt",import.meta.url),"utf8");
const sitemap=readFileSync(new URL("../sitemap.xml",import.meta.url),"utf8");
const css=readFileSync(new URL("../style.css",import.meta.url),"utf8");
const payee="0x6b01efA0705E91a7aca54271510bf9e594717f34";

test("page clearly names the free offline product",()=>{
  assert.ok(h.includes("Read the permission."));
  assert.ok(h.includes("Before you sign."));
  assert.ok(h.includes("NO WALLET CONNECTION"));
  assert.ok(h.toLowerCase().includes("unsigned json"));
});
test("page CSP forbids every external connection",()=>{
  const csp=h.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp);
  assert.ok(csp.includes("connect-src 'none'"));
  assert.ok(csp.includes("script-src 'self'"));
  assert.ok(csp.includes("form-action 'none'"));
  assert.ok(csp.includes("default-src 'none'"));
  assert.ok(!csp.includes("unsafe-inline"));
});
test("only one local script module and stylesheet",()=>{
  const scripts=[...h.matchAll(/<script\b[^>]*src="([^"]+)"/g)].map(m=>m[1]);
  assert.deepEqual(scripts,["./src/app.mjs?v=20261020-sigtransfer"]);
  assert.ok(h.includes('href="./style.css"'));
});
test("UI never invokes provider or wallet signing",()=>{
  assert.ok(!app.includes("window.ethereum"));
  assert.ok(!app.includes("eth_requestAccounts"));
  assert.ok(!app.includes("eth_signTypedData"));
  assert.ok(!app.includes("eth_sendTransaction"));
  assert.ok(!app.includes("wallet_connect"));
});
test("no fetch, XHR, beacons or remote scripts in any JS",()=>{
  for(const s of [app,engine]){
    assert.ok(!/\bfetch\s*\(/.test(s));
    assert.ok(!/\bXMLHttpRequest\b/.test(s));
    assert.ok(!/sendBeacon/.test(s));
    assert.ok(!/import\s*\(\s*["']http/.test(s));
  }
});
test("no localStorage, sessionStorage or cookie recording",()=>{
  assert.ok(!/localStorage|sessionStorage|document\.cookie|indexedDB/.test(app));
});
test("free inspector never marks result as safe to sign",()=>{
  assert.ok(h.includes("never an endorsement to sign"));
  assert.ok(engine.includes("REVIEW_REQUIRED_NOT_SAFE_CERTIFICATION"));
  assert.ok(!engine.includes('"SAFE_TO_SIGN"'));
});
test("signed messages and private keys are rejected rather than analyzed",()=>{
  assert.ok(engine.includes("DO NOT paste signatures"));
  assert.ok(h.includes("Never paste a signature"));
});
test("all sample controls have accessible labels",()=>{
  for(const id of ["sample-permit","sample-permit2","sample-signature-transfer","sample-eip3009","sample-calldata",
    "input-json","expected-chain","expected-spender","expected-contract",
    "inspect","clear","download","status","result-details","finding-list"]){
    assert.ok(h.includes('id="'+id+'"'),id);
  }
});
test("source controls output via textContent rather than unsanitized HTML",()=>{
  assert.ok(app.includes("textContent"));
  assert.ok(!app.includes("innerHTML"));
  assert.ok(!app.includes("insertAdjacentHTML"));
  assert.ok(!app.includes("eval("));
});
test("download starts disabled until local analysis",()=>{
  assert.ok(h.includes('id="download" type="button" class="btn secondary wide" disabled'));
});
test("full public owner recipient is pinned and visible to visitors",()=>{
  assert.ok(h.includes(payee));
  assert.ok(h.includes('id="payee"'));
});
test("EIP681 request strictly uses native Base Circle USDC and fixed 1 USDC",()=>{
  const href=h.match(/id="tip-uri"[^>]*href="([^"]+)"/)?.[1]?.replaceAll("&amp;","&");
  assert.ok(href);
  const u=new URL(href);
  assert.equal(u.protocol,"ethereum:");
  assert.equal(u.pathname,BASE_USDC+"@8453/transfer");
  assert.equal(u.searchParams.get("address"),payee);
  assert.equal(u.searchParams.get("uint256"),"1000000");
});
test("voluntary support clearly not a purchase or investment",()=>{
  assert.ok(h.includes("not an investment or paid audit order"));
  assert.ok(h.includes("payment request only"));
  assert.ok(h.includes("No charge occurs by viewing this page"));
});
test("proposed $15 review requires written scope",()=>{
  assert.ok(h.includes("15 <span>USDC proposed fixed pilot"));
  assert.ok(h.includes("agreed in writing first"));
  assert.ok(h.includes("A marketplace listing is not a commissioned order"));
});
test("feedback asks about real pain and willingness to pay",()=>{
  assert.ok(h.includes('id="pain"'));
  assert.ok(h.includes('id="willingness"'));
  assert.ok(h.includes("$0 — free is enough"));
  assert.ok(h.includes("$50+ integration"));
});
test("feedback submission is not automatic network tracking",()=>{
  assert.ok(app.includes("mailto:onecursor1@gmail.com?subject="));
  assert.ok(h.includes("Nothing is posted automatically"));
});
test("GitHub issue template explicitly rejects private content",()=>{
  assert.ok(feedback.includes("DO NOT upload"));
  assert.ok(feedback.includes("id: budget"));
  assert.ok(feedback.includes("required: true"));
});
test("outside signer risk reference is included without claim of affiliation",()=>{
  assert.ok(h.includes("https://revoke.cash/"));
  assert.ok(h.includes("SignScope does not connect to your wallet"));
});
test("Uniswap Permit2 and EIP712 primary sources are linked",()=>{
  assert.ok(h.includes("https://eips.ethereum.org/EIPS/eip-712"));
  assert.ok(h.includes("developers.uniswap.org/docs/protocols/permit2"));
});
test("canonical website points at original separate SignScope URL",()=>{
  assert.ok(h.includes('rel="canonical" href="https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/"'));
  assert.ok(sitemap.includes("signscope-offline-permit-checker/"));
  assert.ok(llms.includes("signscope-offline-permit-checker/"));
});
test("SEO robots and sitemap text are nonempty",()=>{
  assert.ok(readFileSync(new URL("../robots.txt",import.meta.url),"utf8").includes("Sitemap:"));
  assert.ok(sitemap.includes("https://www.sitemaps.org/schemas/sitemap/0.9")||
            sitemap.includes("http://www.sitemaps.org/schemas/sitemap/0.9"));
});
test("site has useful small-screen layouts",()=>{
  assert.ok(css.includes("@media(max-width:800px)"));
  assert.ok(css.includes("@media(max-width:520px)"));
});
test("user and payer are disclosed as one beneficial owner",()=>{
  assert.ok(h.includes("one beneficial human owner"));
  assert.ok(llms.includes("One original economic owner"));
});
test("site claims no revenue, not a proven paid business",()=>{
  assert.ok(llms.includes("No external paid users proven"));
  assert.ok(h.includes("No fabricated independent customer"));
});
test("HTML avoids automatically executed forms and third-party ad trackers",()=>{
  assert.ok(!h.includes("<form"));
  assert.ok(!h.includes("google-analytics.com"));
  assert.ok(!h.includes("facebook.com/tr"));
  assert.ok(!h.includes("googletagmanager.com"));
});

test("optional paid technical review routes to real verified original marketplace listing rather than asking for self-paid tip",()=>{
  const id="26905668-717a-41d7-9cc1-5d7ea1c331b1";
  const u="https://clawlancer.ai/marketplace/"+id;
  assert.ok(h.includes('href="'+u+'"'));
  assert.ok(h.includes('View 15 USDC fixed offer'));
  assert.ok(h.includes('rel="noopener noreferrer"'));
  assert.ok(h.includes("funded order"));
  assert.ok(h.includes("not an automatic charge") || h.includes("NOT an automatic charge"));
  assert.ok(llms.includes(u));
});
test("manual 15 USDC paid review remains distinct from native Base USDC 1 tip",()=>{
  assert.ok(h.includes("Ask about scope before buying"));
  assert.ok(h.includes('id="tip-uri"'));
  assert.ok(h.includes("No private keys"));
  assert.ok(!h.includes("15 USDC earned"));
});
test("paid listing readme accurately discloses zero buyers",()=>{
  const docs=readFileSync(new URL("../README.md",import.meta.url),"utf8");
  assert.ok(docs.includes("times_purchased=0"));
  assert.ok(docs.includes("NOT a buyer, order"));
});

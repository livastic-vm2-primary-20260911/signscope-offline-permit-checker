import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {AS_OF,AS_OF_SECONDS,bundle,FICTIONAL_UNSIGNED,result}
  from "../sample-report/generate.mjs";
import {BASE_USDC,MAX160,PERMIT2} from "../src/analysis.mjs";
const load=p=>readFileSync(new URL(p,import.meta.url),"utf8");
const raw=load("../sample-report/sample-fictional-output.json");
const actual=JSON.parse(raw);
const html=load("../sample-report/index.html");
const home=load("../index.html");
const css=load("../sample-report/sample.css");
const sitemap=load("../sitemap.xml");
const docs=load("../README.md");
const llms=load("../llms.txt");
const paid="https://clawlancer.ai/marketplace/26905668-717a-41d7-9cc1-5d7ea1c331b1";
const sample="/signscope-offline-permit-checker/sample-report/";
test("generated fictional bundle is bit-for-bit reproducible",()=>{
 assert.deepEqual(actual,bundle());
 assert.equal(raw,JSON.stringify(bundle(),null,2)+"\n");
});
test("sample is NOT a real paid case, customer, contract or sale",()=>{
 assert.equal(actual.exampleOnly,true);
 assert.equal(actual.actualCustomer,false);
 assert.equal(actual.customerTransaction,false);
 assert.equal(actual.commissionedWork,false);
 assert.equal(actual.priceChargedBaseCircleUSDC,"0");
 assert.equal(actual.underlyingSignerOrWalletAuthenticated,false);
});
test("sample is bounded public unsigned synthetic token data",()=>{
 assert.equal(actual.input.primaryType,"PermitSingle");
 assert.equal(actual.input.domain.chainId,8453);
 assert.equal(actual.input.domain.verifyingContract,PERMIT2);
 assert.equal(actual.input.message.details.token,BASE_USDC);
 assert.equal(actual.input.message.details.amount,MAX160.toString());
 assert.equal(actual.input.message.spender,"0x2222222222222222222222222222222222222222");
});
test("never pretend to have recovered signer identity from unsigned JSON",()=>{
 assert.equal(actual.output.observed.owner,null);
 assert.equal(actual.underlyingSignerOrWalletAuthenticated,false);
});
test("parser identifies maxUint160 and prolonged allowance",()=>{
 const names=actual.output.findings.map(x=>x.code);
 assert.deepEqual(names,["MAXIMUM_ALLOWANCE","LONG_LIVED"]);
 assert.equal(actual.output.observed.amounts[0].maximum,true);
 assert.ok(actual.output.observed.amounts[0].display.includes("effectively unlimited"));
});
test("report distinguishes allowance expiry from signature deadline",()=>{
 assert.deepEqual(actual.output.observed.deadlines.map(x=>x.name),
  ["allowance expiration","signature deadline"]);
 assert.ok(actual.output.observed.deadlines[0].daysFromNow>365);
 assert.ok(actual.output.observed.deadlines[1].daysFromNow<365);
});
test("snapshot clock is pinned and deterministic",()=>{
 assert.equal(actual.generatedAtUtc,AS_OF);
 assert.equal(AS_OF_SECONDS,Math.floor(Date.parse(AS_OF)/1000));
 assert.deepEqual(actual.output,result());
});
test("local preview makes NO wallet, paid or remote call",()=>{
 assert.equal(actual.output.walletConnected,false);
 assert.equal(actual.output.uploaded,false);
 assert.equal(actual.output.signed,false);
 assert.equal(actual.output.chargedUSDC,"0");
 assert.equal(actual.chainQueried,false);
 assert.equal(actual.contractBytecodeInspected,false);
});
test("no secret fields or actual signatures in the sample",()=>{
 const content=JSON.stringify(actual.input);
 for (const s of ['"privateKey"','"mnemonic"','"signature"','"seedPhrase"']) {
  assert.ok(!content.includes(s),s);
 }
});
test("fictional sample does NOT claim security endorsement",()=>{
 assert.ok(actual.output.verdict.includes("NOT_SAFE_CERTIFICATION"));
 assert.ok(html.includes("Not safe-to-sign certification"));
 assert.ok(html.includes("not a paid client"));
});
test("static report page forbids all outgoing connections and scripts",()=>{
 const csp=html.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
 assert.ok(csp?.includes("default-src 'none'"));
 assert.ok(csp.includes("connect-src 'none'"));
 assert.ok(csp.includes("script-src 'none'"));
 assert.ok(csp.includes("form-action 'none'"));
 assert.ok(!html.includes("<script"));
});
test("raw JSON and source generator visible to developers",()=>{
 assert.ok(html.includes('href="./sample-fictional-output.json"'));
 assert.ok(html.includes("sample-report/generate.mjs"));
 assert.ok(html.includes("src/analysis.mjs"));
});
test("paid conversion is exact same-owner real 15 USDC listing",()=>{
 assert.ok(html.includes(paid));
 assert.ok(actual.optionalFixedOffer===paid);
 assert.ok(html.includes("15 USDC"));
 assert.ok(html.includes("No independent customer purchase"));
});
test("main site links directly to the free sample before purchase",()=>{
 assert.ok(home.includes('href="./sample-report/"'));
 assert.ok(home.includes("See a FREE fictional sample report"));
});
test("free sample is discoverable, but no fake thanks or revenue",()=>{
 assert.ok(sitemap.includes(sample));
 assert.ok(!sitemap.includes("/feedback/thanks/"));
 assert.ok(docs.includes(sample));
 assert.ok(llms.includes(sample));
});
test("report uses responsive styles for smaller screens",()=>{
 assert.ok(css.includes("@media(max-width:870px)"));
 assert.ok(css.includes("@media(max-width:530px)"));
});

import {test} from "node:test";
import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {
  SAMPLE_SIGNATURE_TRANSFER,BASE_USDC,PERMIT2,inspect
} from "../src/analysis.mjs";
const sample=JSON.parse(SAMPLE_SIGNATURE_TRANSFER);
const data=inspect(SAMPLE_SIGNATURE_TRANSFER,{expectedChainId:"8453",expectedSpender:"0x2222222222222222222222222222222222222222"});
const src=readFileSync(new URL("../src/app.mjs",import.meta.url),"utf8");
const html=readFileSync(new URL("../index.html",import.meta.url),"utf8");
const codes=data.findings.map(x=>x.code);
test("published fifth local sample is a fictional unsigned signature transfer",()=>{
 assert.equal(sample.primaryType,"PermitTransferFrom");
 assert.equal(sample.domain.chainId,8453);
 assert.equal(sample.domain.verifyingContract,PERMIT2);
 assert.equal(sample.message.permitted.token,BASE_USDC);
 assert.equal(sample.message.permitted.amount,"5000000");
});
test("sample encodes signed caller via the exact official EIP712 struct type",()=>{
 const declared=sample.types.PermitTransferFrom;
 assert.deepEqual(declared.map(x=>x.name),["permitted","spender","nonce","deadline"]);
 assert.equal(declared.find(x=>x.name==="spender")?.type,"address");
});
test("built-in sample does NOT assert unknown eventual token recipient",()=>{
 assert.equal(data.observed.spender,"0x2222222222222222222222222222222222222222");
 assert.equal(data.observed.recipient,null);
 assert.ok(codes.includes("RECIPIENT_OUTSIDE_SIGNED_PERMIT"));
});
test("known Base Circle native USDC sample displays only bounded amount",()=>{
 assert.equal(data.observed.amounts[0].atomic,"5000000");
 assert.equal(data.observed.amounts[0].display,"5 native Circle USDC (Base)");
 assert.equal(data.observed.amounts[0].maximum,false);
});
test("actual chain and signer binding warning is not a claim of an audit",()=>{
 assert.equal(data.verdict,"REVIEW_REQUIRED_NOT_SAFE_CERTIFICATION");
 assert.ok(data.limitations.some(x=>x.includes("not authenticated")));
});
test("built-in fifth sample is wired to a visible page control",()=>{
 assert.ok(html.includes('id="sample-signature-transfer"'));
 assert.ok(src.includes('"sample-signature-transfer":SAMPLE_SIGNATURE_TRANSFER'));
 assert.ok(src.includes('"sample-signature-transfer":"Permit2 SignatureTransfer"'));
});
test("browser bundle and analyzer import have matching cache-version pins",()=>{
 assert.ok(html.includes("src/app.mjs?v=20261020-intended-base-usdc-spend"));
 assert.ok(src.includes('from "./analysis.mjs?v=20261020-sigtransfer";'));
 assert.ok(src.includes('from "./intent-compare.mjs";'));
});
test("fifth sample never requests a real wallet or produces a signature",()=>{
 assert.equal(data.walletConnected,false);
 assert.equal(data.signed,false);
 assert.equal(data.uploaded,false);
 assert.equal(data.chargedUSDC,"0");
});

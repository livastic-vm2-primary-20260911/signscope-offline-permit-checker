import {test} from "node:test";
import assert from "node:assert/strict";
import {
 analyzePlan,assertUnambiguousJson,SAMPLE_BROKEN_ALLOWANCE,
 SAMPLE_SIGNATURE_TRANSFER,MAX_PLAN_BYTES
} from "../permit2-debug/analyze.mjs";
import {BASE_USDC,MAX160,MAX256,PERMIT2} from "../src/analysis.mjs";

const adr=x=>"0x"+String(x).repeat(40);
const TIME=Math.floor(Date.parse("2026-10-20T12:35:00Z")/1000);
const inspect=(x,o={})=>analyzePlan(typeof x==="string"?x:JSON.stringify(x),{nowSeconds:TIME,...o});
const warnings=x=>x.findings.map(f=>f.code);
const a=()=>JSON.parse(SAMPLE_BROKEN_ALLOWANCE);
const b=()=>JSON.parse(SAMPLE_SIGNATURE_TRANSFER);
const isWarn=(report,name)=>warnings(report).includes(name);
const correctAllowance=()=>{
 const x=a();
 x.flow="allowanceTransfer";x.functionName="permit";x.permit.spender=adr(9);
 x.erc20ApprovedToPermit2="yes";x.permit.details[0].amount="1000000";
 x.permit.sigDeadline=String(TIME+3600);
 x.permit.details[0].expiration=String(TIME+3600*24);
 return x;
};
const correctSignature=()=>{
 const x=b();
 x.erc20ApprovedToPermit2="yes";
 x.permit.deadline=String(TIME+3600);
 return x;
};

test("synthetic failing Permit2 allowance case reports ABI and wrong spender",()=>{
 const result=inspect(SAMPLE_BROKEN_ALLOWANCE);
 for(const code of [
   "WRONG_FUNCTION_NAME","SIGNED_SPENDER_MISMATCH",
   "TRANSFER_CALLER_MISMATCH","SELF_SPENDER_RISK",
   "UNLIMITED_AMOUNT","LONG_LIVED","ERC20_APPROVAL_UNVERIFIED"
 ])assert.ok(isWarn(result,code),code);
});
test("correct hypothetical allowance typed shape avoids wrong ABI label",()=>{
 const r=inspect(correctAllowance());
 assert.ok(!isWarn(r,"WRONG_FUNCTION_NAME"));
 assert.ok(!isWarn(r,"SIGNED_SPENDER_MISMATCH"));
 assert.ok(!isWarn(r,"TRANSFER_CALLER_MISMATCH"));
 assert.ok(!isWarn(r,"UNLIMITED_AMOUNT"));
 assert.equal(r.observed.shape,"AllowanceTransfer");
 assert.equal(r.observed.permittedAtomic,"1000000");
 assert.equal(r.observed.requestedAtomic,"500000");
});
test("correctly formatted hypothetical plan is still never endorsed as safe",()=>{
 const r=inspect(correctAllowance());
 assert.equal(r.verdict,"REVIEW_REQUIRED_NOT_A_SAFE_TO_SIGN_VERDICT");
 assert.equal(r.paid,false);
 assert.equal(r.walletConnected,false);
 assert.equal(r.transfersSent,false);
 assert.equal(r.signaturesProduced,false);
});
test("EIP712 Permit2 destination is canonical public contract only if user asserts it",()=>{
 const r=inspect(correctAllowance());
 assert.equal(r.observed.calledContract,PERMIT2.toLowerCase());
 assert.equal(r.observed.claimedPermit2,PERMIT2.toLowerCase());
});
test("wrong contract route triggers explicit warning",()=>{
 const x=correctAllowance();x.calledContract=adr(4);
 assert.ok(isWarn(inspect(x),"PERMIT2_DESTINATION_MISMATCH"));
});
test("wrong EIP712 verifying contract triggers separate warning",()=>{
 const x=correctAllowance();x.permit2Address=adr(4);
 assert.ok(isWarn(inspect(x),"PERMIT2_DOMAIN_MISMATCH"));
});
test("wrong declared network is rejected by expected network",()=>{
 const x=correctAllowance();x.chainId=1;
 assert.ok(isWarn(inspect(x),"CHAIN_MISMATCH"));
});
test("EVM Sepolia default explicit expected chain 11155111 is honored",()=>{
 const r=inspect(correctAllowance());
 assert.equal(r.observed.chainId,11155111);
 assert.ok(!isWarn(r,"CHAIN_MISMATCH"));
});
test("optional independent expected chain selection overrides embedded claim",()=>{
 const x=correctAllowance();
 assert.ok(isWarn(inspect(x,{expectedChainId:"8453"}),"CHAIN_MISMATCH"));
});
test("unknown flow fails closed rather than assuming approval",()=>{
 const x=correctAllowance();x.flow="automaticTransfer";
 assert.throws(()=>inspect(x),/Select one known flow/);
});
test("missing chain is not treated as safe",()=>{
 const x=correctAllowance();delete x.chainId;
 assert.ok(isWarn(inspect(x),"CHAIN_UNREADABLE"));
});
test("unsupported decimal float or negative amounts fail",()=>{
 for(const y of ["-1","1.5","1e9","NaN","Infinity",null]) {
  const x=correctAllowance();x.transferFrom.amount=y;
  assert.ok(isWarn(inspect(x),"AMOUNT_INVALID"),String(y));
 }
});
test("unbounded uint160 permitted amount detected",()=>{
 const x=correctAllowance();x.permit.details[0].amount=MAX160.toString();
 assert.ok(isWarn(inspect(x),"UNLIMITED_AMOUNT"));
});
test("more than uint160 rejected",()=>{
 const x=correctAllowance();x.permit.details[0].amount=MAX256.toString();
 assert.ok(isWarn(inspect(x),"AMOUNT_INVALID"));
});
test("requested allowance transfer exceeding the signed amount rejected",()=>{
 const x=correctAllowance();x.transferFrom.amount="1000001";
 assert.ok(isWarn(inspect(x),"TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE"));
});
test("wrong token route has explicit no signed permission matching",()=>{
 const x=correctAllowance();x.transferFrom.token=adr(7);
 assert.ok(isWarn(inspect(x),"TOKEN_NOT_PERMITTED"));
});
test("invalid signature submission deadline noted",()=>{
 const x=correctAllowance();x.permit.sigDeadline="-99";
 assert.ok(isWarn(inspect(x),"INVALID_TIME"));
});
test("expired allowance noted independently of signature expiration",()=>{
 const x=correctAllowance();x.permit.details[0].expiration=String(TIME-50);
 assert.ok(isWarn(inspect(x),"EXPIRED"));
});
test("permission lifetime over 1 year noted",()=>{
 const x=correctAllowance();x.permit.details[0].expiration=String(TIME+86400*400);
 assert.ok(isWarn(inspect(x),"LONG_LIVED"));
});
test("underlying approval is never verified from status claimed yes",()=>{
 const x=correctAllowance();x.erc20ApprovedToPermit2="yes";
 assert.ok(isWarn(inspect(x),"ERC20_APPROVAL_SELF_REPORTED"));
});
test("underlying approval reported missing has more severe warning",()=>{
 const x=correctAllowance();x.erc20ApprovedToPermit2="no";
 assert.ok(isWarn(inspect(x),"ERC20_APPROVAL_REPORTED_MISSING"));
});
test("underlying token approval unknown cannot be assumed",()=>{
 const x=correctAllowance();x.erc20ApprovedToPermit2="unknown";
 assert.ok(isWarn(inspect(x),"ERC20_APPROVAL_UNVERIFIED"));
});
test("missing caller cannot be independently inferred",()=>{
 const x=correctAllowance();delete x.caller;
 assert.ok(isWarn(inspect(x),"CALLER_UNKNOWN"));
});
test("AllowanceTransfer permit relayer caller may differ from spender",()=>{
 const x=correctAllowance();x.caller=adr(8);
 const r=inspect(x);
 assert.ok(!isWarn(r,"TRANSFER_CALLER_MISMATCH"));
 assert.ok(!isWarn(r,"SIGNED_SPENDER_MISMATCH"));
});
test("AllowanceTransfer subsequent transferFrom caller MUST equal spender",()=>{
 const x=correctAllowance();x.transferCaller=adr(8);
 assert.ok(isWarn(inspect(x),"TRANSFER_CALLER_MISMATCH"));
});
test("token owner/from inconsistency noted",()=>{
 const x=correctAllowance();x.transferFrom.from=adr(8);
 assert.ok(isWarn(inspect(x),"TRANSFER_OWNER_MISMATCH"));
});
test("malformed recipient and token noted",()=>{
 const x=correctAllowance();x.transferFrom.to="not-an-address";x.transferFrom.token="0xdead";
 const r=inspect(x);
 assert.ok(isWarn(r,"RECIPIENT_UNKNOWN"));
 assert.ok(isWarn(r,"TRANSFER_TOKEN_UNKNOWN"));
});
test("no permit details cannot be mistaken for issued allowance",()=>{
 const x=correctAllowance();delete x.permit.details;
 const r=inspect(x);
 assert.ok(isWarn(r,"PERMIT_DETAILS_INVALID"));
 assert.ok(isWarn(r,"TOKEN_NOT_PERMITTED"));
});
test("Permit2 20+ batch item limit enforced",()=>{
 const x=correctAllowance();x.permit.details=Array.from({length:21},()=>x.permit.details[0]);
 assert.throws(()=>inspect(x),/Too many Permit2/);
});
test("uint48 nonce overflows are reported",()=>{
 const x=correctAllowance();x.permit.details[0].nonce=(1n<<48n).toString();
 assert.ok(isWarn(inspect(x),"NONCE_INVALID"));
});
test("signatureTransfer example exposes recipient from caller details",()=>{
 const r=inspect(SAMPLE_SIGNATURE_TRANSFER);
 assert.equal(r.observed.shape,"SignatureTransfer");
 assert.equal(r.observed.recipient,adr(3));
 assert.equal(r.observed.permittedAtomic,"1000000");
 assert.equal(r.observed.requestedAtomic,"500000");
 assert.ok(isWarn(r,"RECIPIENT_NOT_SIGNED"));
});
test("SignatureTransfer uses caller as spender, NOT extra signed field",()=>{
 const r=inspect(correctSignature());
 assert.equal(r.observed.spender,adr(9));
 assert.ok(!isWarn(r,"EXTRA_SIGNED_SPENDER_FIELD"));
 assert.ok(!isWarn(r,"ACTUAL_CALLER_MISMATCH"));
});
test("SignatureTransfer conflicting intended spender noted",()=>{
 const x=correctSignature();x.intendedSpender=adr(8);
 assert.ok(isWarn(inspect(x),"ACTUAL_CALLER_MISMATCH"));
});
test("SignatureTransfer invented standalone signed spender noted",()=>{
 const x=correctSignature();x.permit.spender=adr(9);
 assert.ok(isWarn(inspect(x),"EXTRA_SIGNED_SPENDER_FIELD"));
});
test("SignatureTransfer wrong function name noted",()=>{
 const x=correctSignature();x.functionName="permitBatch";
 assert.ok(isWarn(inspect(x),"WRONG_FUNCTION_NAME"));
});
test("SignatureTransfer request over signed permit amount noted",()=>{
 const x=correctSignature();x.transferDetails.requestedAmount="1000001";
 assert.ok(isWarn(inspect(x),"REQUEST_EXCEEDS_PERMIT"));
});
test("SignatureTransfer signature deadline expired noted",()=>{
 const x=correctSignature();x.permit.deadline=String(TIME-1);
 assert.ok(isWarn(inspect(x),"EXPIRED"));
});
test("SignatureTransfer nonce malformed noted",()=>{
 const x=correctSignature();x.permit.nonce="-1";
 assert.ok(isWarn(inspect(x),"NONCE_INVALID"));
});
test("SignatureTransfer malformed transfer recipient noted",()=>{
 const x=correctSignature();x.transferDetails.to="bad";
 assert.ok(isWarn(inspect(x),"RECIPIENT_UNKNOWN"));
});
test("SignatureTransfer batch mismatched lengths noted",()=>{
 const x=correctSignature();x.permit.permitted=[x.permit.permitted,x.permit.permitted];
 assert.ok(isWarn(inspect(x),"BATCH_LENGTH_MISMATCH"));
});
test("SignatureTransfer true batch of matched details analyzed",()=>{
 const x=correctSignature();
 x.permit.permitted=[
  {token:BASE_USDC,amount:"1000000"},
  {token:adr(8),amount:"1000"}
 ];
 x.transferDetails=[
  {to:adr(3),requestedAmount:"500000"},
  {to:adr(7),requestedAmount:"1500"}
 ];
 const r=inspect(x);
 assert.ok(isWarn(r,"REQUEST_EXCEEDS_PERMIT"));
 assert.ok(!isWarn(r,"BATCH_LENGTH_MISMATCH"));
});
test("SignatureTransfer original sample ERC-20 approval remains unverified",()=>{
 const r=inspect(SAMPLE_SIGNATURE_TRANSFER);
 assert.ok(isWarn(r,"ERC20_APPROVAL_UNVERIFIED"));
});
test("Signer and signature are never authenticated",()=>{
 const r=inspect(correctSignature());
 assert.ok(r.limitations.some(x=>x.includes("signature")));
 assert.equal(r.signaturesProduced,false);
});
test("maxUINT256 SignatureTransfer permitted amount reported",()=>{
 const x=correctSignature();x.permit.permitted.amount=MAX256.toString();
 assert.ok(isWarn(inspect(x),"UNLIMITED_AMOUNT"));
});
test("raw token decimals not guaranteed on Sepolia",()=>{
 const r=inspect(correctSignature());
 assert.ok(r.observed.amountInterpretation.includes("unverified"));
});
test("no outbound data or payment fields exist in output",()=>{
 const r=inspect(correctSignature());
 assert.equal(r.shippedInput,false);
 assert.equal(r.walletConnected,false);
 assert.equal(r.transfersSent,false);
 assert.equal(r.chargedNativeUSDC,"0");
});
test("JSON duplicate top-level chain fields rejected without overwriting",()=>{
 const raw=SAMPLE_SIGNATURE_TRANSFER.replace('"chainId": 11155111,',
  '"chainId": 11155111, "chainId": 8453,');
 assert.throws(()=>inspect(raw),/Duplicate JSON property/);
});
test("JSON duplicate nested requestedAmount rejected",()=>{
 const raw=SAMPLE_SIGNATURE_TRANSFER.replace('"requestedAmount": "500000"',
  '"requestedAmount": "500000", "requestedAmount": "5000000"');
 assert.throws(()=>inspect(raw),/Duplicate JSON property/);
});
test("JSON duplicate escaped property name also rejected",()=>{
 const raw='{"flow":"signatureTransfer","\\u0066low":"allowanceTransfer"}';
 assert.throws(()=>assertUnambiguousJson(raw),/Duplicate JSON property/);
});
test("simple correctly formed JSON not misclassified as duplicate",()=>{
 assert.equal(assertUnambiguousJson('{"a":1,"nested":{"b":2},"c":[3,false,null]}'),true);
});
test("malformed JSON cannot sneak through string scanner",()=>{
 for(const raw of ['{"a":NaN}', '{"a":1,}', '{"x":"a\\q"}',
  '{"x":true false}', '{"x":.2}', '{"x":"unterminated}']){
  assert.throws(()=>assertUnambiguousJson(raw));
 }
});
test("strict no-wallet parser bounded by same 40KB as parent tool",()=>{
 assert.equal(MAX_PLAN_BYTES,40000);
 assert.throws(()=>assertUnambiguousJson('{"a":"'+'X'.repeat(41000)+'"}'),/40 KB/);
});
test("unknown arbitrary JSON object lacks explicit flow and fails closed",()=>{
 assert.throws(()=>inspect({hello:"world"}),/Select one known flow/);
});
test("all observed addresses and risk statements derived from user assertion",()=>{
 const r=inspect(correctSignature());
 assert.equal(r.analysisKind,"FICTIONAL_OR_USER_ASSERTED_INPUT_ONLY");
 assert.ok(r.observed.notes[0].includes("assertions"));
 assert.ok(r.verdict.includes("NOT_A_SAFE"));
});

test("Permit2 allowance expiration over uint48 warned independently of timestamp",()=>{
 const x=correctAllowance();x.permit.details[0].expiration=(1n<<48n).toString();
 assert.ok(isWarn(inspect(x),"ALLOWANCE_EXPIRY_INVALID_UINT48"));
});
test("self-Spender detection is EVM case-insensitive",()=>{
 const x=correctAllowance();x.permit.spender=PERMIT2.toLowerCase();
 assert.ok(isWarn(inspect(x),"SELF_SPENDER_RISK"));
});
test("Base USDC address in Sepolia example is NOT authenticated as Sepolia USDC",()=>{
 const r=inspect(correctSignature());
 assert.ok(isWarn(r,"TOKEN_CHAIN_UNVERIFIED"));
});

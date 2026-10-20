import {test} from "node:test";
import assert from "node:assert/strict";
import {
 MAX_BYTES,MAX256,MAX160,BASE_USDC,PERMIT2,
 addr,uint,parse,inspect,inspectTyped,inspectCall,
 SAMPLE_PERMIT,SAMPLE_APPROVE
} from "../src/analysis.mjs";

const a="0x1111111111111111111111111111111111111111";
const b="0x2222222222222222222222222222222222222222";
const c="0x3333333333333333333333333333333333333333";
const json=x=>JSON.stringify(x);
const permit=()=>JSON.parse(SAMPLE_PERMIT);
const approve=()=>JSON.parse(SAMPLE_APPROVE);
const sig={
 types:{PermitSingle:[
  {name:"details",type:"PermitDetails"},{name:"spender",type:"address"},{name:"sigDeadline",type:"uint256"}]},
 primaryType:"PermitSingle",
 domain:{name:"Permit2",chainId:8453,verifyingContract:PERMIT2},
 message:{details:{token:BASE_USDC,amount:"1000000",expiration:"1893456000",nonce:"1"},
  spender:b,sigDeadline:"1893456000"}
};
const batch=()=>({
 types:{PermitBatch:[{name:"details",type:"PermitDetails[]"},{name:"spender",type:"address"},{name:"sigDeadline",type:"uint256"}]},
 primaryType:"PermitBatch",domain:sig.domain,
 message:{spender:b,sigDeadline:"1893456000",details:[
  {token:BASE_USDC,amount:"2",expiration:"1893456000",nonce:"1"},
  {token:c,amount:MAX160.toString(),expiration:"1893456000",nonce:"2"}
 ]}
});
const trace=result=>result.findings.map(x=>x.code);
const report=data=>inspect(json(data),{expectedChainId:"8453",nowSeconds:1790000000});

test("samples are complete and strictly unsigned",()=>{
 assert.equal(typeof SAMPLE_PERMIT,"string");assert.equal(typeof SAMPLE_APPROVE,"string");
 assert.ok(SAMPLE_PERMIT.length>400);assert.ok(!SAMPLE_PERMIT.includes("signature"));
});
test("address parser accepts case-insensitive 40 hex",()=>{
 assert.equal(addr(BASE_USDC),BASE_USDC.toLowerCase());
 assert.equal(addr("0x123"),null);assert.equal(addr(3),null);
});
test("uint supports 0, integer strings, hex and Max256",()=>{
 assert.equal(uint(0),0n);assert.equal(uint("1000000"),1000000n);
 assert.equal(uint("0xff"),255n);assert.equal(uint(MAX256.toString()),MAX256);
});
test("uint rejects float, unsafe JS integer, negative and exponential",()=>{
 for(const x of [-1,1.1,Number.MAX_SAFE_INTEGER+2,"-1","1e12","+1","12.5","",null]){
  assert.equal(uint(x),null);
 }
});
test("uint enforces 160 vs 256-bit size",()=>{
 assert.equal(uint(MAX160.toString(),160),MAX160);
 assert.equal(uint(MAX256.toString(),160),null);
});
test("untrusted oversized input rejected",()=>{
 assert.equal(MAX_BYTES,40000);
 assert.throws(()=>parse("x".repeat(41000)),/10–40,000/);
});
test("invalid JSON and arrays as root rejected",()=>{
 assert.throws(()=>parse("{x:3, data: 123}"),/Invalid JSON/);
 assert.throws(()=>parse(json([1,2,3,4,5])),/root must be an object/);
});
test("signed EIP712 payload and private secrets forbidden",()=>{
 const d=permit();d.signature="0x"+"a".repeat(130);
 assert.throws(()=>parse(json(d)),/DO NOT paste signatures/);
 d.signature=undefined;d.privateKey="sensitive";
 assert.throws(()=>parse(json(d)),/DO NOT paste signatures/);
});
test("deep objects rejected",()=>{
 const d={};let cur=d;
 for(let i=0;i<12;i++){cur.k={};cur=cur.k;}
 assert.throws(()=>parse(json(d)),/nested JSON/);
});
test("EIP712 permit has owner, spender, known Base USDC amount",()=>{
 const r=report(permit());
 assert.equal(r.inputKind,"EIP712_UNSIGNED");
 assert.equal(r.observed.primaryType,"Permit");
 assert.equal(r.observed.chainId,8453);
 assert.equal(r.observed.owner,a);
 assert.equal(r.observed.spender,b);
 assert.equal(r.observed.amounts[0].display,"1 native Circle USDC (Base)");
});
test("EIP712 report never signs, uploads or charges",()=>{
 const r=report(permit());
 assert.equal(r.unsignedSourceOnly,true);
 assert.equal(r.uploaded,false);assert.equal(r.walletConnected,false);
 assert.equal(r.signed,false);assert.equal(r.chargedUSDC,"0");
});
test("EIP712 no chainId results in explicit warning",()=>{
 const d=permit();delete d.domain.chainId;
 const r=report(d);
 assert.ok(trace(r).includes("CHAIN_MISSING"));
});
test("EIP712 expected Base and actual Ethereum chain mismatch",()=>{
 const d=permit();d.domain.chainId=1;
 const r=report(d);
 assert.ok(trace(r).includes("CHAIN_MISMATCH"));
 assert.equal(r.observed.amounts[0].display,"Raw token units; decimals NOT verified");
});
test("EIP712 missing verifyingContract warned",()=>{
 const d=permit();delete d.domain.verifyingContract;
 assert.ok(trace(report(d)).includes("DOMAIN_CONTRACT_MISSING"));
});
test("EIP712 expected independent spender mismatch warned",()=>{
 const r=inspect(SAMPLE_PERMIT,{expectedSpender:c,nowSeconds:1790000000});
 assert.ok(trace(r).includes("EXPECTED_SPENDER_MISMATCH"));
});
test("EIP712 expected independent contract mismatch warned",()=>{
 const r=inspect(SAMPLE_PERMIT,{expectedContract:c,nowSeconds:1790000000});
 assert.ok(trace(r).includes("CONTRACT_MISMATCH"));
});
test("EIP712 unlimited Permit amount flagged",()=>{
 const d=permit();d.message.value=MAX256.toString();
 assert.ok(trace(report(d)).includes("MAXIMUM_ALLOWANCE"));
 assert.equal(report(d).observed.amounts[0].maximum,true);
});
test("EIP712 max integer cannot overflow JS by accidental numeric coercion",()=>{
 const d=permit();d.message.value=MAX256.toString();
 assert.equal(report(d).observed.amounts[0].atomic,MAX256.toString());
});
test("EIP712 invalid or negative amount flagged",()=>{
 const d=permit();d.message.value="-10";
 assert.ok(trace(report(d)).includes("AMOUNT_UNREADABLE"));
});
test("zero amount labelled but not called automatically safe",()=>{
 const d=permit();d.message.value="0";
 const r=report(d);
 assert.ok(trace(r).includes("ZERO_AMOUNT"));
 assert.equal(r.verdict,"REVIEW_REQUIRED_NOT_SAFE_CERTIFICATION");
});
test("expired deadline flagged",()=>{
 const d=permit();d.message.deadline="1780000000";
 assert.ok(trace(report(d)).includes("EXPIRED"));
});
test("10-year permission flagged",()=>{
 const d=permit();d.message.deadline="2147483647";
 assert.ok(trace(report(d)).includes("LONG_LIVED"));
});
test("invalid deadline warned",()=>{
 const d=permit();d.message.deadline="not a deadline";
 assert.ok(trace(report(d)).includes("EXPIRY_UNKNOWN"));
});
test("Permit with wrong declared field names is unknown",()=>{
 const d=permit();d.types.Permit=d.types.Permit.filter(x=>x.name!=="spender");
 assert.ok(trace(report(d)).includes("UNRECOGNIZED_TYPE"));
});
test("unknown EIP712 primary type is not reported as safe",()=>{
 const d=permit();d.primaryType="ApproveEverything";
 const r=report(d);
 assert.ok(trace(r).includes("UNRECOGNIZED_TYPE"));
 assert.equal(r.observed.recognized,false);
});
test("EIP3009 transfer authorization decodes recipient distinct from spender",()=>{
 const d={
  types:{TransferWithAuthorization:["from","to","value","validAfter","validBefore","nonce"].map(name=>({name,type:"uint256"}))},
  primaryType:"TransferWithAuthorization",
  domain:{chainId:8453,verifyingContract:BASE_USDC},
  message:{from:a,to:c,value:"1000000",validAfter:"0",validBefore:"1900000000",nonce:"0x"+"a".repeat(64)}
 };
 const r=report(d);
 assert.equal(r.observed.recipient,c);assert.equal(r.observed.spender,null);
 assert.equal(r.observed.amounts[0].display,"1 native Circle USDC (Base)");
});
test("EIP3009 expiry before validAfter flags invalid window",()=>{
 const d={
  types:{TransferWithAuthorization:["from","to","value","validAfter","validBefore","nonce"].map(name=>({name,type:"string"}))},
  primaryType:"TransferWithAuthorization",
  domain:{chainId:8453,verifyingContract:BASE_USDC},
  message:{from:a,to:c,value:"1",validAfter:"1900000000",validBefore:"1800000000",nonce:"1"}
 };
 assert.ok(trace(report(d)).includes("BAD_WINDOW"));
});
test("EIP3009 recipient missing flagged",()=>{
 const d={
  types:{TransferWithAuthorization:["from","to","value","validAfter","validBefore","nonce"].map(name=>({name,type:"string"}))},
  primaryType:"TransferWithAuthorization",
  domain:{chainId:8453,verifyingContract:BASE_USDC},
  message:{from:a,to:"invalid",value:"1",validAfter:"0",validBefore:"1900000000",nonce:"1"}
 };
 assert.ok(trace(report(d)).includes("RECIPIENT_UNKNOWN"));
});
test("Permit2 single scope accepts bounded known USDC allowance",()=>{
 const r=report(sig);
 assert.equal(r.observed.recognized,true);
 assert.equal(r.observed.primaryType,"PermitSingle");
 assert.equal(r.observed.spender,b);
 assert.equal(r.observed.amounts[0].display,"1 native Circle USDC (Base)");
});
test("Permit2 single checks canonical domain",()=>{
 const d=structuredClone(sig);d.domain.verifyingContract=c;
 assert.ok(trace(report(d)).includes("PERMIT2_DOMAIN_MISMATCH"));
});
test("Permit2 160-bit maximum is unlimited",()=>{
 const d=structuredClone(sig);d.message.details.amount=MAX160.toString();
 assert.ok(trace(report(d)).includes("MAXIMUM_ALLOWANCE"));
});
test("Permit2 amount above 160-bit rejected",()=>{
 const d=structuredClone(sig);d.message.details.amount=MAX256.toString();
 assert.ok(trace(report(d)).includes("AMOUNT_UNREADABLE"));
});
test("Permit2 batch discovers second token unlimited",()=>{
 const r=report(batch());
 assert.equal(r.observed.amounts.length,2);
 assert.equal(r.observed.amounts[1].maximum,true);
 assert.ok(trace(r).includes("MAXIMUM_ALLOWANCE"));
});
test("Permit2 malformed batch not implicitly safe",()=>{
 const d=batch();d.message.details.push(null);
 assert.ok(trace(report(d)).includes("INVALID_BATCH_ENTRY"));
});
test("Permit2 SignatureTransfer warns that actual recipient outside signed data",()=>{
 const d={
  types:{PermitTransferFrom:[{name:"permitted",type:"TokenPermissions"},{name:"nonce",type:"uint256"},{name:"deadline",type:"uint256"}]},
  primaryType:"PermitTransferFrom",domain:{chainId:8453,verifyingContract:PERMIT2},
  message:{permitted:{token:BASE_USDC,amount:"5000000"},nonce:"123",deadline:"1893456000"}
 };
 const r=report(d);
 assert.equal(r.observed.recognized,true);
 assert.ok(trace(r).includes("SPENDER_NOT_DECLARED_IN_TYPES"));
 assert.ok(trace(r).includes("RECIPIENT_OUTSIDE_SIGNED_PERMIT"));
 assert.equal(r.observed.amounts[0].display,"5 native Circle USDC (Base)");
});
test("Permit2 SignatureTransfer expected spender cannot be proven",()=>{
 const d={
  types:{PermitTransferFrom:[{name:"permitted",type:"TokenPermissions"}]},
  primaryType:"PermitTransferFrom",domain:{chainId:8453,verifyingContract:PERMIT2},
  message:{permitted:{token:BASE_USDC,amount:"100000"},deadline:"1893456000"}
 };
 assert.ok(trace(inspect(json(d),{expectedSpender:b,nowSeconds:1790000000})).includes("EXPECTED_SPENDER_MISMATCH"));
});
test("unknown JSON fails closed without guessed action",()=>{
 assert.throws(()=>inspect(json({unrelated:1234})),/Expected UNSIGNED/);
});
const wordAddr=x=>"0".repeat(24)+x.slice(2);
const wordVal=x=>BigInt(x).toString(16).padStart(64,"0");
const tx=(selector,words)=>({chainId:8453,from:a,to:BASE_USDC,data:selector+words.join("")});
test("approve() selector decodes spender and raw Base USDC amount",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(1000000)]);
 const r=report(d);
 assert.equal(r.inputKind,"UNSIGNED_CALLDATA");
 assert.equal(r.observed.action,"ERC20_APPROVE");
 assert.equal(r.observed.spender,b);
 assert.equal(r.observed.amountDisplay,"1 native Circle USDC (Base)");
});
test("maxUint ERC20 approval explicitly flagged",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(MAX256)]);
 assert.ok(trace(report(d)).includes("UNLIMITED_AMOUNT"));
});
test("NFT setApprovalForAll(true) explicit all-operator warning",()=>{
 const d=tx("0xa22cb465",[wordAddr(b),wordVal(1)]);
 assert.ok(trace(report(d)).includes("ALL_NFT_OPERATOR"));
});
test("NFT setApprovalForAll(false) does not claim broad authorization",()=>{
 const d=tx("0xa22cb465",[wordAddr(b),wordVal(0)]);
 assert.ok(!trace(report(d)).includes("ALL_NFT_OPERATOR"));
});
test("ERC20 transfer is not approval",()=>{
 const r=report(tx("0xa9059cbb",[wordAddr(c),wordVal(2000000)]));
 assert.equal(r.observed.action,"ERC20_TRANSFER");
 assert.equal(r.observed.recipient,c);
 assert.equal(r.observed.spender,null);
});
test("transferFrom contains caller-unknown warning",()=>{
 const r=report(tx("0x23b872dd",[wordAddr(a),wordAddr(c),wordVal(2000000)]));
 assert.equal(r.observed.action,"ERC20_TRANSFER_FROM");
 assert.ok(trace(r).includes("CALLER_UNKNOWN"));
});
test("unknown function selector fails closed",()=>{
 const r=report(tx("0x12345678",[]));
 assert.equal(r.observed.action,"UNKNOWN_SELECTOR");
 assert.ok(trace(r).includes("UNKNOWN_SELECTOR"));
});
test("malformed or short calldata fails instead of guessing",()=>{
 assert.throws(()=>report(tx("0x095ea7b3",[wordAddr(b)])),/Wrong ABI calldata length/);
});
test("expected contract mismatch in transaction envelope flagged",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(10)]);
 assert.ok(trace(inspect(json(d),{expectedContract:c})).includes("CONTRACT_MISMATCH"));
});
test("expected spender mismatch in tx flagged",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(10)]);
 assert.ok(trace(inspect(json(d),{expectedSpender:c})).includes("SPENDER_MISMATCH"));
});
test("missing transaction chainId flagged",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(10)]);delete d.chainId;
 assert.ok(trace(report(d)).includes("CHAIN_MISSING"));
});
test("transaction wrong chain flagged",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(10)]);d.chainId=1;
 assert.ok(trace(report(d)).includes("CHAIN_MISMATCH"));
});
test("cannot infer other token decimals from unknown contract",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(1000000)]);d.to=c;
 assert.equal(report(d).observed.amountDisplay,"Raw token units; decimals NOT verified");
});
test("no AI prompt or wallet command hidden inside analyzer",()=>{
 const r=report(permit());
 assert.ok(r.limitations.some(t=>t.includes("not authenticated")));
 assert.ok(!Object.hasOwn(r,"signedMessage"));
 assert.equal(r.chargedUSDC,"0");
});

test("EIP712Domain field missing from declared types warns instead of assuming domain signature binding",()=>{
 const d=permit();delete d.types.EIP712Domain;
 assert.ok(trace(report(d)).includes("DOMAIN_TYPE_MISSING"));
});
test("EIP712Domain chainId without correctly typed field warns",()=>{
 const d=permit();d.types.EIP712Domain=d.types.EIP712Domain.filter(f=>f.name!=="chainId");
 assert.ok(trace(report(d)).includes("DOMAIN_FIELD_NOT_DECLARED"));
});
test("EIP712Domain verifyingContract wrong declared type warns",()=>{
 const d=permit();
 d.types.EIP712Domain.find(f=>f.name==="verifyingContract").type="string";
 assert.ok(trace(report(d)).includes("DOMAIN_FIELD_NOT_DECLARED"));
});
test("EIP2612 purported Permit with false spender Solidity type warns",()=>{
 const d=permit();d.types.Permit.find(f=>f.name==="spender").type="string";
 assert.ok(trace(report(d)).includes("TYPE_DECLARATION_MISMATCH"));
});
test("Permit2 missing nested detail struct definitions warns",()=>{
 assert.ok(trace(report(sig)).includes("PERMIT2_DETAILS_TYPE_UNKNOWN"));
});
test("Base USDC maxUInt256 presents unlimited label, not astronomical marketing amount",()=>{
 const d=permit();d.message.value=MAX256.toString();
 assert.ok(report(d).observed.amounts[0].display.includes("effectively unlimited"));
});
test("NFT/ERC20 maxUInt256 calldata reports unlimited rather than huge human token count",()=>{
 const d=tx("0x095ea7b3",[wordAddr(b),wordVal(MAX256)]);
 assert.ok(report(d).observed.amountDisplay.includes("effectively unlimited"));
});
test("explicit unsure chain selection disables expected Base mismatch but keeps domain observation",()=>{
 const d=permit();d.domain.chainId=1;
 const r=inspect(json(d),{expectedChainId:null,nowSeconds:1790000000});
 assert.equal(r.observed.chainId,1);
 assert.ok(!trace(r).includes("CHAIN_MISMATCH"));
});

test("zero EIP2612 owner explicitly warned",()=>{
 const d=permit();d.message.owner="0x"+"0".repeat(40);
 assert.ok(trace(report(d)).includes("ZERO_OWNER_ADDRESS"));
});
test("zero spender explicitly warned",()=>{
 const d=permit();d.message.spender="0x"+"0".repeat(40);
 assert.ok(trace(report(d)).includes("ZERO_SPENDER_ADDRESS"));
});

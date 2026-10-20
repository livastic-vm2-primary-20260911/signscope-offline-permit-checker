import {test} from "node:test";
import assert from "node:assert/strict";
import {inspect,MAX256,BASE_USDC,PERMIT2} from "../src/analysis.mjs";

const SPENDER="0x2222222222222222222222222222222222222222";
const OTHER="0x3333333333333333333333333333333333333333";
const JSONify=x=>JSON.stringify(x);
function typed(spender=SPENDER) {
 return {
  types:{
   EIP712Domain:[
    {name:"name",type:"string"},
    {name:"chainId",type:"uint256"},
    {name:"verifyingContract",type:"address"}
   ],
   TokenPermissions:[{name:"token",type:"address"},{name:"amount",type:"uint256"}],
   PermitTransferFrom:[
    {name:"permitted",type:"TokenPermissions"},
    {name:"spender",type:"address"},
    {name:"nonce",type:"uint256"},
    {name:"deadline",type:"uint256"}
   ]
  },
  primaryType:"PermitTransferFrom",
  domain:{name:"Permit2",chainId:8453,verifyingContract:PERMIT2},
  message:{
   permitted:{token:BASE_USDC,amount:"2500000"},
   spender,nonce:"713",deadline:"1893456000"
  }
 };
}
const codes=r=>r.findings.map(x=>x.code);

test("official PermitTransferFrom EIP712 contains spender field",()=>{
 const d=typed(),fields=d.types.PermitTransferFrom.map(x=>x.name);
 assert.deepEqual(fields,["permitted","spender","nonce","deadline"]);
});
test("genuine signed spender is exposed and matches independently expected caller",()=>{
 const r=inspect(JSONify(typed()),{expectedSpender:SPENDER,expectedChainId:"8453"});
 assert.equal(r.observed.primaryType,"PermitTransferFrom");
 assert.equal(r.observed.recognized,true);
 assert.equal(r.observed.spender,SPENDER);
 assert.ok(!codes(r).includes("EXPECTED_SPENDER_MISMATCH"));
 assert.ok(!codes(r).includes("SPENDER_MISSING_IN_SUPPLIED_TYPED_DATA"));
});
test("independently expected caller different from signed spender is warned",()=>{
 const r=inspect(JSONify(typed()),{expectedSpender:OTHER});
 assert.equal(r.observed.spender,SPENDER);
 assert.ok(codes(r).includes("EXPECTED_SPENDER_MISMATCH"));
});
test("signed spender and final transfer recipient remain different concepts",()=>{
 const r=inspect(JSONify(typed()));
 assert.equal(r.observed.spender,SPENDER);
 assert.equal(r.observed.recipient,null);
 assert.ok(codes(r).includes("RECIPIENT_OUTSIDE_SIGNED_PERMIT"));
});
test("missing spender in supplied EIP712 message never falsely asserts binding",()=>{
 const d=typed();delete d.message.spender;
 const r=inspect(JSONify(d));
 assert.equal(r.observed.spender,null);
 assert.ok(codes(r).includes("SPENDER_MISSING_IN_SUPPLIED_TYPED_DATA"));
});
test("undeclared spender in supplied EIP712 type cannot be assumed signed",()=>{
 const d=typed();d.types.PermitTransferFrom=d.types.PermitTransferFrom.filter(x=>x.name!=="spender");
 const r=inspect(JSONify(d));
 assert.ok(codes(r).includes("TYPE_DECLARATION_MISMATCH"));
 assert.ok(codes(r).includes("SPENDER_NOT_DECLARED_IN_TYPES"));
 assert.equal(r.observed.spender,null);
});
test("batch SignatureTransfer also binds caller even when recipient not in typed payload",()=>{
 const d=typed();
 d.types.PermitBatchTransferFrom=[
  {name:"permitted",type:"TokenPermissions[]"},
  {name:"spender",type:"address"},
  {name:"nonce",type:"uint256"},
  {name:"deadline",type:"uint256"}
 ];
 d.primaryType="PermitBatchTransferFrom";
 d.message.permitted=[d.message.permitted];
 const r=inspect(JSONify(d),{expectedSpender:SPENDER});
 assert.equal(r.observed.spender,SPENDER);
 assert.equal(r.observed.recipient,null);
 assert.ok(codes(r).includes("RECIPIENT_OUTSIDE_SIGNED_PERMIT"));
});
test("PermitWitnessTransferFrom requires additional witness semantics review",()=>{
 const d=typed();
 d.primaryType="PermitWitnessTransferFrom";
 d.types.PermitWitnessTransferFrom=d.types.PermitTransferFrom;
 const r=inspect(JSONify(d),{expectedSpender:SPENDER});
 assert.equal(r.observed.spender,SPENDER);
 assert.ok(codes(r).includes("WITNESS_REVIEW_REQUIRED"));
});
test("spender should never be set from a wrong Solidity type",()=>{
 const d=typed();d.types.PermitTransferFrom[1].type="string";
 const r=inspect(JSONify(d));
 assert.equal(r.observed.spender,null);
 assert.ok(codes(r).includes("SPENDER_NOT_DECLARED_IN_TYPES"));
});
test("high-risk spending amount remains flagged for an otherwise canonical spender",()=>{
 const d=typed();d.message.permitted.amount=MAX256.toString();
 const r=inspect(JSONify(d),{expectedSpender:SPENDER});
 assert.equal(r.observed.spender,SPENDER);
 assert.ok(codes(r).includes("MAXIMUM_ALLOWANCE"));
});
test("browser-only analysis does not authenticate or execute a signature",()=>{
 const r=inspect(JSONify(typed()));
 assert.equal(r.walletConnected,false);
 assert.equal(r.signed,false);
 assert.equal(r.uploaded,false);
 assert.equal(r.chargedUSDC,"0");
 assert.ok(r.limitations.some(x=>x.includes("not authenticated")));
});

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  inspect,SAMPLE_APPROVE,SAMPLE_PERMIT,SAMPLE_SIGNATURE_TRANSFER,
  BASE_USDC,MAX256,MAX160,PERMIT2
} from '../src/analysis.mjs';
import {
  compareUnsignedApprovalIntent,parseIntendedBaseUsdc,IntentComparisonError
} from '../src/intent-compare.mjs';

const spender='0x'+'2'.repeat(40);
const hexAmount=n=>n.toString(16).padStart(64,'0');
function calldata(amount,other={}){
  const obj=JSON.parse(SAMPLE_APPROVE);
  obj.data='0x095ea7b3'+'0'.repeat(24)+spender.slice(2)+hexAmount(amount);
  return JSON.stringify({...obj,...other});
}
function checked(raw='50',unsigned=SAMPLE_APPROVE){
  return compareUnsignedApprovalIntent(inspect(unsigned,{expectedChainId:'8453'}),raw);
}
function has(result,code){return result.findings.some(f=>f.code===code);}

test('parser uses exact six-decimal BigInt arithmetic, not floats',()=>{
  assert.equal(parseIntendedBaseUsdc('50').atomic,50000000n);
  assert.equal(parseIntendedBaseUsdc('0.000001').atomic,1n);
  assert.equal(parseIntendedBaseUsdc('50.123456').atomic,50123456n);
  assert.equal(parseIntendedBaseUsdc(' 50.5 ').atomic,50500000n);
  assert.equal(parseIntendedBaseUsdc('1000000000').atomic,1000000000000000n);
});
test('malformed, underspecified, off-range intent is rejected before any result',()=>{
  for(const value of ['', '0','-5','+5','1e2','0.0000001','NaN','Infinity',
    '1000000001','05','0x12','../../etc/passwd']){
    assert.throws(()=>parseIntendedBaseUsdc(value),IntentComparisonError);
  }
  for(const value of [50,true,{},null]){
    assert.throws(()=>parseIntendedBaseUsdc(value),IntentComparisonError);
  }
});
test('no input amount preserves the prior original analyzer output exactly',()=>{
  const original=inspect(SAMPLE_APPROVE);
  assert.strictEqual(compareUnsignedApprovalIntent(original,''),original);
  assert.strictEqual(compareUnsignedApprovalIntent(original,undefined),original);
});
test('real-world pain example: $50 intended, MAX_UINT256 approve prompts clear unlimited warning',()=>{
  const base=inspect(SAMPLE_APPROVE);
  const result=checked('50');
  assert.equal(result.observed.intendedSpendBaseCircleUsdc,'50');
  assert.equal(result.observed.intendedComparison,'UNLIMITED_REQUEST');
  assert.equal(result.observed.approvalToIntendedRatio,'MAX_UINT256');
  assert(has(result,'UNLIMITED_APPROVAL_FOR_LIMITED_INTENT'));
  assert(!base.observed.intendedSpendBaseCircleUsdc);
  assert(!JSON.stringify(base).includes('intendedComparison'));
  assert(result.limitations.some(t=>t.includes('NOT inspect a previously granted allowance')));
});
test('allowance $100 against intended $50 displays a bounded 2.00x warning',()=>{
  const r=checked('50',calldata(100000000n));
  assert.equal(r.observed.approvalToIntendedRatio,'2.00×');
  assert.equal(r.observed.intendedComparison,'REQUEST_EXCEEDS_INTENT');
  assert(has(r,'APPROVAL_GREATER_THAN_INTENDED'));
});
test('allowance $25 against intended $50 is not misrepresented as safe',()=>{
  const r=checked('50',calldata(25000000n));
  assert.equal(r.observed.approvalToIntendedRatio,'0.50×');
  assert(has(r,'APPROVAL_BELOW_INTENDED'));
  assert(r.verdict.includes('NOT_SAFE'));
});
test('matching $50 allowance is informational only, no safe-to-sign verdict',()=>{
  const r=checked('50',calldata(50000000n));
  assert.equal(r.observed.approvalToIntendedRatio,'1.00×');
  const match=r.findings.find(x=>x.code==='APPROVAL_EQUALS_INTENDED');
  assert.equal(match.level,'info');
  assert(r.verdict.includes('NOT_SAFE'));
});
test('bridged USDbC Base token not silently assumed to have canonical 6 decimals',()=>{
  const r=checked('50',calldata(50000000n,{to:'0xd9aaec86b65d86f6a7b5b1b0c42ffa531710b6ca'}));
  assert(has(r,'UNVERIFIED_USDC_TOKEN'));
  assert.equal(r.observed.approvalToIntendedRatio,undefined);
});
test('wrong chain or omitted chain refuses Circle Base units',()=>{
  for(const value of [1,null]){
    const r=checked('50',calldata(50000000n,{chainId:value}));
    assert(has(r,'INTENT_COMPARISON_CHAIN_UNKNOWN'));
    assert.equal(r.observed.intendedComparison,'UNVERIFIABLE');
  }
});
test('EIP2612 typed Permit on exact Circle Base USDC also compares intent',()=>{
  const r=checked('1',SAMPLE_PERMIT);
  assert.equal(r.observed.primaryType,'Permit');
  assert.equal(r.observed.intendedComparison,'REQUEST_EQUALS_INTENT');
});
test('EIP712 type cannot pretend to be transfer permission outside its declared scope',()=>{
  const r=checked('50',SAMPLE_SIGNATURE_TRANSFER);
  assert(has(r,'UNKNOWN_APPROVAL_SEMANTICS'));
});
test('max Permit2 uint160 allowance Base USDC is flagged as unlimited',()=>{
  const raw=JSON.stringify({
    types:{
      EIP712Domain:[
        {name:'name',type:'string'},{name:'chainId',type:'uint256'},
        {name:'verifyingContract',type:'address'}],
      PermitDetails:[
        {name:'token',type:'address'},{name:'amount',type:'uint160'},
        {name:'expiration',type:'uint48'},{name:'nonce',type:'uint48'}],
      PermitSingle:[
        {name:'details',type:'PermitDetails'},
        {name:'spender',type:'address'},
        {name:'sigDeadline',type:'uint256'}]
    },
    domain:{name:'Permit2',chainId:8453,verifyingContract:PERMIT2},
    primaryType:'PermitSingle',
    message:{
      details:{token:BASE_USDC,amount:MAX160.toString(),expiration:'1893456000',nonce:'3'},
      spender,sigDeadline:'1893456000'
    }
  });
  const r=checked('50',raw);
  assert.equal(r.observed.approvalToIntendedRatio,'MAX_UINT160');
  assert(has(r,'UNLIMITED_APPROVAL_FOR_LIMITED_INTENT'));
});
test('non-approval calldata is never misinterpreted as a spend authority',()=>{
  const tx=JSON.parse(SAMPLE_APPROVE);
  tx.data='0xa9059cbb'+tx.data.slice(10);
  const r=checked('50',JSON.stringify(tx));
  assert(has(r,'NOT_ERC20_APPROVAL'));
  assert.equal(r.observed.approvalToIntendedRatio,undefined);
});
test('zero token allowance rejects attempt to interpret it as an exact spender permission',()=>{
  const r=checked('50',calldata(0n));
  assert(has(r,'APPROVAL_BELOW_INTENDED'));
  assert.equal(r.observed.approvalToIntendedRatio,'0.00×');
});
test('single reporter does not request keys, RPC, state storage, a wallet, or publish user inputs',()=>{
  const check=(f)=>String.raw({raw:f});
  const doc=check(compareUnsignedApprovalIntent.toString()+parseIntendedBaseUsdc.toString());
  assert(!/fetch\(|ethereum\.request|eth_sendTransaction|XMLHttpRequest|localStorage|sessionStorage|navigator\.sendBeacon/.test(doc));
  const x=checked('50');
  assert.equal(x.walletConnected,false);
  assert.equal(x.uploaded,false);
  assert.equal(x.signed,false);
  assert.equal(x.chargedUSDC,'0');
});

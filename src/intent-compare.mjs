/**
 * Optional Base Circle USDC intended-spend comparison against one locally
 * pasted unsigned allowance. No wallet/RPC/network and NO safe-to-sign verdict.
 */
import {BASE_USDC,MAX256,MAX160} from './analysis.mjs';

const USDC=BASE_USDC.toLowerCase();
const UNIT=1000000n;
const MAX_INTENDED=1000000000n*UNIT;
const isObject=x=>x!==null&&typeof x==='object'&&!Array.isArray(x);

export class IntentComparisonError extends Error {
  constructor(code){super(code);this.code=code;this.name='IntentComparisonError';}
}
export function parseIntendedBaseUsdc(raw){
  if(typeof raw!=='string'||raw.length>48)
    throw new IntentComparisonError('INVALID_INTENDED_BASE_USDC');
  const s=raw.trim();
  if(!/^(?:0|[1-9]\d{0,9})(?:\.\d{1,6})?$/.test(s))
    throw new IntentComparisonError('INVALID_INTENDED_BASE_USDC');
  const [whole,fraction='']=s.split('.');
  const n=BigInt(whole)*UNIT+BigInt(fraction.padEnd(6,'0')||'0');
  if(n<=0n||n>MAX_INTENDED)
    throw new IntentComparisonError('INTENDED_AMOUNT_OUT_OF_RANGE');
  return {text:s,atomic:n};
}
function compareRatio(authorized,intended){
  if(authorized>=intended*1000000n)return '>1,000,000×';
  // BigInt fixed two-decimal read-only ratio, not a wallet quote.
  const scaled=authorized*100n/intended;
  return String(scaled/100n)+'.'+(scaled%100n).toString().padStart(2,'0')+'×';
}
function scope(report){
  if(!isObject(report)||!isObject(report.observed)||!Array.isArray(report.findings))
    throw new IntentComparisonError('INVALID_INSPECTION_RECEIPT');
  const o=report.observed;
  if(o.chainId!==8453)return {code:'INTENT_COMPARISON_CHAIN_UNKNOWN',
    reason:'The supplied unsigned request is not explicitly bound to Base chain 8453; token units cannot be assumed to be Base Circle USDC.'};
  if(report.inputKind==='UNSIGNED_CALLDATA'){
    if(o.action!=='ERC20_APPROVE')return {code:'NOT_ERC20_APPROVAL',
      reason:'This calldata is not a standard ERC-20 approve request; allowance-to-spend comparison does not apply.'};
    if(typeof o.tokenContract!=='string'||o.tokenContract.toLowerCase()!==USDC)
      return {code:'UNVERIFIED_USDC_TOKEN',
        reason:'This token contract is not canonical Base Circle USDC. Token decimals cannot be assumed.'};
    return {atomic:o.amountAtomic,maximum:MAX256};
  }
  if(report.inputKind==='EIP712_UNSIGNED'&&o.primaryType==='Permit'&&
     typeof o.verifyingContract==='string'&&o.verifyingContract.toLowerCase()===USDC)
    return {atomic:o.amounts?.[0]?.atomic,maximum:MAX256};
  if(report.inputKind==='EIP712_UNSIGNED'&&o.primaryType==='PermitSingle'&&
     o.amounts?.length===1&&typeof o.amounts[0].token==='string'&&
     o.amounts[0].token.toLowerCase()===USDC)
    return {atomic:o.amounts[0].atomic,maximum:MAX160};
  return {code:'UNKNOWN_APPROVAL_SEMANTICS',
    reason:'This signing request does not establish a single recognized Base Circle USDC approval amount; cannot compute a ratio.'};
}
export function compareUnsignedApprovalIntent(report,rawAmount){
  if(rawAmount===undefined||rawAmount===null||rawAmount==='')return report;
  const intended=parseIntendedBaseUsdc(rawAmount);
  const o=scope(report);
  const result={
    ...report,
    observed:{...report.observed,intendedSpendBaseCircleUsdc:intended.text},
    findings:report.findings.slice(),
    limitations:[
      ...(report.limitations||[]),
      'This is only a local comparison against user-supplied UNSIGNED JSON. It does NOT inspect a previously granted allowance, authenticate a dApp, guarantee that a spender is safe, simulate a transaction or revoke approval.'
    ]
  };
  const add=(code,reason,level='attention')=>result.findings.push({code,reason,level});
  if(o.code){
    add(o.code,o.reason);
    result.observed.intendedComparison='UNVERIFIABLE';
    return result;
  }
  if(typeof o.atomic!=='string'||!/^(?:0|[1-9]\d*)$/.test(o.atomic)){
    add('APPROVAL_AMOUNT_UNKNOWN','Approval amount is absent or unreadable; cannot compare it to intended spending.');
    result.observed.intendedComparison='UNVERIFIABLE';
    return result;
  }
  const allowance=BigInt(o.atomic);
  if(allowance===o.maximum){
    add('UNLIMITED_APPROVAL_FOR_LIMITED_INTENT',
      'The unsigned request asks for maximum-width allowance, vastly more than your intended spend. This is not an exact one-time permission. Verify spender, token and approval policy independently.');
    result.observed.intendedComparison='UNLIMITED_REQUEST';
    result.observed.approvalToIntendedRatio='MAX_UINT'+(o.maximum===MAX160?'160':'256');
  }else if(allowance>intended.atomic){
    add('APPROVAL_GREATER_THAN_INTENDED',
      'Requested approval exceeds your intended USDC spend. Confirm why the dApp needs a larger reusable allowance and how it can be limited or revoked.');
    result.observed.intendedComparison='REQUEST_EXCEEDS_INTENT';
    result.observed.approvalToIntendedRatio=compareRatio(allowance,intended.atomic);
  }else if(allowance<intended.atomic){
    add('APPROVAL_BELOW_INTENDED',
      'Requested approval is smaller than intended spend. The intended operation could fail or require more approval; this is not a safe-to-sign conclusion.');
    result.observed.intendedComparison='REQUEST_BELOW_INTENT';
    result.observed.approvalToIntendedRatio=compareRatio(allowance,intended.atomic);
  }else{
    add('APPROVAL_EQUALS_INTENDED',
      'Requested amount equals intended spending, but spender authenticity and actual onchain allowance are NOT verified.','info');
    result.observed.intendedComparison='REQUEST_EQUALS_INTENT';
    result.observed.approvalToIntendedRatio='1.00×';
  }
  return result;
}

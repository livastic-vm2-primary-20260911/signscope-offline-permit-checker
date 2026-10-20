/**
 * SignScope Permit2 Call Preflight — purely local, untrusted planning JSON.
 *
 * This is a comparison of USER ASSERTIONS, NOT real chain state, full calldata
 * decoding, transaction simulation, EIP712 hashing/signature verification,
 * contract authentication, or a warranty that a wallet action is safe.
 */
import {addr,uint,parse,MAX160,MAX256,PERMIT2,BASE_USDC} from "../src/analysis.mjs";

export const MAX_PLAN_BYTES = 40000;
const BOUND_ENTRIES=20;
const PERMIT2_LOWER=PERMIT2.toLowerCase();
const USDC_LOWER=BASE_USDC.toLowerCase();
const isObj=x=>x!==null&&typeof x==="object"&&!Array.isArray(x);
const fail=s=>{throw new Error(s);};

export function assertUnambiguousJson(raw){
  if(typeof raw!=="string"||new TextEncoder().encode(raw).length>MAX_PLAN_BYTES)
    fail("JSON must be a bounded 40 KB plain text string");
  let i=0, nodes=0, depth=0;
  const ws=()=>{while(/\s/.test(raw[i]||"")&&i<raw.length)i++;};
  const string=()=>{
    if(raw[i]!=='"')fail("Expected JSON string");
    const start=i++;let escape=false;
    for(;i<raw.length;i++){
      const c=raw[i];
      if(escape){escape=false;continue;}
      if(c==="\\"){escape=true;continue;}
      if(c==='"'){
        ++i;
        return JSON.parse(raw.slice(start,i));
      }
    }
    fail("Unterminated JSON string");
  };
  const value=()=>{
    if(++nodes>3500)fail("JSON too complex");
    if(++depth>11)fail("JSON too deeply nested");
    ws();
    const c=raw[i];
    if(c==='{'){
      i++;ws();
      const keys=new Set();
      if(raw[i]==='}'){i++;depth--;return;}
      let n=0;
      while(i<raw.length){
        if(++n>100)fail("Too many object properties");
        ws();const key=string();
        if(keys.has(key))fail("Duplicate JSON property rejected; cannot trust overwritten financial fields");
        keys.add(key);ws();
        if(raw[i++]!==':')fail("Missing JSON field separator");
        value();ws();
        if(raw[i]===','){i++;continue;}
        if(raw[i]==='}'){i++;depth--;return;}
        fail("Malformed JSON object separator");
      }
      fail("Unterminated JSON object");
    }
    if(c==='['){
      i++;ws();if(raw[i]===']'){i++;depth--;return;}
      let n=0;
      while(i<raw.length){
        if(++n>100)fail("Too many array entries");
        value();ws();
        if(raw[i]===','){i++;continue;}
        if(raw[i]===']'){i++;depth--;return;}
        fail("Malformed JSON array separator");
      }
      fail("Unterminated JSON array");
    }
    if(c==='"'){string();depth--;return;}
    const rest=raw.slice(i);
    const match=/^(?:true|false|null|-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?)/.exec(rest);
    if(!match)fail("Invalid JSON value");
    i+=match[0].length;depth--;
  };
  ws();value();ws();
  if(i!==raw.length)fail("Trailing content after JSON");
  return true;
}

const safeTimestamp=(x,now,check)=> {
  const n=uint(x,256);
  if(n===null){check("INVALID_TIME","Timestamp is missing or not a nonnegative integer");return null;}
  const parsed=Number(n);
  if(!Number.isSafeInteger(parsed)){
    check("TIME_OUT_OF_RANGE","Timestamp cannot be checked safely on this system");
    return null;
  }
  if(parsed<now) check("EXPIRED","An authorization deadline/expiration is in the past");
  if(parsed>now+86400*365)check("LONG_LIVED","Authorization deadline or allowance expiration is more than one year away");
  return parsed;
};
const addressToString=x=>addr(x)||null;
const mapAmount=(value,bits,check)=>{
  const n=uint(value,bits);
  if(n===null){check("AMOUNT_INVALID","Amount is not an unsigned integer fitting this Permit2 flow");return null;}
  if(n===(bits===160?MAX160:MAX256))
    check("UNLIMITED_AMOUNT","Declared allowance/limit uses the maximum unsigned integer");
  return n;
};
const present=v=>v!==null&&v!==undefined&&v!=="";
const same=(a,b)=>Boolean(a&&b&&a.toLowerCase()===b.toLowerCase());

export const SAMPLE_BROKEN_ALLOWANCE=JSON.stringify({
 flow:"allowanceTransfer",
 chainId:11155111,
 expectedChainId:11155111,
 permit2Address:PERMIT2,
 calledContract:PERMIT2,
 functionName:"permitBatch",
 owner:"0x1111111111111111111111111111111111111111",
 caller:"0x9999999999999999999999999999999999999999",
 intendedSpender:"0x9999999999999999999999999999999999999999",
 transferCaller:"0x9999999999999999999999999999999999999999",
 erc20ApprovedToPermit2:"unknown",
 permit:{
  spender:PERMIT2,
  details:[{token:BASE_USDC,amount:MAX160.toString(),expiration:"1893456000",nonce:"1"}],
  sigDeadline:"1893456000"
 },
 transferFrom:{
  from:"0x1111111111111111111111111111111111111111",
  to:"0x3333333333333333333333333333333333333333",
  token:BASE_USDC,amount:"500000"
 }
},null,2);

export const SAMPLE_SIGNATURE_TRANSFER=JSON.stringify({
 flow:"signatureTransfer",
 chainId:11155111,
 expectedChainId:11155111,
 permit2Address:PERMIT2,
 calledContract:PERMIT2,
 functionName:"permitTransferFrom",
 owner:"0x1111111111111111111111111111111111111111",
 caller:"0x9999999999999999999999999999999999999999",
 intendedSpender:"0x9999999999999999999999999999999999999999",
 erc20ApprovedToPermit2:"unknown",
 permit:{permitted:{token:BASE_USDC,amount:"1000000"},nonce:"1",deadline:"1893456000"},
 transferDetails:{to:"0x3333333333333333333333333333333333333333",requestedAmount:"500000"}
},null,2);

export function analyzePlan(raw,options={}){
  assertUnambiguousJson(raw);
  const d=parse(raw);
  const flow=d.flow;
  if(flow!=="allowanceTransfer"&&flow!=="signatureTransfer")
    fail("Select one known flow: allowanceTransfer or signatureTransfer");
  const now=Number.isSafeInteger(options.nowSeconds)?options.nowSeconds:Math.floor(Date.now()/1000);
  const findings=[],add=(code,message,severity="attention")=>{
    if(findings.length<70)findings.push({code,message,severity});
  };
  // An explicit null from the UI means "Not sure". Do NOT silently treat
  // an untrusted value embedded in buyer-provided JSON as independent evidence.
  const optsChain=Object.hasOwn(options,"expectedChainId")
    ?(options.expectedChainId===null?null:uint(options.expectedChainId,256))
    :present(d.expectedChainId)?uint(d.expectedChainId,256):null;
  const chainVal=uint(d.chainId,256);
  const chain=chainVal!==null && chainVal<=BigInt(Number.MAX_SAFE_INTEGER)?Number(chainVal):null;
  if(chain===null)add("CHAIN_UNREADABLE","The plan does not include a valid chainId");
  if(present(options.expectedChainId)&&optsChain===null)
    add("EXPECTED_CHAIN_UNREADABLE","Expected chain could not be parsed");
  if(optsChain!==null&&chainVal!==null&&optsChain!==chainVal)
    add("CHAIN_MISMATCH","Actual declared chain differs from the independently expected chain");
  const contract=addressToString(d.calledContract);
  const claimedPermit2=addressToString(d.permit2Address);
  if(!contract||contract!==PERMIT2_LOWER)
    add("PERMIT2_DESTINATION_MISMATCH","Called contract is not the official Permit2 address; chain deployment has not been authenticated");
  if(!claimedPermit2||claimedPermit2!==PERMIT2_LOWER)
    add("PERMIT2_DOMAIN_MISMATCH","Claimed EIP-712 verifying contract differs from canonical Permit2");
  const owner=addressToString(d.owner);
  const caller=addressToString(d.caller);
  const intendedSpender=addressToString(d.intendedSpender);
  const status=d.erc20ApprovedToPermit2;
  if(status!=="yes"&&status!=="no"&&status!=="unknown")
    add("ERC20_APPROVAL_UNVERIFIED","Underlying ERC-20 approval to Permit2 is unknown; this static tool NEVER looks up onchain allowance");
  else if(status==="no")add("ERC20_APPROVAL_REPORTED_MISSING","Input states the ERC-20 token has not approved Permit2");
  else if(status==="unknown")add("ERC20_APPROVAL_UNVERIFIED","Check independent token approval to Permit2: a Permit2 signature is not by itself the ERC-20 token's approval");
  else add("ERC20_APPROVAL_SELF_REPORTED","ERC-20 approval is only user-asserted, NOT verified onchain","info");
  if(!owner)add("OWNER_INVALID","Owner is missing or not a valid EVM address");
  if(!caller)add("CALLER_UNKNOWN","The actual contract caller (msg.sender) is not known");
  if(!intendedSpender)add("INTENDED_SPENDER_UNKNOWN","Intended spender is absent or malformed");
  if(caller&&intendedSpender&&!same(caller,intendedSpender)&&flow==="signatureTransfer")
    add("ACTUAL_CALLER_MISMATCH","Permit2 SignatureTransfer binds its spender via msg.sender; the caller differs from the expected spender");
  let shape="unknown";
  const observed={
    flow,chainId:chain,expectedChainId:optsChain===null?null:optsChain.toString(),
    claimedPermit2,calledContract:contract,owner,caller,intendedSpender,
    underlyingApprovalClaim:status||"unknown",
    functionName:typeof d.functionName==="string"?d.functionName.slice(0,80):null,
    spender:null,recipient:null,token:null,permittedAtomic:null,requestedAtomic:null,
    signatureDeadline:null,allowanceExpiration:null,
    nonce:null,notes:["All fields are assertions supplied in this local JSON, never authenticated blockchain state."]
  };
  const permit=isObj(d.permit)?d.permit:{};
  if(!isObj(d.permit))add("PERMIT_MISSING","Expected permit object is missing");
  if(flow==="allowanceTransfer"){
    shape="AllowanceTransfer";
    if(d.functionName!=="permit")
      add("WRONG_FUNCTION_NAME","AllowanceTransfer accepts permit(owner,PermitSingle|PermitBatch,bytes), NOT a seven-argument permitBatch method");
    const spender=addressToString(permit.spender);
    observed.spender=spender;
    if(!spender)add("PERMIT_SPENDER_INVALID","PermitSingle/PermitBatch signed spender is absent/malformed");
    if(intendedSpender&&spender&&!same(intendedSpender,spender))
      add("SIGNED_SPENDER_MISMATCH","Permit's declared spender does not match the app contract intended to spend");
    const transferCaller=addressToString(d.transferCaller);
    if(!transferCaller)
      add("TRANSFER_CALLER_UNKNOWN","The later Permit2.transferFrom actual caller is missing");
    else if(spender&&!same(transferCaller,spender))
      add("TRANSFER_CALLER_MISMATCH","Permit2.transferFrom checks allowance granted to msg.sender, not the Permit2 contract itself");
    observed.transferCaller=transferCaller;
    if(present(permit.sigDeadline))
      observed.signatureDeadline=safeTimestamp(permit.sigDeadline,now,add);
    else add("SIGNATURE_DEADLINE_UNKNOWN","Permit signature deadline absent");
    const rawDetails=Array.isArray(permit.details)?permit.details:[permit.details];
    if(rawDetails.length>BOUND_ENTRIES)fail("Too many Permit2 token allowances (>20)");
    if(rawDetails.length===0||!rawDetails.every(isObj))
      add("PERMIT_DETAILS_INVALID","Permit details must be a single object or an array of token allowances");
    const details=rawDetails.filter(isObj);
    const valid=[];
    for(const item of details){
      const token=addressToString(item.token);
      const amount=mapAmount(item.amount,160,add);
      if(uint(item.nonce,48)===null)add("NONCE_INVALID","AllowanceTransfer PermitDetails nonce must be uint48");
      let exp=null;
      if(present(item.expiration)){
        if(uint(item.expiration,48)===null)
          add("ALLOWANCE_EXPIRY_INVALID_UINT48","AllowanceTransfer expiration must fit in uint48");
        exp=safeTimestamp(item.expiration,now,add);
      }else add("ALLOWANCE_EXPIRY_UNKNOWN","AllowanceTransfer expiration is missing");
      valid.push({token,amount,expiry:exp});
    }
    if(valid.length>0) observed.allowanceExpiration=valid[0].expiry;
    const transfer=isObj(d.transferFrom)?d.transferFrom:{};
    if(!isObj(d.transferFrom))add("TRANSFER_CALL_MISSING","Missing later transferFrom request");
    const target=addressToString(transfer.to),token=addressToString(transfer.token);
    const from=addressToString(transfer.from);
    observed.recipient=target;
    observed.token=token;
    if(owner&&from&&!same(owner,from))
      add("TRANSFER_OWNER_MISMATCH","transferFrom.from differs from token owner's declared address");
    if(!target)add("RECIPIENT_UNKNOWN","Recipient to was not a valid address");
    if(!token)add("TRANSFER_TOKEN_UNKNOWN","Transfer token address not valid");
    const requested=mapAmount(transfer.amount,160,add);
    observed.requestedAtomic=requested?.toString()||null;
    const candidates=valid.filter(x=>x.token&&x.token===token);
    if(candidates.length===0){
      add("TOKEN_NOT_PERMITTED","Requested transfer token is missing from declared signed allowance details");
    }else {
      const matched=candidates[0];
      observed.permittedAtomic=matched.amount?.toString()||null;
      if(matched.amount!==null&&requested!==null&&requested>matched.amount)
        add("TRANSFER_AMOUNT_EXCEEDS_ALLOWANCE","Requested amount exceeds the declared signed token allowance");
    }
    if(spender&&same(spender,PERMIT2_LOWER))
      add("SELF_SPENDER_RISK","Spender field identifies Permit2 itself rather than the actual dApp contract caller");
    // An AllowanceTransfer permit() can be submitted by relayers. Only
    // the subsequent transferFrom caller must equal the permit spender.
  }else{
    shape="SignatureTransfer";
    if(d.functionName!=="permitTransferFrom")
      add("WRONG_FUNCTION_NAME","SignatureTransfer uses permitTransferFrom(PermitTransferFrom,SignatureTransferDetails,owner,signature); not an arbitrary extra spender/to/amount function");
    if(present(permit.spender))
      add("EXTRA_SIGNED_SPENDER_FIELD","PermitTransferFrom struct does NOT have a standalone spender field; Permit2 binds the actual caller in its authorization hash");
    observed.spender=caller;
    if(present(permit.deadline))
      observed.signatureDeadline=safeTimestamp(permit.deadline,now,add);
    else add("SIGNATURE_DEADLINE_UNKNOWN","PermitTransferFrom deadline is missing");
    const nonce=uint(permit.nonce,256);
    if(nonce===null)add("NONCE_INVALID","SignatureTransfer nonce must be a nonnegative uint256");
    observed.nonce=nonce?.toString()||null;
    const signed=Array.isArray(permit.permitted)?permit.permitted:[permit.permitted];
    const detailArray=Array.isArray(d.transferDetails)?d.transferDetails:[d.transferDetails];
    if(signed.length>BOUND_ENTRIES||detailArray.length>BOUND_ENTRIES)
      fail("Too many Permit2 batch items (>20)");
    if(signed.length!==detailArray.length)
      add("BATCH_LENGTH_MISMATCH","Signed permitted token array and caller transferDetails array have unequal lengths");
    for(let i=0;i<Math.min(signed.length,detailArray.length);i++){
      const p=signed[i],t=detailArray[i];
      if(!isObj(p)||!isObj(t)){add("TRANSFER_DETAILS_INVALID","A signed permitted item or caller transfer detail is malformed");continue;}
      const token=addressToString(p.token);
      const recipient=addressToString(t.to);
      const permitted=mapAmount(p.amount,256,add);
      const requested=mapAmount(t.requestedAmount,256,add);
      if(!token)add("TOKEN_UNKNOWN","Signed permitted item has invalid token address");
      if(!recipient)add("RECIPIENT_UNKNOWN","Caller-supplied recipient is absent or invalid");
      if(permitted!==null&&requested!==null&&requested>permitted)
        add("REQUEST_EXCEEDS_PERMIT","Caller-requested transfer amount is larger than signed permitted amount");
      if(i===0){
        observed.token=token;observed.recipient=recipient;
        observed.permittedAtomic=permitted?.toString()||null;
        observed.requestedAtomic=requested?.toString()||null;
      }
    }
    add("RECIPIENT_NOT_SIGNED","SignatureTransfer recipient and requestedAmount are caller-supplied calldata, not both bound as fields in PermitTransferFrom typed data","info");
    add("SIGNATURE_CALLER_NOT_AUTHENTICATED","Static input cannot establish the actual msg.sender, recovered signer, nonce bitmap or signature validity","info");
  }
  observed.shape=shape;
  if(observed.token===USDC_LOWER&&chain!==null&&chain!==8453)
    add("TOKEN_CHAIN_UNVERIFIED","The published Base Circle USDC token address does not establish a real supported token contract on this different chain");
  if(observed.token===USDC_LOWER&&chain===8453)
    observed.amountInterpretation="Known native Circle USDC on Base has six decimals; only numeric conversion, never live token validation";
  else
    observed.amountInterpretation="Raw atomic token units; decimals and chain token authenticity unverified";
  return {
    product:"SignScope / FREE PRIVATE Permit2 Preflight",
    analysisKind:"FICTIONAL_OR_USER_ASSERTED_INPUT_ONLY",
    shippedInput:false,walletConnected:false,signaturesProduced:false,
    transfersSent:false,paid:false,chargedNativeUSDC:"0",
    verdict:"REVIEW_REQUIRED_NOT_A_SAFE_TO_SIGN_VERDICT",
    observed, findings,
    attentionCount:findings.filter(x=>x.severity!=="info").length,
    limitations:[
      "No wallet connection, nonce bitmap, token allowance, actual msg.sender, signature, contract bytecode, token balance, gas or revert simulation was performed.",
      "A checked box saying ERC-20 approved is only user input. Do not infer real onchain state.",
      "An ABI shape check is not a guarantee of transaction success. Verify official interfaces, EIP712 hashing and actual custom revert separately.",
      "Do not paste signatures, wallet seeds, API credentials, private customer data or real sensitive wallet holdings."
    ]
  };
}

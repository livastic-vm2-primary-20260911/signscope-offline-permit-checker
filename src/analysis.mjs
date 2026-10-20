/* SignScope — static pre-sign scope explanation; NOT signature verification,
 * authenticated simulation, onchain allowance index, or safety certification.
 * Never signs, asks for accounts, sends a transaction or fetches external data.
 */
export const MAX_BYTES=40000;
export const MAX256=(1n<<256n)-1n;
export const MAX160=(1n<<160n)-1n;
export const BASE_USDC="0x833589fCD6eDb6E08f4C7C32D4f71b54bdA02913";
export const PERMIT2="0x000000000022D473030F116dDEE9F6B43aC78BA3";
const ADDRESS=/^0x[0-9a-fA-F]{40}$/;
const isObj=v=>v!==null&&typeof v==="object"&&!Array.isArray(v);
const must=(ok,msg)=>{if(!ok)throw new Error(msg);};
export const addr=v=>typeof v==="string"&&ADDRESS.test(v)?v.toLowerCase():null;
export function uint(v,bits=256){
  if(typeof v==="number"&&(!Number.isSafeInteger(v)||v<0))return null;
  if(typeof v!=="string"&&typeof v!=="number")return null;
  const s=String(v);
  if(s.length>80||!/^(?:0|[1-9][0-9]*|0x[0-9a-fA-F]+)$/.test(s))return null;
  try{const b=BigInt(s);return b>=0n&&b<=(1n<<BigInt(bits))-1n?b:null;}catch{return null;}
}
function guard(v,depth=0,counter={n:0}){
  must(depth<=10,"Too much nested JSON");
  if(!v||typeof v!=="object")return;
  must(++counter.n<4000,"JSON too complex");
  if(Array.isArray(v)){
    must(v.length<=100,"Array too large");
    v.forEach(x=>guard(x,depth+1,counter));return;
  }
  const keys=Object.keys(v);
  must(keys.length<=100,"Object too wide");
  for(const k of keys){
    must(!/^(privateKey|mnemonic|seedPhrase|secretKey|rawSignature|signature|signatures)$/i.test(k),
         "DO NOT paste signatures or private keys");
    guard(v[k],depth+1,counter);
  }
}
export function parse(raw){
  must(typeof raw==="string","Paste plain text JSON, not a wallet signature");
  const len=new TextEncoder().encode(raw).length;
  must(len>=10&&len<=MAX_BYTES,"Input must be 10–40,000 UTF-8 bytes");
  must(!raw.includes("\0"),"NUL bytes rejected");
  let obj;try{obj=JSON.parse(raw);}catch{throw new Error("Invalid JSON");}
  must(isObj(obj),"JSON root must be an object");guard(obj);
  return obj;
}
function hasFields(arr,fields){
  return Array.isArray(arr)&&fields.every(k=>arr.some(x=>isObj(x)&&x.name===k));
}
function normalLabel(v,n=70){
  return typeof v==="string"?v.replace(/[\x00-\x1f]/g," ").slice(0,n):null;
}
function formatUnits(n,decimals=6){
  const p=10n**BigInt(decimals),part=String(n%p).padStart(decimals,"0").replace(/0+$/,"");
  return (n/p).toString()+(part?"."+part:"");
}
function amountInfo(value,token,chain,bits=256){
  const n=uint(value,bits),t=addr(token);
  return {
    token:t,
    atomic:n===null?"UNREADABLE":n.toString(),
    display:n===null?"Unreadable amount":
      n===(1n<<BigInt(bits))-1n
        ?"MAX_UINT"+bits+" — effectively unlimited if used as an allowance"
        :(t===BASE_USDC.toLowerCase()&&chain===8453
          ?formatUnits(n)+" native Circle USDC (Base)"
          :"Raw token units; decimals NOT verified"),
    maximum:n!==null&&n===(1n<<BigInt(bits))-1n,
    zero:n===0n
  };
}
const nowSeconds=()=>Math.floor(Date.now()/1000);
const blankResult=(inputKind,observed,findings)=>({
  product:"SignScope",inputKind,
  unsignedSourceOnly:true,uploaded:false,walletConnected:false,signed:false,chargedUSDC:"0",
  verdict:"REVIEW_REQUIRED_NOT_SAFE_CERTIFICATION",
  observed,findings,
  limitations:[
    "User-submitted unsigned JSON is not authenticated. No contract bytecode, ledger, nonce state or token decimals fetched.",
    "Unknown methods/contract logic cannot be simulated or classified reliably.",
    "Never use this preview as permission to sign, approve, or send tokens."
  ]
});

export function inspectTyped(raw,opts={}){
  const d=parse(raw);
  must(isObj(d.types)&&isObj(d.domain)&&isObj(d.message)&&
       typeof d.primaryType==="string"&&d.primaryType.length<=100,
       "Expected EIP-712 types, domain, primaryType, message");
  const primary=d.primaryType,m=d.message,t=d.types,domain=d.domain;
  const expectedChain=opts.expectedChainId===null?null:uint(opts.expectedChainId??"8453");
  const expectedSpender=addr(opts.expectedSpender);
  const expectedContract=addr(opts.expectedContract);
  const now=Number.isSafeInteger(opts.nowSeconds)?opts.nowSeconds:nowSeconds();
  const warnings=[],add=(code,reason,level="attention")=>{
    if(warnings.length<65)warnings.push({code,level,reason});
  };
  const chainU=uint(domain.chainId),chain=chainU!==null&&chainU<1000000000n?Number(chainU):null;
  const verifying=addr(domain.verifyingContract);
  // EIP-712 domain fields shown in a JSON object are not necessarily
  // cryptographically bound if omitted from its EIP712Domain type. Warn.
  const domainType=t.EIP712Domain;
  if(!Array.isArray(domainType)){
    add("DOMAIN_TYPE_MISSING","EIP712Domain type declaration was not provided; cannot verify which domain fields are signed.");
  }else{
    for(const [key,type] of [["chainId","uint256"],["verifyingContract","address"]]){
      if(domain[key]!==undefined&&!domainType.some(f=>isObj(f)&&f.name===key&&f.type===type))
        add("DOMAIN_FIELD_NOT_DECLARED","The "+key+" field is displayed but not declared with its expected EIP712 type.");
    }
  }
  if(chain===null)add("CHAIN_MISSING","No valid chainId binds this domain.");
  else if(expectedChain!==null&&chainU!==expectedChain)
    add("CHAIN_MISMATCH","Message chain differs from your expected network.");
  if(!verifying)add("DOMAIN_CONTRACT_MISSING","Missing EIP712 verifyingContract prevents independent contract binding.");
  else if(verifying==="0x"+"0".repeat(40))add("ZERO_VERIFYING_CONTRACT","Zero contract address is not a normal verifier.");
  if(expectedContract&&verifying!==expectedContract)
    add("CONTRACT_MISMATCH","Domain verifier differs from the independently expected contract.");

  let owner=null,spender=null,recipient=null,recognized=false,amounts=[],deadlines=[];
  const checkAmount=(value,token,bits=256)=>{
    const a=amountInfo(value,token,chain,bits);amounts.push(a);
    if(a.atomic==="UNREADABLE")add("AMOUNT_UNREADABLE","Cannot parse a nonnegative unsigned integer.");
    if(a.maximum)add("MAXIMUM_ALLOWANCE","Maximum uint value gives a practically unlimited approval.");
    if(a.zero)add("ZERO_AMOUNT","Zero amount may grant no new spending or revoke permissions depending on contract.","info");
  };
  const checkDeadline=(name,value)=>{
    const n=uint(value);
    if(n===null){add("EXPIRY_UNKNOWN",name+" expiry is missing or unreadable");return;}
    const days=Number(n)/86400-now/86400;
    deadlines.push({name,epoch:n.toString(),daysFromNow:Number.isFinite(days)?Math.round(days*10)/10:null});
    if(days<0)add("EXPIRED",name+" already expired.");
    else if(days>365)add("LONG_LIVED",name+" remains usable for over one year.");
    else if(!Number.isFinite(days))add("EXPIRY_RANGE_UNKNOWN",name+" expiration is out of range.");
  };
  if(primary==="Permit"&&hasFields(t.Permit,["owner","spender","value","nonce","deadline"])){
    recognized=true;owner=addr(m.owner);spender=addr(m.spender);
    checkAmount(m.value,verifying);checkDeadline("deadline",m.deadline);
  }else if(primary==="TransferWithAuthorization"&&hasFields(t.TransferWithAuthorization,
      ["from","to","value","validAfter","validBefore","nonce"])){
    recognized=true;owner=addr(m.from);recipient=addr(m.to);
    checkAmount(m.value,verifying);checkDeadline("validBefore",m.validBefore);
    const a=uint(m.validAfter),z=uint(m.validBefore);
    if(a===null)add("START_UNKNOWN","Valid-after timestamp cannot be parsed.");
    if(a!==null&&Number(a)>now)add("FUTURE_START","Authorization not yet usable.","info");
    if(a!==null&&z!==null&&a>=z)add("BAD_WINDOW","Authorization start is not before expiry.");
  }else if(primary==="PermitSingle"&&hasFields(t.PermitSingle,["details","spender","sigDeadline"])&&isObj(m.details)){
    recognized=true;spender=addr(m.spender);
    checkAmount(m.details.amount,m.details.token,160);
    checkDeadline("allowance expiration",m.details.expiration);
    checkDeadline("signature deadline",m.sigDeadline);
  }else if(primary==="PermitBatch"&&hasFields(t.PermitBatch,["details","spender","sigDeadline"])&&Array.isArray(m.details)){
    recognized=true;spender=addr(m.spender);
    if(m.details.length>20)add("BATCH_TOO_LARGE","Only first 20 entries analyzed.");
    for(const a of m.details.slice(0,20)){
      if(!isObj(a)){add("INVALID_BATCH_ENTRY","Malformed token permission.");continue;}
      checkAmount(a.amount,a.token,160);checkDeadline("allowance expiration",a.expiration);
    }
    checkDeadline("signature deadline",m.sigDeadline);
  }else if(["PermitTransferFrom","PermitBatchTransferFrom","PermitWitnessTransferFrom"].includes(primary)&&
           Array.isArray(t[primary])&&Object.hasOwn(m,"permitted")&&Object.hasOwn(m,"deadline")){
    recognized=true;
    const entries=Array.isArray(m.permitted)?m.permitted:[m.permitted];
    if(entries.length>20)add("BATCH_TOO_LARGE","Only first 20 entries analyzed.");
    for(const a of entries.slice(0,20)){
      if(!isObj(a)){add("PERMISSION_UNKNOWN","Malformed token permissions.");continue;}
      checkAmount(a.amount,a.token);
    }
    checkDeadline("signature deadline",m.deadline);
    // The PermitHash library includes msg.sender in the signed struct hash
    // for SignatureTransfer even though permit's Solidity struct does NOT
    // declare a spender field. A complete EIP-712 signing request typically
    // declares spender:address in types and supplies the intended caller in
    // message. Do not conflate this caller-bound spender with the later
    // transferDetails.to and requestedAmount supplied to the contract call.
    const signatureType=t[primary];
    const declaredSpender=signatureType.some(
      f=>isObj(f)&&f.name==="spender"&&f.type==="address"
    );
    if(declaredSpender){
      spender=addr(m.spender);
      if(!spender)add("SPENDER_MISSING_IN_SUPPLIED_TYPED_DATA",
        "Signed Permit2 SignatureTransfer caller/spender was not present as a valid address; cannot verify caller binding from this JSON.");
    } else {
      add("SPENDER_NOT_DECLARED_IN_TYPES",
        "Supplied EIP-712 type omits or mistypes the spender:address field. Permit2 PermitHash includes msg.sender in its signature digest; this JSON cannot prove which caller was bound.");
    }
    if(primary==="PermitWitnessTransferFrom"){
      add("WITNESS_REVIEW_REQUIRED",
        "Witness-bound requests can sign additional application data; the witness type/hash and eventual transfer details are NOT decoded or authenticated here.");
    } else {
      add("RECIPIENT_OUTSIDE_SIGNED_PERMIT",
        "Permit2 SignatureTransfer separately receives recipient and requestedAmount in transferDetails. The signed spender/caller is bound through PermitHash msg.sender, but this unsigned JSON does NOT reveal or verify the eventual recipient or call.");
    }
  }
  // A matching field name with the wrong declared EIP-712 type is NOT
  // evidence that a token contract would consume the value as expected.
  if(recognized){
    const required={
      Permit:[["owner","address"],["spender","address"],["value","uint256"],["nonce","uint256"],["deadline","uint256"]],
      TransferWithAuthorization:[["from","address"],["to","address"],["value","uint256"],["validAfter","uint256"],["validBefore","uint256"],["nonce","bytes32"]],
      PermitSingle:[["details","PermitDetails"],["spender","address"],["sigDeadline","uint256"]],
      PermitBatch:[["details","PermitDetails[]"],["spender","address"],["sigDeadline","uint256"]],
      PermitTransferFrom:[["permitted","TokenPermissions"],["spender","address"],["nonce","uint256"],["deadline","uint256"]],
      PermitBatchTransferFrom:[["permitted","TokenPermissions[]"],["spender","address"],["nonce","uint256"],["deadline","uint256"]]
    };
    for(const [name,type] of required[primary]||[]){
      if(!t[primary]?.some(f=>isObj(f)&&f.name===name&&f.type===type))
        add("TYPE_DECLARATION_MISMATCH","Signed structure "+primary+" has missing/incorrect declared field: "+name+".");
    }
    if(primary==="PermitSingle"||primary==="PermitBatch"){
      const detailTypes=[["token","address"],["amount","uint160"],["expiration","uint48"],["nonce","uint48"]];
      for(const [name,type] of detailTypes){
        if(!t.PermitDetails?.some(f=>isObj(f)&&f.name===name&&f.type===type))
          add("PERMIT2_DETAILS_TYPE_UNKNOWN","Permit2 detail field "+name+" was not declared as "+type+".");
      }
    }
  }
  if(primary.startsWith("Permit")&&primary!=="Permit"&&verifying!==PERMIT2.toLowerCase())
    add("PERMIT2_DOMAIN_MISMATCH","Permit2-shaped message is not bound to canonical Permit2.");
  if(!recognized)add("UNRECOGNIZED_TYPE","Unknown or malformed signing type; no reliable grant semantics.");
  if(recognized&&(["Permit","TransferWithAuthorization"].includes(primary))&&!owner)
    add("OWNER_UNKNOWN","Missing/invalid owner or sender address.");
  if(recognized&&["Permit","PermitSingle","PermitBatch"].includes(primary)&&!spender)
    add("SPENDER_UNKNOWN","Missing/invalid spender in signed message.");
  if(recognized&&primary==="TransferWithAuthorization"&&!recipient)
    add("RECIPIENT_UNKNOWN","Missing/invalid transfer recipient.");
  if(owner==="0x"+"0".repeat(40))
    add("ZERO_OWNER_ADDRESS","Signer/owner is the zero address; an EIP-2612 Permit should reject this.");
  if(spender==="0x"+"0".repeat(40))
    add("ZERO_SPENDER_ADDRESS","Spender is the zero address; verify whether this is a deliberate revocation or malformed request.");
  if(recipient==="0x"+"0".repeat(40))
    add("ZERO_RECIPIENT_ADDRESS","Recipient is the zero address; a real transfer could be burned or rejected.");
  if(expectedSpender&&spender!==expectedSpender)
    add("EXPECTED_SPENDER_MISMATCH","Expected spender differs from the signed scope or is unavailable.");
  if(amounts.length===0)add("AMOUNT_UNKNOWN","No recognized token authorization amount displayed.");
  return blankResult("EIP712_UNSIGNED",{
    primaryType:primary,domainName:normalLabel(domain.name),
    domainVersion:normalLabel(domain.version,24),chainId:chain,
    verifyingContract:verifying,recognized,owner,spender,recipient,
    amounts,deadlines
  },warnings);
}

export function inspectCall(raw,opts={}){
  const d=parse(raw),data=d.data??d.input;
  must(typeof data==="string"&&/^0x[0-9a-fA-F]{8,2040}$/.test(data)&&data.length%2===0,
       "Expected bounded hex data in transaction envelope");
  const selector=data.slice(0,10).toLowerCase(),warnings=[],add=(code,reason)=>{
    if(warnings.length<45)warnings.push({code,level:"attention",reason});
  };
  const word=i=>{const x=data.slice(10+i*64,10+(i+1)*64);return x.length===64?x:null;};
  const wa=i=>{const x=word(i);return x&&/^0{24}[0-9a-fA-F]{40}$/.test(x)?addr("0x"+x.slice(24)):null;};
  const wn=i=>{const x=word(i);return x?BigInt("0x"+x):null;};
  const lengthCheck=n=>must(data.length===10+64*n,"Wrong ABI calldata length");
  let action="UNKNOWN_SELECTOR",spender=null,recipient=null,amount=null;
  let owner=addr(d.from);
  if(selector==="0x095ea7b3"){lengthCheck(2);action="ERC20_APPROVE";spender=wa(0);amount=wn(1);}
  else if(selector==="0xa22cb465"){
    lengthCheck(2);action="NFT_APPROVAL_FOR_ALL";spender=wa(0);amount=wn(1);
    if(amount===1n)add("ALL_NFT_OPERATOR","setApprovalForAll(true) grants operator access to all NFTs in this collection.");
    if(amount!==0n&&amount!==1n)add("MALFORMED_BOOL","NFT approval boolean must be zero or one.");
  }else if(selector==="0xa9059cbb"){lengthCheck(2);action="ERC20_TRANSFER";recipient=wa(0);amount=wn(1);}
  else if(selector==="0x23b872dd"){
    lengthCheck(3);action="ERC20_TRANSFER_FROM";owner=wa(0);recipient=wa(1);amount=wn(2);
    add("CALLER_UNKNOWN","Cannot prove caller authorization from input data.");
  }else add("UNKNOWN_SELECTOR","Unknown/dynamic calldata; cannot assess action.");
  if(amount===MAX256)add("UNLIMITED_AMOUNT","Max uint256 approval/amount.");
  if(["ERC20_APPROVE","NFT_APPROVAL_FOR_ALL"].includes(action)&&!spender)
    add("SPENDER_INVALID","Approval spender missing or invalid.");
  const chainU=uint(d.chainId),chain=chainU!==null&&chainU<1000000n?Number(chainU):null;
  const expectedChain=opts.expectedChainId===null?null:uint(opts.expectedChainId??"8453");
  if(chain===null)add("CHAIN_MISSING","Transaction does not specify chain.");
  else if(expectedChain!==null&&chainU!==expectedChain)add("CHAIN_MISMATCH","Unexpected network.");
  const contract=addr(d.to),expectedContract=addr(opts.expectedContract);
  if(expectedContract&&expectedContract!==contract)
    add("CONTRACT_MISMATCH","Called token contract differs from expected address.");
  const expectedSpender=addr(opts.expectedSpender);
  if(expectedSpender&&expectedSpender!==spender)
    add("SPENDER_MISMATCH","Operator differs from expected spender.");
  return blankResult("UNSIGNED_CALLDATA",{
    action,selector,chainId:chain,tokenContract:contract,
    owner,spender,recipient,amountAtomic:amount===null?null:amount.toString(),
    amountDisplay:amount===null?"Unknown":amountInfo(amount.toString(),contract,chain).display
  },warnings);
}
export function inspect(raw,opts={}){
  const d=parse(raw);
  if(isObj(d.types)&&isObj(d.domain)&&isObj(d.message))return inspectTyped(raw,opts);
  if(typeof d.data==="string"||typeof d.input==="string")return inspectCall(raw,opts);
  throw new Error("Expected UNSIGNED EIP712 JSON or transaction JSON envelope with data");
}
export const SAMPLE_PERMIT=JSON.stringify({
 types:{
   EIP712Domain:[{name:"name",type:"string"},{name:"version",type:"string"},
                {name:"chainId",type:"uint256"},{name:"verifyingContract",type:"address"}],
   Permit:[{name:"owner",type:"address"},{name:"spender",type:"address"},
           {name:"value",type:"uint256"},{name:"nonce",type:"uint256"},
           {name:"deadline",type:"uint256"}]
 },
 primaryType:"Permit",
 domain:{name:"USD Coin",version:"2",chainId:8453,verifyingContract:BASE_USDC},
 message:{owner:"0x1111111111111111111111111111111111111111",
          spender:"0x2222222222222222222222222222222222222222",
          value:"1000000",nonce:"1",deadline:"1893456000"}
},null,2);
// Fictional official-shaped Permit2 SignatureTransfer typed-data sample.
 // The spender in the digest must match the actual caller (msg.sender).
 // The later transferDetails recipient/requested amount are deliberately
 // unknown and NOT alleged to be signed by this JSON object.
export const SAMPLE_SIGNATURE_TRANSFER=JSON.stringify({
 types:{
   EIP712Domain:[
    {name:"name",type:"string"},{name:"chainId",type:"uint256"},
    {name:"verifyingContract",type:"address"}],
   TokenPermissions:[
    {name:"token",type:"address"},{name:"amount",type:"uint256"}],
   PermitTransferFrom:[
    {name:"permitted",type:"TokenPermissions"},
    {name:"spender",type:"address"},
    {name:"nonce",type:"uint256"},
    {name:"deadline",type:"uint256"}]
 },
 primaryType:"PermitTransferFrom",
 domain:{name:"Permit2",chainId:8453,verifyingContract:PERMIT2},
 message:{
   permitted:{token:BASE_USDC,amount:"5000000"},
   spender:"0x2222222222222222222222222222222222222222",
   nonce:"7",deadline:"1893456000"
 }
},null,2);
export const SAMPLE_APPROVE=JSON.stringify({
 chainId:8453,to:BASE_USDC,from:"0x1111111111111111111111111111111111111111",
 data:"0x095ea7b3"+"0".repeat(24)+"2".repeat(40)+MAX256.toString(16).padStart(64,"0")
},null,2);

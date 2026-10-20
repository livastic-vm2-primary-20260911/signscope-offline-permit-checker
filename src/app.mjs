import {
  inspect, BASE_USDC, PERMIT2, MAX160,
  SAMPLE_PERMIT, SAMPLE_APPROVE
} from "./analysis.mjs?v=20261020-typecheck";

const $ = id => document.getElementById(id);
const input=$("input-json");
const status=$("status");
const sampleNames={
  "sample-permit":"EIP-2612 Permit",
  "sample-permit2":"Permit2",
  "sample-eip3009":"USDC authorization",
  "sample-calldata":"ERC-20 approve"
};
const sample2=JSON.stringify({
  types:{
    EIP712Domain:[
      {name:"name",type:"string"},{name:"chainId",type:"uint256"},
      {name:"verifyingContract",type:"address"}],
    PermitDetails:[
      {name:"token",type:"address"},{name:"amount",type:"uint160"},
      {name:"expiration",type:"uint48"},{name:"nonce",type:"uint48"}],
    PermitSingle:[
      {name:"details",type:"PermitDetails"},{name:"spender",type:"address"},
      {name:"sigDeadline",type:"uint256"}]
  },
  primaryType:"PermitSingle",
  domain:{name:"Permit2",chainId:8453,verifyingContract:PERMIT2},
  message:{
    details:{token:BASE_USDC,amount:MAX160.toString(),expiration:"1893456000",nonce:"4"},
    spender:"0x2222222222222222222222222222222222222222",
    sigDeadline:"1799999999"
  }
},null,2);
const sample3=JSON.stringify({
  types:{
    EIP712Domain:[
      {name:"name",type:"string"},{name:"version",type:"string"},
      {name:"chainId",type:"uint256"},{name:"verifyingContract",type:"address"}],
    TransferWithAuthorization:[
      {name:"from",type:"address"},{name:"to",type:"address"},
      {name:"value",type:"uint256"},{name:"validAfter",type:"uint256"},
      {name:"validBefore",type:"uint256"},{name:"nonce",type:"bytes32"}]
  },
  primaryType:"TransferWithAuthorization",
  domain:{name:"USD Coin",version:"2",chainId:8453,verifyingContract:BASE_USDC},
  message:{
    from:"0x1111111111111111111111111111111111111111",
    to:"0x3333333333333333333333333333333333333333",
    value:"1000000",validAfter:"0",validBefore:"1893456000",
    nonce:"0x"+"7".repeat(64)
  }
},null,2);
const samples={
  "sample-permit":SAMPLE_PERMIT,
  "sample-permit2":sample2,
  "sample-eip3009":sample3,
  "sample-calldata":SAMPLE_APPROVE
};
let report=null;
function setStatus(text,kind=""){
  status.textContent=text;status.dataset.kind=kind;
}
function clearResult(){
  report=null;
  $("kind").textContent="No input yet";
  $("result-heading").textContent="Your preview appears here.";
  $("result-blurb").textContent="Paste unsigned typed data or select a fictional example. No risk score or wallet connection.";
  $("finding-count").textContent="—";
  $("known-scope").textContent="—";
  $("result-details").replaceChildren();
  const list=$("finding-list");list.replaceChildren();
  const li=document.createElement("li");
  li.textContent="Compare chain, contract, spender, token and amount with independent official documentation.";
  list.append(li);
  $("download").disabled=true;
}
function addDetail(name,value){
  if(value===null||value===undefined||value==="")return;
  const el=document.createElement("div");el.className="detail";
  const label=document.createElement("span");label.textContent=String(name);
  const item=document.createElement("code");item.textContent=String(value);
  el.append(label,item);
  $("result-details").append(el);
}
function render(obj){
  report=obj;
  $("result-details").replaceChildren();
  const observed=obj.observed||{};
  $("kind").textContent=obj.inputKind==="EIP712_UNSIGNED"?"EIP-712 typed message":"ABI calldata";
  $("result-heading").textContent=
    observed.primaryType || observed.action || "Unknown structured request";
  $("result-blurb").textContent=obj.inputKind==="EIP712_UNSIGNED"
    ?"Read this signing request's declared grant scope. Contract behavior and true wallet state are NOT verified."
    :"This is a static known-selector explanation only. It is NOT a transaction simulation.";
  const attention=obj.findings.filter(f=>f.level==="attention").length;
  $("finding-count").textContent=String(attention);
  $("known-scope").textContent=observed.recognized===false?"No":obj.verdict?"Partial":"Unknown";
  addDetail("Signing type",observed.primaryType||observed.action);
  addDetail("Chain ID",observed.chainId);
  addDetail("Signing domain",observed.domainName);
  addDetail("Domain version",observed.domainVersion);
  addDetail("Verifier/token",observed.verifyingContract||observed.tokenContract);
  addDetail("Signer/owner",observed.owner);
  addDetail("Spender",observed.spender);
  addDetail("Recipient",observed.recipient);
  if(Array.isArray(observed.amounts)){
    observed.amounts.slice(0,20).forEach((a,index)=>{
      addDetail("Amount "+(index+1),a.display+" · "+a.atomic+" atomic units");
      if(a.token)addDetail("Token "+(index+1),a.token);
    });
  }else {
    addDetail("Amount",observed.amountDisplay);
    addDetail("Raw atomic units",observed.amountAtomic);
  }
  if(Array.isArray(observed.deadlines)){
    observed.deadlines.slice(0,25).forEach(d=>{
      addDetail(d.name,d.epoch+" Unix sec · "+d.daysFromNow+" days from now");
    });
  }
  const list=$("finding-list");list.replaceChildren();
  if(obj.findings.length===0){
    const li=document.createElement("li");li.className="info";
    li.textContent="No selected heuristic warnings, but this is NOT proof of safety. Check official contracts and full wallet context.";
    list.append(li);
  }else {
    for(const f of obj.findings.slice(0,60)){
      const li=document.createElement("li");
      if(f.level==="info")li.className="info";
      const headline=document.createElement("b");
      headline.textContent=f.code;
      const explanation=document.createElement("span");
      explanation.textContent=f.reason;
      li.append(headline,explanation);
      list.append(li);
    }
  }
  $("download").disabled=false;
  setStatus("LOCAL-ONLY: "+attention+" attention signals; no wallet, upload, signing, network request, or payment. Never treat this as safety certification.",attention?"warning":"success");
}
const selectSample=(id)=>{
  input.value=samples[id]||"";
  for(const [key] of Object.entries(sampleNames)){
    $(key).classList.toggle("active",key===id);
  }
  clearResult();
  setStatus("Loaded a FICTIONAL unsigned sample. Click Inspect locally. No external requests.");
};
for(const key of Object.keys(sampleNames)){
  $(key).addEventListener("click",()=>selectSample(key));
}
$("inspect").addEventListener("click",()=>{
  try {
    const chain=$("expected-chain").value;
    const result=inspect(input.value,{
      expectedChainId:chain||null,
      expectedSpender:$("expected-spender").value.trim(),
      expectedContract:$("expected-contract").value.trim()
    });
    render(result);
  }catch(e){
    clearResult();
    setStatus("Input could not be inspected: "+String(e?.message||e).slice(0,260)+". Do not interpret an error as permission to sign.","warning");
  }
});
$("clear").addEventListener("click",()=>{
  input.value="";$("expected-spender").value="";$("expected-contract").value="";
  clearResult();setStatus("Cleared local input. No data was uploaded.");
});
input.addEventListener("input",()=>{
  if(report){clearResult();setStatus("Input changed. Analyze again; previous receipt no longer describes the editor.");}
});
$("download").addEventListener("click",()=>{
  if(!report)return;
  // Only derived scope fields and warning codes, not the raw pasted JSON.
  const safe={
    ...report,
    note:"This local interpretation is not a safe-to-sign verdict or authenticating signature proof."
  };
  const blob=new Blob([JSON.stringify(safe,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url;a.download="signscope-UNSIGNED-local-review.json";a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1000);
});
$("copy-payee").addEventListener("click",async()=>{
  const payee=$("payee").textContent.trim();
  try{
    if(!navigator.clipboard?.writeText)throw new Error("Clipboard API unavailable");
    await navigator.clipboard.writeText(payee);
    $("copy-payee").textContent="Copied public Base USDC recipient ✓";
  }catch{
    $("copy-payee").textContent="Copy manually from address above";
  }
});
$("feedback-email").addEventListener("click",()=>{
  const pain=$("pain").value;
  const willingness=$("willingness").value;
  const what=$("suggestion").value.slice(0,500).replace(/[\x00-\x1f]/g," ");
  const subject="SignScope real user feedback — "+pain;
  const body="Context: "+pain+"\nWould pay: "+willingness+
   "\nSuggestion (no secrets): "+what+
   "\n\nPlease never send signatures, wallet keys, sensitive wallet histories, or private customer data.";
  $("feedback-email").href="mailto:onecursor1@gmail.com?subject="+
    encodeURIComponent(subject)+"&body="+encodeURIComponent(body);
});
selectSample("sample-permit");
setStatus("Loaded a fictional Permit example. Inspect locally — no wallet or external server.");

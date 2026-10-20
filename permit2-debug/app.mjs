import {
 analyzePlan,SAMPLE_BROKEN_ALLOWANCE,SAMPLE_SIGNATURE_TRANSFER
} from "./analyze.mjs";

const $=id=>document.getElementById(id);
const input=$("plan");
const status=$("status");
const buttonIds=["sample-broken","sample-signature"];
let current=null;
let lastResult=null;

function showStatus(text,kind=""){
  status.textContent=text;
  status.dataset.kind=kind;
}
function clear(){
  lastResult=null;
  $("kind").textContent="No input inspected";
  $("summary").textContent="Run a fictional broken case first.";
  $("blurb").textContent="This local preview identifies mismatched fields. It cannot execute the actual contract.";
  $("warning-count").textContent="—";
  $("money-cost").textContent="0";
  $("details").replaceChildren();
  $("findings").replaceChildren();
  const li=document.createElement("li");
  li.textContent="Run the analysis to view declared scope conflicts. Unknown is not safe.";
  $("findings").append(li);
  $("download").disabled=true;
}
function loadSample(kind){
  current=kind;
  input.value=kind==="sample-signature"?SAMPLE_SIGNATURE_TRANSFER:SAMPLE_BROKEN_ALLOWANCE;
  for(const id of buttonIds)$(id).classList.toggle("active",id===kind);
  clear();
  showStatus("Loaded a fictional "+(kind==="sample-signature"?"SignatureTransfer":"broken AllowanceTransfer")+" example. No wallet or HTTP request.");
}
function detail(name,value){
  if(value===null||value===undefined||value==="")return;
  const row=document.createElement("div");row.className="detail";
  const label=document.createElement("span");label.textContent=name;
  const content=document.createElement("code");
  content.textContent=typeof value==="object"?JSON.stringify(value):String(value);
  row.append(label,content);
  $("details").append(row);
}
function render(report){
  lastResult=report;
  $("kind").textContent=report.observed.shape;
  $("summary").textContent=report.attentionCount+" field / flow mismatch"+(report.attentionCount===1?"":"es")+" to review";
  $("blurb").textContent="This diagnosis interprets your supplied, untrusted JSON only. It does not verify a signature, actual caller, contract deployment, token allowance, gas, or transaction result.";
  $("warning-count").textContent=String(report.attentionCount);
  $("money-cost").textContent="0";
  $("details").replaceChildren();
  for(const [label,key] of [
    ["Flow","flow"],["Network","chainId"],["Expected network","expectedChainId"],
    ["Function","functionName"],["Permit2 target","calledContract"],
    ["Claimed signing domain","claimedPermit2"],
    ["Token owner","owner"],["Call's msg.sender","caller"],
    ["Intended spender","intendedSpender"],["Signed/later spender","spender"],
    ["Later transfer caller","transferCaller"],["Recipient","recipient"],
    ["Token","token"],["Signed amount (atomic)","permittedAtomic"],
    ["Requested amount (atomic)","requestedAtomic"],
    ["Signature deadline","signatureDeadline"],["Allowance expires","allowanceExpiration"],
    ["Nonce","nonce"],["User's ERC-20 approval claim","underlyingApprovalClaim"],
    ["Amount interpretation","amountInterpretation"]
  ])detail(label,report.observed[key]);
  const list=$("findings");list.replaceChildren();
  if(!report.findings.length){
    const li=document.createElement("li");li.className="info";
    li.textContent="No selected shape warnings; this NEVER proves a call will succeed or is safe.";
    list.append(li);
  }else{
    for(const f of report.findings){
      const li=document.createElement("li");
      if(f.severity==="info")li.classList.add("info");
      const label=document.createElement("b");label.textContent=f.code;
      const explanation=document.createElement("span");explanation.textContent=f.message;
      li.append(label,explanation);list.append(li);
    }
  }
  $("download").disabled=false;
  showStatus("LOCAL-ONLY: "+report.attentionCount+" review signals from unsigned USER assertions. Uploaded=false, wallet=false, transfer=false, paid=0. NOT proof of safe execution.",report.attentionCount?"warning":"success");
}
for(const id of buttonIds)$(id).addEventListener("click",()=>loadSample(id));
$("inspect").addEventListener("click",()=>{
  try{
    const selected=$("expected-chain").value;
    const report=analyzePlan(input.value,{
      expectedChainId:selected===""?null:selected
    });
    render(report);
  }catch(e){
    clear();
    showStatus("Unable to inspect: "+String(e?.message||e).slice(0,250)+". Do not assume the unsigned operation is valid.","warning");
  }
});
$("reset").addEventListener("click",()=>{
  input.value="";
  current=null;
  for(const id of buttonIds)$(id).classList.remove("active");
  clear();
  showStatus("Cleared input locally. No uploaded data or wallet action.");
});
input.addEventListener("input",()=>{
  if(lastResult){
    clear();
    showStatus("Input changed. Inspect again before using this explanation.","warning");
  }
});
$("download").addEventListener("click",()=>{
  if(!lastResult)return;
  const result={
    ...lastResult,
    note:"LOCAL-ONLY. Does not prove signature authenticity, real allowance, correct ABI execution, onchain token approval, or a safe transaction."
  };
  const blob=new Blob([JSON.stringify(result,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");
  a.href=url;
  a.download="signscope-PERMIT2-UNSIGNED-preflight-review.json";
  a.click();
  setTimeout(()=>URL.revokeObjectURL(url),1200);
});
loadSample("sample-broken");
showStatus("Loaded fictional broken Permit2 allowance example. Click Inspect; no network, wallet or payment.");

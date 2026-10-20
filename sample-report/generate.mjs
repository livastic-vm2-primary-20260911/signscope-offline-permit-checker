/*
 * Reproducible, deterministic FICTIONAL SignScope output showcase.
 * NEVER run a real transaction, wallet signing, HTTP call, or payment.
 * This is an illustration, NOT any customer deliverable or audited receipt.
 */
import {writeFileSync} from "node:fs";
import {inspect,BASE_USDC,PERMIT2,MAX160} from "../src/analysis.mjs";

export const AS_OF="2026-10-20T12:30:00.000Z";
export const AS_OF_SECONDS=Math.floor(Date.parse(AS_OF)/1000);
export const FICTIONAL_UNSIGNED={
  types:{
    EIP712Domain:[
      {name:"name",type:"string"},{name:"chainId",type:"uint256"},
      {name:"verifyingContract",type:"address"}
    ],
    PermitDetails:[
      {name:"token",type:"address"},{name:"amount",type:"uint160"},
      {name:"expiration",type:"uint48"},{name:"nonce",type:"uint48"}
    ],
    PermitSingle:[
      {name:"details",type:"PermitDetails"},{name:"spender",type:"address"},
      {name:"sigDeadline",type:"uint256"}
    ]
  },
  primaryType:"PermitSingle",
  domain:{name:"Permit2",chainId:8453,verifyingContract:PERMIT2},
  message:{
    details:{token:BASE_USDC,amount:MAX160.toString(),expiration:"1893456000",nonce:"4"},
    spender:"0x2222222222222222222222222222222222222222",
    sigDeadline:"1799999999"
  }
};
export function result(){
  return inspect(JSON.stringify(FICTIONAL_UNSIGNED),{
    expectedChainId:"8453",
    expectedSpender:"0x2222222222222222222222222222222222222222",
    expectedContract:PERMIT2,
    nowSeconds:AS_OF_SECONDS
  });
}
export function bundle(){
  return {
    exampleOnly:true,
    sampleType:"FICTIONAL_UNSIGNED_PERMIT2_ALLOWANCE",
    generatedAtUtc:AS_OF,
    actualCustomer:false, customerTransaction:false, commissionedWork:false,
    priceChargedBaseCircleUSDC:"0",
    underlyingSignerOrWalletAuthenticated:false,
    chainQueried:false, contractBytecodeInspected:false,
    reviewer:'AI-assisted static local engine only; neither human audit nor certified security report',
    freeService:"https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/",
    optionalFixedOffer:"https://clawlancer.ai/marketplace/26905668-717a-41d7-9cc1-5d7ea1c331b1",
    input:FICTIONAL_UNSIGNED,
    output:result()
  };
}
if (process.argv[1]?.endsWith("/generate.mjs")){
  const value=bundle();
  if (!value.output.observed.amounts[0].maximum)throw Error("Sample must flag max allowance");
  if (value.output.walletConnected || value.output.signed || value.output.uploaded)throw Error("Not a local preview");
  writeFileSync(new URL("./sample-fictional-output.json",import.meta.url),JSON.stringify(value,null,2)+"\n");
  console.log("FICTIONAL_STATIC_SAMPLE_WRITTEN",value.output.findings.map(x=>x.code).join(","));
}

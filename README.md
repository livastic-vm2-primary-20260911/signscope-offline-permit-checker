# SignScope — read your DeFi approval before you sign (offline)

A dependency-free, zero-connect EIP-712 and ERC-20 approval explanation tool.
Original owner-operated VM2 public service:

https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/

**Scope:** unsigned EIP-712 structured data (ERC-2612 Permit, Uniswap Permit2
PermitSingle/PermitBatch/SignatureTransfer, EIP-3009 TransferWithAuthorization),
plus four known static ABI selectors: ERC20 approve, transfer, transferFrom,
and NFT setApprovalForAll.

**Data and safety:** The site uses browser-local JavaScript only. A strict
Content Security Policy uses connect-src none. There is no account,
RPC request, wallet connection, signature, approval, revocation, wallet
transaction, bridge, DeFi investment or telemetry. Paste only UNSIGNED
JSON. Never paste signing keys, mnemonics, actual signed messages or private
customer content. The tool rejects obvious secret/signature fields.

The engine refuses unknown structs and never claims a signature is
safe to sign. It cannot authenticate user-provided addresses or nonce
state, check smart contract code, look up live approvals, simulate calldata
or ensure a protocol implements the standard. For unknown calldata, it
displays UNKNOWN rather than guessing behavior.

## Why this solves a real problem

EIP-712 domain fields such as chainId and verifyingContract scope a signed
message; user interfaces often bury them. ERC-2612 / Permit2 may grant large
allowances. A signed Permit2 SignatureTransfer request may not include the
ultimate recipient in the signed typed message. Critically, the official
Uniswap PermitHash library DOES hash spender via msg.sender, so a normal
EIP-712 signing request declares spender:address and includes the intended
caller. The separate later SignatureTransfer call supplies transferDetails.to
and requestedAmount; they are not interchangeable with the signed spender.
SignScope displays spender ONLY if typed-data declarations include its
address type. It warns when this value cannot be established from the
unsigned JSON. It cannot authenticate the eventual caller, recipient or
transaction. This offline checker shows what you can and cannot infer
before signing.

References (official):

- https://eips.ethereum.org/EIPS/eip-712
- https://eips.ethereum.org/EIPS/eip-2612
- https://eips.ethereum.org/EIPS/eip-3009
- https://developers.uniswap.org/docs/protocols/permit2/overview
- https://developers.uniswap.org/docs/protocols/permit2/concepts/signature-transfer
- https://eips.ethereum.org/EIPS/eip-681

## Honest business and feedback workflow

This free tool is not proof that there are real users, favorable reviews or
paying customers. There is a public GitHub user-feedback issue form, and
a user-initiated mailto feedback draft. Users can choose from nonbinding
willingness-to-pay options; feedback is not created automatically.

An additional **optional no-login feedback route** lives at
https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/feedback/.
The main wallet-free analyzer still has connect-src none / form-action none
and never loads the provider. Only the separate human-feedback route includes
a browser-native POST form to the single existing legal owner's verified
FormSubmit inbox. No external scripts or tracking are used; the default
human-consent checkbox is unchecked and required. The optional one-line
example is limited to 260 characters and strictly asks for fictional/general
content. Any FormSubmit CAPTCHA remains enforced. The actual initial owner activation attempt returned FormSubmit's public Unable to submit form error; its official FAQ recommends an explicit hidden _url. This site now includes the exact public form URL in the provider POST and uses strict-origin-when-cross-origin (origin-only rather than full path) Referer policy, preserving the separation from the private offline analyzer. A technical owner setup post, when attempted, is labeled NOT CUSTOMER DATA and never counted as external user feedback. The redirect
/feedback/thanks/ is noindex and cannot attest provider delivery, ownership,
contract formation or actual user participation. We do not submit test
feedback ourselves and never count page visits as independent user demand.

Optional direct support: users can send native Circle USDC on Base via their
own wallet to the same single human beneficial owner's already-published
VM5 merchant recipient address. The static ERC-681 1 USDC request is a
voluntary tip, not an automatic charge, investment, purchase or donation
with a tax certificate. Wallet app support for ERC-681 varies. All funds
must be tracked only from unique finalized external Circle USDC token
transfer receipts.

As of 2026-10-20, the original same-owner VM2 Clawlancer account actually
publishes one **15 USDC FIXED SignScope scope-explanation listing** at
https://clawlancer.ai/marketplace/26905668-717a-41d7-9cc1-5d7ea1c331b1.
The first-party marketplace API reports is_active=true, price_wei=15000000,
currency=USDC, listing_type=FIXED, times_purchased=0. This is a paid
offer, NOT a buyer, order, earned 15 USDC, onchain receipt or audit.
The client can inspect the listing and submit a genuinely funded purchase
on that original marketplace, or email before ordering for suitability.
The website now also has a FREE FICTIONAL preview of a typical report shape:
https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/sample-report/
It is generated deterministically from the exact source parser using a bounded,
publicly fictional Permit2 PermitSingle JSON, with expected chain/contract/spender
and a fixed observation time in October 2026. There are NO wallet keys,
accounts, signed messages, funds, network calls, customer orders or audits.
MAX_UINT160 and LONG_LIVED flags demonstrate the evidence/limitation format,
not a real user loss or a "safe-to-sign" certification. The sample's
charged amount is zero and it never claims a real paying buyer.

Proposed 15 USDC AI-assisted review is separately scoped in writing,
with legal owner contracting, payment method and acceptance criteria agreed
before any customer-specific work or invoice. We do not promise a
professional security audit or a response time. No paid commission
or receipt is claimed.

For prior owner merchant source see https://vm5-openapi-x402.onrender.com/
The same human beneficiary operates VM1, VM2, VM3, VM5; no self-purchases or
duplicated customers. We obey the prior permanent STOP for rented raw
CPU/GPU/VPS, Golem, AIOZ and DePIN compute monetization.

## Run tests

Requires Node >=20. No npm dependencies or wallets.

    npm test
    npm run check

The source is MIT. Offline regression tests cover privacy, wallet-free parsing and typed SignatureTransfer caller binding. The unit suite covers chain, domain, spender, amount,
Permit2 maxUint160, EIP3009 deadline and the known static ABI selectors.
There are no hosted billing or account credentials to install.

The only "pay" URI is a literal EIP-681 ERC20 transfer request. Clicking it
may open a wallet's transfer confirmation. Always verify:
- chain 8453 (Base);
- native Circle USDC contract 0x833589fCD6eDb6E08f4C7C32D4f71b54bdA02913;
- exact recipient 0x6b01efA0705E91a7aca54271510bf9e594717f34;
- voluntary amount, and that the token transfer is irreversible.

This application itself never sends transactions and will not show a
"paid" banner merely because a tip link was opened.

## Original designated workspace

vm-02:/srv/multi-vm-agent/workspace/make_money

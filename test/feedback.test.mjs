import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

const file = p => readFileSync(new URL(p, import.meta.url), "utf8");
const main = file("../index.html");
const feedback = file("../feedback/index.html");
const thanks = file("../feedback/thanks/index.html");
const css = file("../feedback/feedback.css");
const sitemap = file("../sitemap.xml");
const readme = file("../README.md");
const llms = file("../llms.txt");
const url = "https://livastic-vm2-primary-20260911.github.io/signscope-offline-permit-checker/feedback/";
const nextUrl = url + "thanks/";

test("SignScope main privacy promise remains strict local-only", () => {
  const csp = main.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp?.includes("connect-src 'none'"));
  assert.ok(csp.includes("form-action 'none'"));
  assert.ok(!main.includes("https://formsubmit.co/"));
});
test("main tool plainly links to optional dedicated feedback route", () => {
  assert.ok(main.includes('href="./feedback/"'));
  assert.ok(main.includes("Send 1-minute feedback without GitHub or email app"));
});
test("no-login form has correct canonical full HTTPS URL", () => {
  assert.ok(feedback.includes('rel="canonical" href="'+url+'"'));
});
test("no-login form has no scripts, beacons, RPC or wallet connect", () => {
  assert.ok(!feedback.includes("<script"));
  assert.ok(!feedback.includes("window.ethereum"));
  assert.ok(!feedback.includes("https://rpc."));
  assert.ok(!feedback.includes("GoogleAnalytics"));
  assert.ok(!feedback.includes("eth_signTypedData"));
});
test("standalone feedback form CSP permits ONLY human form POST to explicit provider", () => {
  const csp = feedback.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp?.includes("default-src 'none'"));
  assert.ok(csp.includes("connect-src 'none'"));
  assert.ok(csp.includes("script-src 'none'"));
  assert.ok(csp.includes("style-src 'self'"));
  assert.ok(csp.includes("form-action https://formsubmit.co"));
  assert.ok(!csp.includes("unsafe-inline"));
});
test("browser-native form POST is explicit, with existing one-owner email", () => {
  assert.ok(feedback.includes('id="signscope-real-user-feedback"'));
  assert.ok(feedback.includes('action="https://formsubmit.co/onecursor1@gmail.com"'));
  assert.ok(feedback.includes('method="POST"'));
});
test("feedback contact email is not being exposed as mandatory user info", () => {
  assert.ok(!feedback.includes('type="email"'));
  assert.ok(!feedback.includes('name="user_email"'));
  assert.ok(!feedback.includes('name="wallet"'));
});
test("subject clearly separates nonpurchase SignScope from other owner's products", () => {
  assert.ok(feedback.includes('name="_subject" value="SignScope — real voluntary pre-sign user feedback; no purchase or order"'));
  assert.ok(feedback.includes('name="product" value="SignScope - local EIP712/Permit2 inspector"'));
});
test("provider return route cannot be confused with payment receipt", () => {
  assert.ok(feedback.includes('name="_next" value="'+nextUrl+'"'));
  assert.ok(thanks.includes("does not independently verify"));
  assert.ok(thanks.includes("not a payment receipt"));
});
test("thanks page is deliberately excluded from indexing", () => {
  assert.ok(thanks.includes('content="noindex,nofollow"'));
  assert.ok(!sitemap.includes("/feedback/thanks/"));
});
test("thanks page itself cannot submit forms or scripts", () => {
  assert.ok(!thanks.includes("<form"));
  assert.ok(!thanks.includes("<script"));
  assert.ok(!thanks.includes("style="));
  assert.ok(thanks.includes("form-action 'none'"));
});
test("select problem is required with no preselected response", () => {
  assert.ok(feedback.includes('id="problem" name="approval_scope_problem" required'));
  assert.ok(feedback.includes('<option value="" disabled selected>Choose a real problem'));
});
test("frequency is required and unbiased to paid use", () => {
  assert.ok(feedback.includes('id="frequency" name="frequency" required'));
  assert.ok(feedback.includes('option value="not_yet_only_researching"'));
  assert.ok(feedback.includes('option value="wallet_developer_daily"'));
});
test("willingness to pay admits honest zero and no-use responses", () => {
  assert.ok(feedback.includes('name="nonbinding_willingness_to_pay_usdc" required'));
  assert.ok(feedback.includes('value="0_usdc_free_is_enough"'));
  assert.ok(feedback.includes('value="would_not_pay_or_use"'));
});
test("willingness to pay is not false sales data", () => {
  assert.ok(feedback.includes("nonbinding"));
  assert.ok(feedback.includes("This is not a checkout"));
});
test("user can choose bounded 1, 5, 15 and 50 plus willingness options", () => {
  for (const s of ["1 USDC","5 USDC","15 USDC","50+ USDC"]) {
    assert.ok(feedback.includes(s),s);
  }
});
test("no user identity or financial history is solicited", () => {
  for (const term of ["wallet addresses","real balances","signed messages","confidential customer"]) {
    assert.ok(feedback.includes(term),term);
  }
});
test("optional comment limited to 260 characters and no paste prompts", () => {
  assert.ok(feedback.includes('name="general_nonsecret_feature_example"'));
  assert.ok(feedback.includes('maxlength="260"'));
  assert.ok(feedback.includes("Fictional or general example only"));
});
test("human-consent checkbox mandatory and NOT checked by default", () => {
  const m = feedback.match(/<input id="external-consent"[^>]*>/)?.[0];
  assert.ok(m);
  assert.ok(m.includes('type="checkbox"'));
  assert.ok(m.includes("required"));
  assert.ok(!m.includes("checked"));
});
test("consent plainly names independent FormSubmit provider and metadata", () => {
  assert.ok(feedback.includes("independent FormSubmit provider"));
  assert.ok(feedback.includes("IP and submission metadata"));
});
test("browser-native CAPTCHA and anti-spam gate remain enabled", () => {
  assert.ok(!feedback.includes('name="_captcha" value="false"'));
  assert.ok(!feedback.includes("captcha=false"));
  assert.ok(feedback.includes("CAPTCHA"));
});
test("honeypot is a spam safeguard rather than a secret collector", () => {
  assert.ok(feedback.includes('name="_honey"'));
  assert.ok(feedback.includes('tabindex="-1"'));
  assert.ok(css.includes(".honey{"));
});
test("no automatic click or submit in any public form asset", () => {
  assert.ok(!feedback.includes('onsubmit='));
  assert.ok(!feedback.includes('autofocus'));
  assert.ok(!feedback.includes('new XMLHttpRequest'));
  assert.ok(feedback.includes('type="submit"'));
});
test("support alternatives preserved without a form requirement", () => {
  assert.ok(feedback.includes("issues/new?template=feedback.yml"));
  assert.ok(feedback.includes("mailto:onecursor1@gmail.com?subject=SignScope"));
  assert.ok(feedback.includes('href="../#analyzer"'));
});
test("standalone feedback UI is mobile responsive", () => {
  assert.ok(css.includes("@media(max-width:800px)"));
  assert.ok(css.includes("@media(max-width:530px)"));
});
test("footer and link disclosure mention one beneficial operator and AI assistance", () => {
  assert.ok(feedback.includes("one real beneficial owner"));
  assert.ok(feedback.includes("AI-assisted"));
});
test("sitemap explicitly contains the free app and feedback, never a fake thanks conversion", () => {
  assert.ok(sitemap.includes("signscope-offline-permit-checker/</loc>"));
  assert.ok(sitemap.includes("signscope-offline-permit-checker/feedback/"));
  assert.ok(!sitemap.includes("/feedback/thanks/"));
});
test("README records separate routing and no real user feedback claims", () => {
  assert.ok(readme.includes(url));
  assert.ok(readme.includes("We do not submit test"));
  assert.ok(readme.includes("cannot attest provider delivery"));
});
test("llms discoverability describes privacy boundary and no fake paying customers", () => {
  assert.ok(llms.includes(url));
  assert.ok(llms.includes("explicit checkbox consent"));
  assert.ok(llms.includes("No actual independent humans"));
});

test("FormSubmit first-party POST contains exact actual public form URL (_url) after observed activation error",()=>{
  assert.ok(feedback.includes('name="_url" value="'+url+'"'));
  assert.ok(feedback.includes('method="POST"'));
  assert.ok(feedback.includes('action="https://formsubmit.co/onecursor1@gmail.com"'));
});
test("cross-origin provider gets only public origin via Referer plus posted _url",()=>{
  assert.ok(feedback.includes('name="referrer" content="strict-origin-when-cross-origin"'));
  assert.ok(!feedback.includes('name="referrer" content="no-referrer"'));
  assert.ok(feedback.includes('including the public site origin and this form URL'));
});
test("main free wallet analyzer retains strict CSP even when external consent form fixes _url",()=>{
  const csp=main.match(/http-equiv="Content-Security-Policy" content="([^"]+)"/)?.[1];
  assert.ok(csp?.includes("connect-src 'none'"));
  assert.ok(csp.includes("form-action 'none'"));
  assert.ok(!main.includes('name="_url"'));
});

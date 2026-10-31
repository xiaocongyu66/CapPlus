// Smoke test for the Rust server (sha256-pow path).
const CAP = process.env.CAP_URL || "http://localhost:3001";
const SITE = "rusttest";
const SECRET = "rust-smoke-secret-32-bytes-padding!";
const UA = "Mozilla/5.0 (X11; Linux x86_64) RustSmoke/1.0";
const { prng } = await import("/root/cpa/cap/core/src/prng.js");
const { createHash } = await import("node:crypto");

const j = async (r) => [r.status, await r.json().catch(() => ({}))];

// 1. challenge
const [cs, ch] = await j(await fetch(`${CAP}/${SITE}/challenge`, { method: "POST" }));
console.log("challenge:", cs, JSON.stringify(ch.challenge), "nonce?", !!ch.nonce);

// 2. solve
const sols = [];
for (let i = 1; i <= ch.challenge.c; i++) {
  const salt = prng(`${ch.token}${i}`, ch.challenge.s);
  const target = prng(`${ch.token}${i}d`, ch.challenge.d);
  let n = 0;
  while (!createHash("sha256").update(salt + n).digest("hex").startsWith(target)) n++;
  sols.push(n);
}
console.log("solved", sols.length, "challenges");

// 3. redeem from the Cap origin (same-origin, like the iframe)
const redeemBody = JSON.stringify({ token: ch.token, solutions: sols });
const [rs, rv] = await j(await fetch(`${CAP}/${SITE}/redeem`, {
  method: "POST",
  headers: { "content-type": "application/json", origin: CAP, "user-agent": UA },
  body: redeemBody,
}));
console.log("redeem:", rs, rv.success, rv.token ? rv.token.slice(0, 24) + "…" : rv);
const tok = rv.token;

// 3b. negative: no Origin header → rejected
const [rs2, rv2] = await j(await fetch(`${CAP}/${SITE}/redeem`, {
  method: "POST", headers: { "content-type": "application/json", "user-agent": UA }, body: redeemBody,
}));
console.log("redeem without Origin:", rs2, rv2.error);

// 4. siteverify (Turnstile contract, same UA)
const verify = (body, hdrs = {}) => fetch(`${CAP}/${SITE}/siteverify`, {
  method: "POST",
  headers: { "content-type": "application/json", "x-cap-client-ua": UA, ...hdrs },
  body: JSON.stringify({ secret: SECRET, ...body }),
}).then(async (r) => [r.status, await r.json()]);

console.log("verify first  →", JSON.stringify(await verify({ response: tok })));
console.log("verify replay →", JSON.stringify(await verify({ response: tok })));
console.log("verify wrongUA→", JSON.stringify(await verify({ response: tok }, { "x-cap-client-ua": "curl/8" })));
console.log("verify badsecret→", JSON.stringify(await verify({ response: tok, secret: "nope" })));

// Run: node worker.test.mjs
//
// The redirect these cases cover is the only thing standing between the move to
// antharmaya.com/tools/stallwatch and every published `curl | sh` installer
// breaking. `wrangler dev` cannot exercise it — it serves assets before the
// script runs and always reports localhost in request.url regardless of Host —
// so the handler is tested directly here instead of being taken on faith.
import assert from "node:assert/strict";
import worker from "./worker.js";

const env = {
  ASSETS: {
    fetch: async (req) =>
      new Response("ASSET:" + new URL(req.url).pathname, { status: 200 }),
  },
};

const call = (host, url) =>
  worker.fetch(new Request(url, { headers: { host } }), env);

const OLD = "stallwatch.antharmaya.com";
const NEW = "https://antharmaya.com/tools/stallwatch";

let failures = 0;
async function check(name, fn) {
  try {
    await fn();
    console.log("  ok   " + name);
  } catch (e) {
    failures++;
    console.log("  FAIL " + name + "\n       " + e.message);
  }
}

await check("the published installer path survives the move", async () => {
  const res = await call(OLD, `https://${OLD}/install.sh`);
  assert.equal(res.status, 301);
  assert.equal(res.headers.get("location"), `${NEW}/install.sh`);
});

await check("the path is preserved, not dropped to the homepage", async () => {
  // A redirect that dropped the path would still return 200 to curl and pipe
  // an HTML page into sh.
  const res = await call(OLD, `https://${OLD}/og.png`);
  assert.equal(res.headers.get("location"), `${NEW}/og.png`);
});

await check("the query string is preserved", async () => {
  const res = await call(OLD, `https://${OLD}/install.sh?v=2`);
  assert.equal(res.headers.get("location"), `${NEW}/install.sh?v=2`);
});

await check("the bare old host reaches the new index", async () => {
  const res = await call(OLD, `https://${OLD}/`);
  assert.equal(res.headers.get("location"), NEW);
});

await check("the canonical host serves assets and does not loop", async () => {
  for (const p of ["/tools/stallwatch/", "/tools/stallwatch/install.sh"]) {
    const res = await call("antharmaya.com", `https://antharmaya.com${p}`);
    assert.equal(res.status, 200, `${p} should serve, not redirect`);
  }
});

console.log(failures ? `\n${failures} failing` : "\nall passing");
process.exit(failures ? 1 : 0);

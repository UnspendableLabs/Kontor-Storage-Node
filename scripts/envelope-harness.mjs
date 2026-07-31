#!/usr/bin/env node
//
// Runs the browser half of the sealed admin channel against a live node.
//
// # Why this exists
//
// `server::admin::envelope` is tested from both ends in Rust: its own tests
// play the client with `p256` and `hkdf`, and `server::admin::ui` pins the
// WebCrypto names the page uses. Neither runs the page's code. A `deriveBits`
// call that asked for 256 bits where the node expands to 512, an `additionalData`
// left off one `encrypt`, a `slice` on the wrong half of the output — every one
// of those passes both suites and leaves an operator with a seed phrase the node
// cannot open.
//
// So this harness takes the three functions out of `index.html` **verbatim** —
// no copy to drift — and drives them against a real binary under Node's
// WebCrypto, which is the same implementation a browser ships. What it proves:
//
//   * the phrase is ciphertext on the wire, and the node opens it;
//   * the seal key comes back sealed, and only that browser opens it;
//   * a sealed passphrase adds a slot;
//   * neither secret appears anywhere in the bodies that crossed.
//
// What it does not prove is that a browser's *page* works — no DOM, no CSP, no
// extension. One manual pass over a secure origin is still worth doing.
//
// # Running it
//
//     cargo build && node scripts/envelope-harness.mjs
//
// It builds nothing, starts the binary itself against a temporary directory and
// an in-memory database, and cleans both up. No Portal is needed: the server
// comes up before any Portal contact, which is the property that makes zero
// configuration work in the first place.

import { spawn } from "node:child_process";
import { mkdtemp, readFile, rm } from "node:fs/promises";
import { createServer } from "node:net";
import { tmpdir } from "node:os";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");
const PAGE = join(ROOT, "src", "server", "admin", "index.html");
const BINARY = join(ROOT, "target", "debug", "Kontor-Storage-Node");

/// The canonical BIP-39 phrase. Nothing is registered, so it goes nowhere.
const PHRASE =
  "abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about";
const ADMIN_PASSWORD = "correct horse battery staple";
const SEAL_PASSPHRASE = "a seal passphrase long enough to be accepted";

/* ---------------- taking the page's own code ---------------- */

/// One `function name(...) {...}` from `source`, brace-matched.
///
/// Sliced rather than reimplemented: a harness holding its own copy of the
/// exchange would agree with itself forever and prove nothing about the page.
function extractFunction(source, name) {
  const start = source.indexOf(`function ${name}(`);
  if (start === -1) throw new Error(`${name} is not in index.html any more`);

  let depth = 0;
  for (let i = source.indexOf("{", start); i < source.length; i += 1) {
    if (source[i] === "{") depth += 1;
    else if (source[i] === "}") {
      depth -= 1;
      if (depth === 0) return source.slice(start, i + 1);
    }
  }
  throw new Error(`${name} in index.html has unbalanced braces`);
}

/// The page's envelope code, as functions this process can call.
///
/// `api` is the one thing supplied from outside: in the page it carries the
/// session token and parses errors, and none of that is what is under test.
async function loadPageCrypto(api) {
  const page = await readFile(PAGE, "utf8");

  const info = page.match(/var ENVELOPE_INFO = "([^"]+)";/);
  if (!info) throw new Error("ENVELOPE_INFO is not in index.html any more");

  const source = [
    `var ENVELOPE_INFO = ${JSON.stringify(info[1])};`,
    ...["hexToBytes", "bytesToHex", "utf8", "openEnvelope", "sealRequest", "openResponse"].map(
      (name) => extractFunction(page, name),
    ),
    "return { openEnvelope, sealRequest, openResponse, ENVELOPE_INFO };",
  ].join("\n\n");

  // eslint-disable-next-line no-new-func
  return new Function("api", source)(api);
}

/* ---------------- a node to talk to ---------------- */

async function freePort() {
  return new Promise((resolve, reject) => {
    const probe = createServer();
    probe.on("error", reject);
    probe.listen(0, "127.0.0.1", () => {
      const { port } = probe.address();
      probe.close(() => resolve(port));
    });
  });
}

const sleep = (ms) => new Promise((resolve) => setTimeout(resolve, ms));

async function startNode() {
  const appDir = await mkdtemp(join(tmpdir(), "kontor-harness-"));
  const port = await freePort();
  const base = `http://127.0.0.1:${port}`;

  const child = spawn(BINARY, ["run"], {
    env: {
      ...process.env,
      // Zero configuration is the thing being exercised: no mnemonic, no admin
      // password, no seal key. Only where to put the volume and where to listen.
      KONTOR_APP_DIR: appDir,
      STORAGE_DIR: join(appDir, "files"),
      DATABASE_URL: "sqlite::memory:",
      SERVER_ADDRESS: `127.0.0.1:${port}`,
      PORTAL_API_URL: "http://127.0.0.1:1", // deliberately unreachable
      ADMIN_PASSWORD: "",
      KONTOR_SETUP_TOKEN: "",
      KONTOR_SEAL_KEY: "",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });

  let log = "";
  child.stdout.on("data", (chunk) => (log += chunk));
  child.stderr.on("data", (chunk) => (log += chunk));

  const stop = async () => {
    child.kill("SIGTERM");
    await rm(appDir, { recursive: true, force: true });
  };

  for (let i = 0; i < 200; i += 1) {
    if (child.exitCode !== null) {
      await stop();
      throw new Error(`the node exited before serving:\n${log}`);
    }
    try {
      const response = await fetch(`${base}/api/info`);
      if (response.ok) return { base, appDir, stop, log: () => log };
    } catch {
      /* not listening yet */
    }
    await sleep(50);
  }

  await stop();
  throw new Error(`the node never served /api/info:\n${log}`);
}

/* ---------------- the page's own reveal logic ---------------- */

/// `show`, sliced out of the page and driven against a stand-in element.
///
/// It earns its place here for the same reason the envelope functions do: it
/// was wrong, and neither suite could see it. Several message boxes ship the
/// `hidden` attribute, nothing else ever clears it, and a `show` that wrote
/// only `textContent` left them invisible — including the one-time
/// `KONTOR_SEAL_KEY` reveal, which the node hands back once and never again.
/// The endpoint tests above all passed while the operator saw nothing at all.
async function checkTheReveal() {
  const page = await readFile(PAGE, "utf8");

  // eslint-disable-next-line no-new-func
  const show = new Function(
    "window",
    `${extractFunction(page, "show")}\nreturn show;`,
  )({ setTimeout: () => 0, clearTimeout: () => {} });

  const box = { textContent: "", hidden: true, msgTimer: null };

  show(box, "KONTOR_SEAL_KEY=…", true);
  check(box.textContent === "KONTOR_SEAL_KEY=…", "show writes the message");
  check(box.hidden === false, "and reveals a box that ships hidden");

  show(box, "");
  check(box.hidden === true, "clearing a message hides its box again");

  // The rule the CSS has to hold up its end of, since `[hidden]` only exists in
  // the user agent stylesheet and any author `display` rule outranks it.
  check(
    page.includes("[hidden] { display: none !important; }"),
    "the stylesheet makes the hidden attribute authoritative",
  );
  check(
    !/#(login|claim|app)\b[^{]*\{[^}]*display:\s*none/.test(page),
    "and no screen is hidden by a display rule the attribute cannot override",
  );

  // Visible is not the same as legible. The reveal is written with blank lines
  // around the key, and `show` writes `textContent` — so without `pre-wrap` the
  // whole thing collapses into one run-on line with a 44-character base64 blob
  // wedged between two sentences. It is shown exactly once, is not recoverable,
  // and is copied by hand.
  check(
    /\.msg\s*\{[^}]*white-space:\s*pre-wrap/.test(page),
    "and messages keep the line breaks they were written with",
  );
  check(
    /show\(\$\("seal-key-reveal"\),[\s\S]{0,400}?\\n\\n/.test(page),
    "which is what the one-time seal key reveal relies on",
  );

  // The same failure one card over. `renderPhase` hides `#setup` the moment the
  // node leaves `uninitialized`, and provisioning does that *before* it answers
  // — so a confirmation nested inside that card is one the operator never reads,
  // along with the Taproot address it names, which at that moment is the entire
  // remaining task. Both boxes have to sit outside it.
  const card = page.indexOf('id="setup" hidden');
  const success = page.indexOf('id="setup-success"');
  const envelope = page.indexOf('id="setup-envelope"');
  check(
    card !== -1 && /\$\("setup"\)\.hidden = phase !== "uninitialized"/.test(page),
    "renderPhase hides the setup card as soon as the node has a key",
  );
  check(
    success !== -1 && envelope !== -1 && success < card && envelope < card,
    "so the confirmation and the fingerprint live outside it",
  );
}

/* ---------------- the checks ---------------- */

function check(condition, what) {
  if (!condition) throw new Error(`FAILED: ${what}`);
  console.log(`  ok  ${what}`);
}

/// Every request body this harness sent, so the secrets can be looked for in
/// exactly the bytes an edge would have been free to log.
const sentBodies = [];

async function main() {
  const node = await startNode();
  let failure = null;

  try {
    let token = null;
    const api = async (path, options = {}) => {
      const headers = { Accept: "application/json" };
      if (token) headers.Authorization = `Bearer ${token}`;
      if (options.body !== undefined) headers["Content-Type"] = "application/json";

      const body = options.body === undefined ? undefined : JSON.stringify(options.body);
      if (body !== undefined) sentBodies.push(body);

      const response = await fetch(`${node.base}${path}`, {
        method: options.method || "GET",
        headers,
        body,
      });
      const text = await response.text();
      const payload = text ? JSON.parse(text) : null;
      if (!response.ok) {
        throw new Error(`${options.method || "GET"} ${path} → ${response.status} ${text}`);
      }
      return payload;
    };

    const page = await loadPageCrypto(api);
    console.log("Driving index.html's own openEnvelope/sealRequest/openResponse\n");

    // The claim, which is the only way into a zero-configuration node.
    const bootstrap = await api("/api/admin/bootstrap");
    check(bootstrap.claimed === false, "a fresh node reports itself unclaimed");

    const setupToken = (await readFile(join(node.appDir, ".setup-token"), "utf8")).trim();
    const claimed = await api("/api/admin/claim", {
      method: "POST",
      body: { token: setupToken, password: ADMIN_PASSWORD },
    });
    token = claimed.token;
    check(typeof token === "string", "the setup token buys an admin session");

    // 1. The seed phrase, up.
    const setupChannel = await page.openEnvelope();
    const sealedSetup = await page.sealRequest(setupChannel, {
      mnemonic: PHRASE,
      account: 1,
      network: "signet",
    });
    check(
      !JSON.stringify(sealedSetup).includes("abandon"),
      "the sealed body carries no word of the phrase",
    );

    const provisioned = await api("/api/admin/setup/provision", {
      method: "POST",
      body: sealedSetup,
    });
    check(
      typeof provisioned.node_id === "string" && provisioned.node_id.startsWith("node-"),
      `the node decrypts it and derives ${provisioned.node_id}`,
    );
    check(provisioned.seal_slot === "file", "the key is sealed under the generated file slot");

    // On the first fetch, not whenever the supervisor happens to be scheduled.
    // The endpoint that sealed the keystore publishes the seal status before it
    // answers, because the page caches this card per phase: an answer of "this
    // node cannot open its own keystore" would otherwise stick for the whole of
    // activation, on a node provisioned a moment earlier.
    const seal = await api("/api/admin/seal");
    check(seal.opened_with === "file", "the node reports which slot it opened through");
    check(
      seal.can_add_env_slot === true && seal.has_env_slot === false,
      "and offers the env slot without waiting for the supervisor",
    );

    // 2. The seal key, down.
    const envChannel = await page.openEnvelope();
    const envReply = await api("/api/admin/seal/env-slot", {
      method: "POST",
      body: await page.sealRequest(envChannel, {}),
    });
    const opened = await page.openResponse(envChannel, envReply.sealed);
    check(opened.env_var === "KONTOR_SEAL_KEY", "the browser opens the sealed reply");
    check(
      Buffer.from(opened.key, "base64").length === 32,
      "what it holds is a 32-byte seal key",
    );
    check(
      !JSON.stringify(envReply).includes(opened.key),
      "the key appears nowhere outside the sealed reply",
    );

    // Only that browser. A second exchange derives different directional keys.
    const eavesdropper = await page.openEnvelope();
    let readable = true;
    try {
      await page.openResponse(eavesdropper, envReply.sealed);
    } catch {
      readable = false;
    }
    check(!readable, "another browser cannot open that reply");

    // 3. The passphrase, up.
    const phraseChannel = await page.openEnvelope();
    const withSlot = await api("/api/admin/seal/passphrase", {
      method: "POST",
      body: await page.sealRequest(phraseChannel, { passphrase: SEAL_PASSPHRASE }),
    });
    check(withSlot.slots.includes("passphrase"), "a sealed passphrase adds its slot");

    const after = await api("/api/admin/seal");
    check(after.has_passphrase_slot === true, "and the node says so afterwards");
    check(
      after.fingerprint !== null && !JSON.stringify(after).includes(SEAL_PASSPHRASE),
      "the seal status publishes no passphrase, in any form",
    );

    // 4. Nothing secret was ever in a body.
    const bodies = sentBodies.join("\n");
    check(!bodies.includes("abandon abandon"), "no request body carried the phrase");
    check(!bodies.includes(SEAL_PASSPHRASE), "no request body carried the passphrase");
    check(!bodies.includes(opened.key), "no request body carried the seal key");

    // 5. And the key the node just handed back is one the page would show.
    console.log("");
    await checkTheReveal();
  } catch (error) {
    failure = error;
  } finally {
    await node.stop();
  }

  if (failure) {
    console.error(`\n${failure.message}`);
    process.exit(1);
  }
  console.log("\nThe browser half of the sealed channel works against a live node.");
}

await main();

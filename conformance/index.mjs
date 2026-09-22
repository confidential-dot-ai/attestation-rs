// The conformance corpus of the CVM attestation profile (design doc section
// 14), with a harness that runs it against a JavaScript implementation.
//
//   const corpus = await loadCorpus();
//   const report = await run(corpus, async (inputs) => appraisalJson);
//
// The appraiser receives the case's inputs and returns the section 5
// appraisal as JSON text or a parsed value. To refuse, it throws an Error
// whose `code` is a refusal code of section 14.4. Any other throw means the
// implementation did not decide, which the report lists as an error, never
// as a decision.

import { readFile, readdir } from "node:fs/promises";
import { dirname, join, posix } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));

/** The refusal codes of section 14.4, in the order of the table. */
export const CODES = Object.freeze([
  "envelope-invalid",
  "policy-invalid",
  "platform-unsupported",
  "report-invalid",
  "signature-invalid",
  "chain-invalid",
  "machine-not-allowed",
  "guest-policy",
  "binding-mismatch",
  "collateral-unavailable",
  "collateral-invalid",
  "revoked",
  "tcb-not-allowed",
  "register-mismatch",
  "log-required",
  "log-invalid",
  "replay-mismatch",
  "reference-mismatch",
  "backing-below-minimum",
  "device-required",
  "device-not-allowed",
  "device-token-invalid",
  "device-policy",
  "unsupported",
]);

const ID = /^[a-z0-9]+(-[a-z0-9]+)*$/;
const VERSION = /^[0-9]+\.[0-9]+$/;

class CaseError extends Error {}

function fail(message) {
  throw new CaseError(message);
}

/** Section 14.2 path form: relative to inputs, forward slashes, no parent segments. */
export function checkPath(p) {
  if (typeof p !== "string" || p === "") fail("empty path");
  if (p.includes("\\")) fail(`${JSON.stringify(p)}: forward slashes only`);
  if (posix.isAbsolute(p) || posix.normalize(p) !== p) fail(`${JSON.stringify(p)}: a clean relative path`);
  for (const seg of p.split("/")) {
    if (seg === "") fail(`${JSON.stringify(p)}: no empty segments`);
    if (seg === ".." || seg === ".") fail(`${JSON.stringify(p)}: no parent segments`);
  }
  return p;
}

function object(v, what) {
  if (v === null || typeof v !== "object" || Array.isArray(v)) fail(`${what}: an object`);
  return v;
}

function text(v, what) {
  if (typeof v !== "string" || v === "") fail(`${what}: a non-empty string`);
  return v;
}

function onlyKeys(o, allowed, what) {
  for (const k of Object.keys(o)) {
    if (!allowed.includes(k)) fail(`${what}: unknown member ${JSON.stringify(k)}`);
  }
}

/** Parses one case object into its checked form (section 14.2). */
export function parseCase(raw) {
  const o = object(raw, "case");
  onlyKeys(o, ["id", "rule", "now", "evidence", "policy", "collateral", "nras", "expect"], "case");
  const id = text(o.id, "id");
  if (!ID.test(id)) fail(`id ${JSON.stringify(id)} is not kebab-case`);
  const rule = object(o.rule, "rule");
  onlyKeys(rule, ["section", "statement"], "rule");
  text(rule.section, "rule.section");
  text(rule.statement, "rule.statement");
  const now = text(o.now, "now");
  if (Number.isNaN(Date.parse(now)) || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(\.\d+)?(Z|[+-]\d{2}:\d{2})$/.test(now)) {
    fail(`now ${JSON.stringify(now)} is not RFC 3339`);
  }
  const c = { id, rule: { section: rule.section, statement: rule.statement }, now, evidence: checkPath(o.evidence) };
  if (o.policy !== undefined) c.policy = checkPath(o.policy);
  c.collateral = {};
  if (o.collateral !== undefined) {
    for (const [key, ref] of Object.entries(object(o.collateral, "collateral"))) {
      if (key === "") fail("collateral: empty key");
      if (typeof ref === "string") {
        c.collateral[key] = { path: checkPath(ref) };
      } else {
        const r = object(ref, `collateral ${key}`);
        onlyKeys(r, ["body", "signing_chain"], `collateral ${key}`);
        if (r.body === undefined || r.signing_chain === undefined) {
          fail(`collateral ${key}: a signed artifact names both body and signing_chain`);
        }
        c.collateral[key] = { body: checkPath(r.body), signingChain: checkPath(r.signing_chain) };
      }
    }
  }
  c.nras = [];
  if (o.nras !== undefined) {
    if (!Array.isArray(o.nras)) fail("nras: an array");
    for (const [i, x] of o.nras.entries()) {
      const e = object(x, `nras[${i}]`);
      onlyKeys(e, ["arch", "nonce", "response", "jwks"], `nras[${i}]`);
      c.nras.push({
        arch: text(e.arch, `nras[${i}].arch`),
        nonce: text(e.nonce, `nras[${i}].nonce`),
        response: checkPath(e.response),
        jwks: checkPath(e.jwks),
      });
    }
  }
  const expect = object(o.expect, "expect");
  onlyKeys(expect, ["appraisal", "refusal"], "expect");
  if ((expect.appraisal === undefined) === (expect.refusal === undefined)) {
    fail("expect: exactly one of appraisal or refusal");
  }
  if (expect.appraisal !== undefined) {
    c.expect = { appraisal: checkPath(expect.appraisal) };
  } else {
    const code = text(expect.refusal, "expect.refusal");
    if (!CODES.includes(code)) fail(`${JSON.stringify(code)} is not a refusal code of section 14.4`);
    c.expect = { refusal: code };
  }
  return c;
}

/**
 * Loads the corpus at `dir` (this directory by default): its version and its
 * cases, each checked against section 14.2 with every referenced input
 * present. `read(path)` returns an input's bytes.
 */
export async function loadCorpus(dir = here) {
  const version = (await readFile(join(dir, "VERSION"), "utf8")).trim();
  if (!VERSION.test(version)) throw new Error(`VERSION ${JSON.stringify(version)} is not <profile>.<revision>`);
  const inputs = join(dir, "inputs");
  const read = async (p) => readFile(join(inputs, checkPath(p)));
  const names = (await readdir(join(dir, "cases"))).filter((n) => n.endsWith(".json")).sort();
  const cases = [];
  const seen = new Set();
  for (const name of names) {
    const file = join(dir, "cases", name);
    let c;
    try {
      c = parseCase(JSON.parse(await readFile(file, "utf8")));
    } catch (e) {
      throw new Error(`cases/${name}: ${e.message}`, { cause: e });
    }
    if (c.id !== name.slice(0, -".json".length)) throw new Error(`cases/${name}: a case file is named by its id, got ${c.id}`);
    if (seen.has(c.id)) throw new Error(`cases/${name}: duplicate id`);
    seen.add(c.id);
    for (const p of referencedPaths(c)) {
      try {
        await read(p);
      } catch (e) {
        throw new Error(`cases/${name}: ${p}: ${e.message}`, { cause: e });
      }
    }
    cases.push(c);
  }
  if (cases.length === 0) throw new Error(`no cases under ${dir}`);
  return { version, cases, read, dir };
}

function referencedPaths(c) {
  const out = [c.evidence];
  if (c.policy) out.push(c.policy);
  for (const r of Object.values(c.collateral)) out.push(...(r.path ? [r.path] : [r.body, r.signingChain]));
  for (const x of c.nras) out.push(x.response, x.jwks);
  if (c.expect.appraisal) out.push(c.expect.appraisal);
  return out;
}

/**
 * Everything a decision depends on (section 14.2), read from a case:
 * `{ now, evidence, policy, collateral, nras }`, with `policy` null for the
 * section 7 default, `collateral[key] = { body, signingChain? }` as bytes and
 * `nras[i] = { arch, nonce, response, jwks }` with the recorded bytes.
 */
export async function inputsFor(corpus, c) {
  const inputs = {
    now: c.now,
    evidence: await corpus.read(c.evidence),
    policy: c.policy ? await corpus.read(c.policy) : null,
    collateral: {},
    nras: [],
  };
  for (const [key, r] of Object.entries(c.collateral)) {
    inputs.collateral[key] = r.path
      ? { body: await corpus.read(r.path) }
      : { body: await corpus.read(r.body), signingChain: await corpus.read(r.signingChain) };
  }
  for (const x of c.nras) {
    inputs.nras.push({ arch: x.arch, nonce: x.nonce, response: await corpus.read(x.response), jwks: await corpus.read(x.jwks) });
  }
  return inputs;
}

/** A JSON number kept as its source text, so 64-bit integers survive parsing. */
export class Num {
  constructor(source) {
    this.source = source;
  }
  toJSON() {
    return typeof JSON.rawJSON === "function" ? JSON.rawJSON(this.source) : Number(this.source);
  }
}

/** Parses JSON text, keeping numbers exact as `Num`. */
export function parseJson(textOrBytes) {
  const s = typeof textOrBytes === "string" ? textOrBytes : new TextDecoder("utf-8", { fatal: true }).decode(textOrBytes);
  return JSON.parse(s, function (_key, value, context) {
    if (typeof value !== "number") return value;
    return new Num(context && typeof context.source === "string" ? context.source : String(value));
  });
}

const NUMBER = /^(-?)(\d+)(?:\.(\d+))?(?:[eE]([+-]?\d+))?$/;

// A JSON number as an exact decimal: digits * 10^exp with no trailing zeros.
function decimal(source) {
  const m = NUMBER.exec(source);
  if (m === null) return null;
  let digits = (m[2] + (m[3] ?? "")).replace(/^0+/, "");
  let exp = (m[4] ? parseInt(m[4], 10) : 0) - (m[3] ? m[3].length : 0);
  if (digits === "") return { neg: false, digits: 0n, exp: 0 };
  const stripped = digits.replace(/0+$/, "");
  exp += digits.length - stripped.length;
  digits = stripped;
  return { neg: m[1] === "-", digits: BigInt(digits), exp };
}

function numEqual(a, b) {
  const x = decimal(a.source);
  const y = decimal(b.source);
  if (x === null || y === null) return a.source === b.source;
  return x.neg === y.neg && x.digits === y.digits && x.exp === y.exp;
}

function isObject(v) {
  return v !== null && typeof v === "object" && !Array.isArray(v) && !(v instanceof Num);
}

/** Section 14.3: removes, in place, the members that are the implementation's own. */
export function strip(appraisal) {
  if (!isObject(appraisal)) return appraisal;
  delete appraisal.iat;
  delete appraisal.ear_verifier_id;
  delete appraisal.ear_raw_evidence;
  if (isObject(appraisal.submods)) {
    for (const sub of Object.values(appraisal.submods)) {
      const checks = isObject(sub) && isObject(sub.ear_verifier_claims) ? sub.ear_verifier_claims.cvm_collateral : undefined;
      if (!isObject(checks)) continue;
      for (const check of Object.values(checks)) {
        if (isObject(check)) delete check.reason;
      }
    }
  }
  return appraisal;
}

/** Whether two parsed JSON values are the same value: objects by member, arrays by position, numbers by value. */
export function equal(a, b) {
  if (a instanceof Num || b instanceof Num) return a instanceof Num && b instanceof Num && numEqual(a, b);
  if (Array.isArray(a) || Array.isArray(b)) {
    return Array.isArray(a) && Array.isArray(b) && a.length === b.length && a.every((v, i) => equal(v, b[i]));
  }
  if (isObject(a) || isObject(b)) {
    if (!isObject(a) || !isObject(b)) return false;
    const ka = Object.keys(a);
    if (ka.length !== Object.keys(b).length) return false;
    return ka.every((k) => Object.hasOwn(b, k) && equal(a[k], b[k]));
  }
  return a === b;
}

const escape = (k) => k.replaceAll("~", "~0").replaceAll("/", "~1");

/** The JSON pointers at which `want` and `got` differ, one per line; empty when equal. */
export function diff(want, got) {
  const out = [];
  const walk = (p, a, b) => {
    if (isObject(a) && isObject(b)) {
      for (const k of [...new Set([...Object.keys(a), ...Object.keys(b)])].sort()) {
        const inA = Object.hasOwn(a, k);
        const inB = Object.hasOwn(b, k);
        if (inA && inB) walk(`${p}/${escape(k)}`, a[k], b[k]);
        else out.push(`${p}/${escape(k)}: ${inA ? "missing" : "unexpected"}`);
      }
      return;
    }
    if (!equal(a, b)) out.push(`${p}: expected ${JSON.stringify(a)}, got ${JSON.stringify(b)}`);
  };
  walk("", want, got);
  return out.join("\n");
}

/** Runs one case; the outcome is "pass", "fail" (another decision) or "error" (no decision). */
export async function runCase(corpus, c, appraiser) {
  let inputs;
  try {
    inputs = await inputsFor(corpus, c);
  } catch (e) {
    return { id: c.id, outcome: "error", detail: e.message };
  }
  let got;
  let refusal = null;
  try {
    got = await appraiser(inputs);
  } catch (e) {
    if (e && typeof e.code === "string") refusal = { code: e.code, reason: e.message ?? "" };
    else return { id: c.id, outcome: "error", detail: e && e.message ? e.message : String(e) };
  }
  if (c.expect.refusal) {
    if (refusal === null) return { id: c.id, outcome: "fail", detail: `appraised, expected refusal ${c.expect.refusal}` };
    if (refusal.code !== c.expect.refusal) {
      return { id: c.id, outcome: "fail", detail: `refused with ${refusal.code}, expected ${c.expect.refusal}: ${refusal.reason}` };
    }
    return { id: c.id, outcome: "pass", detail: "" };
  }
  if (refusal !== null) {
    return { id: c.id, outcome: "fail", detail: `refused with ${refusal.code}, expected an appraisal: ${refusal.reason}` };
  }
  let want;
  let have;
  try {
    want = parseJson(await corpus.read(c.expect.appraisal));
  } catch (e) {
    return { id: c.id, outcome: "error", detail: `${c.expect.appraisal}: ${e.message}` };
  }
  try {
    have = typeof got === "string" || got instanceof Uint8Array ? parseJson(got) : parseJson(JSON.stringify(got));
  } catch (e) {
    return { id: c.id, outcome: "error", detail: `the appraisal is not JSON: ${e.message}` };
  }
  strip(want);
  strip(have);
  if (!equal(want, have)) {
    return { id: c.id, outcome: "fail", detail: `appraisal differs from ${c.expect.appraisal}:\n${diff(want, have)}` };
  }
  return { id: c.id, outcome: "pass", detail: "" };
}

/** Runs every case against `appraiser` and reports each outcome. */
export async function run(corpus, appraiser) {
  const results = [];
  for (const c of corpus.cases) results.push(await runCase(corpus, c, appraiser));
  const count = (o) => results.filter((r) => r.outcome === o).length;
  return { version: corpus.version, results, passed: count("pass") === results.length, counts: { pass: count("pass"), fail: count("fail"), error: count("error") } };
}

/** The report as text, one line per case and a summary line. */
export function format(report) {
  const lines = [];
  for (const r of report.results) {
    lines.push(`${r.outcome.padEnd(5)} ${r.id}`);
    if (r.detail) for (const l of r.detail.split("\n")) lines.push(`      ${l}`);
  }
  const { pass, fail, error } = report.counts;
  lines.push(`corpus ${report.version}: ${pass} of ${report.results.length} cases pass (${fail} fail, ${error} error)`);
  return lines.join("\n") + "\n";
}

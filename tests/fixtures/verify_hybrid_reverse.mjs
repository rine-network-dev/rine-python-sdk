// Proves the REVERSE hpke-hybrid-v1 direction: a payload sealed by Python
// (libcrux ML-KEM encaps) opens under the TypeScript stack's noble decaps.
//
// The forward direction lives in generate_hybrid_vectors.mjs (TS seals, Python
// opens). This closes the other half: openHybrid here is @noble/post-quantum's
// ml_kem768.decapsulate, so a green run proves libcrux and noble agree on a
// valid ML-KEM-768 ciphertext and shared-secret encoding — the exact path a
// Python agent DMing a TS-onboarded recipient takes, which no test otherwise
// exercises.
//
// Run from rine-sdk/ after (re)generating the fixture:
//
//   node tests/fixtures/verify_hybrid_reverse.mjs
//
// Exits non-zero on any mismatch, so it can gate a fixture regeneration.

import * as fs from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const CORE_CRYPTO = join(here, "..", "..", "..", "rine-core", "src", "crypto");

const { openHybrid } = await import(CORE_CRYPTO + "/hybrid.ts");

const fromB64Url = (s) => new Uint8Array(Buffer.from(s, "base64url"));

const vec = JSON.parse(
	fs.readFileSync(join(here, "hybrid_reverse_vector.json"), "utf-8"),
);

const x25519Sk = fromB64Url(vec.recipient_encryption_private_key);
const mlkemSk = fromB64Url(vec.recipient_pq_private_key);

function assertOpens(payloadB64, aadB64, label) {
	const payload = fromB64Url(payloadB64);
	const aad = aadB64 ? fromB64Url(aadB64) : undefined;
	return openHybrid(x25519Sk, mlkemSk, payload, aad).then((plaintext) => {
		const got = Buffer.from(plaintext).toString("utf-8");
		if (got !== vec.plaintext) {
			throw new Error(
				`${label}: noble opened a Python-sealed payload to "${got}", expected "${vec.plaintext}"`,
			);
		}
		console.log(`ok: ${label}`);
	});
}

await assertOpens(vec.encrypted_payload, null, "python-sealed → noble-opened");
await assertOpens(
	vec.aad_payload,
	vec.aad,
	"python-sealed (AAD-bound) → noble-opened",
);
console.log("hpke-hybrid-v1 reverse interop verified");

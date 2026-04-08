/**
 * Generate cross-language test vectors from rine-core TypeScript.
 * Run from rine-sdk/: npx tsx tests/fixtures/generate_vectors.mjs
 * Output: tests/fixtures/vectors.json
 */

import { writeFileSync } from "fs";
import { fileURLToPath } from "url";
import { dirname, join } from "path";

// rine-core is a sibling directory in the worktree
const __dirname = dirname(fileURLToPath(import.meta.url));
const CORE_CRYPTO = join(__dirname, "..", "..", "..", "rine-core", "src", "crypto");
const CORE_SRC = join(__dirname, "..", "..", "..", "rine-core", "src");

// Dynamic imports resolve .ts files via tsx
const keys = await import(CORE_CRYPTO + "/keys.ts");
const sign = await import(CORE_CRYPTO + "/sign.ts");
const envelope = await import(CORE_CRYPTO + "/envelope.ts");
const hpke = await import(CORE_CRYPTO + "/hpke.ts");
const senderKeys = await import(CORE_CRYPTO + "/sender-keys.ts");
const skHelpers = await import(CORE_CRYPTO + "/sender-keys-helpers.ts");

const { generateSigningKeyPair, generateEncryptionKeyPair, toBase64Url, fromBase64Url } = keys;
const { signPayload } = sign;
const { encodeEnvelope } = envelope;
const { seal, open } = hpke;
const { generateSenderKey, deriveMessageKey, sealGroup } = senderKeys;
const { uuidToBytes, bytesToUuid } = skHelpers;

function b64(buf) { return toBase64Url(new Uint8Array(buf)); }

async function main() {
    const vectors = {};

    // === Ed25519 Signing ===
    const signKp = generateSigningKeyPair();
    const signMessage = new TextEncoder().encode("test message for signing");
    const signature = signPayload(signKp.privateKey, signMessage);

    vectors.signing = {
        private_key: b64(signKp.privateKey),
        public_key: b64(signKp.publicKey),
        message: b64(signMessage),
        signature: b64(signature),
    };

    // === Inner Envelope ===
    const kid = "rine:12345678-1234-5678-9abc-def012345678";
    const envPayload = new TextEncoder().encode('{"task":"test"}');
    const envSig = signPayload(signKp.privateKey, envPayload);
    const envelopeBytes = encodeEnvelope(kid, envSig, envPayload);

    vectors.envelope = {
        kid,
        signature: b64(envSig),
        payload: b64(envPayload),
        encoded: b64(envelopeBytes),
    };

    // === HPKE ===
    const encKp = generateEncryptionKeyPair();
    const hpkePlaintext = envelopeBytes;
    const hpkeCiphertext = await seal(encKp.publicKey, hpkePlaintext);
    // Verify round-trip
    const hpkeRecovered = await open(encKp.privateKey, hpkeCiphertext);
    if (b64(hpkeRecovered) !== b64(hpkePlaintext)) throw new Error("HPKE round-trip failed");

    vectors.hpke = {
        recipient_private_key: b64(encKp.privateKey),
        recipient_public_key: b64(encKp.publicKey),
        plaintext: b64(hpkePlaintext),
        ciphertext: b64(hpkeCiphertext),
    };

    // === Sender Keys (deterministic) ===
    const groupId = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const agentId = "11111111-2222-3333-4444-555555555555";
    const skState = generateSenderKey(groupId, agentId);
    // Use fixed chain key for determinism
    const fixedChainKey = new Uint8Array(32);
    fixedChainKey.fill(0xAB);
    skState.chainKey = fixedChainKey;
    skState.messageIndex = 0;

    const { messageKey, nextChainKey } = deriveMessageKey(fixedChainKey);

    vectors.sender_keys = {
        chain_key: b64(fixedChainKey),
        message_key: b64(messageKey),
        next_chain_key: b64(nextChainKey),
        group_id: groupId,
        agent_id: agentId,
        sender_key_id: skState.senderKeyId,
    };

    // Seal a group message
    const skPlaintext = new TextEncoder().encode('{"group":"message"}');
    const { encryptedPayload: skCiphertext, updatedState } = await sealGroup(
        signKp.privateKey, kid, skState, skPlaintext
    );

    vectors.sender_keys.signing_private_key = b64(signKp.privateKey);
    vectors.sender_keys.signing_kid = kid;
    vectors.sender_keys.plaintext = b64(skPlaintext);
    vectors.sender_keys.ciphertext = b64(skCiphertext);
    vectors.sender_keys.message_index_after = updatedState.messageIndex;

    // === UUID bytes ===
    const testUuid = "12345678-abcd-ef01-2345-6789abcdef01";
    const uuidBytes = uuidToBytes(testUuid);

    vectors.uuid = {
        string: testUuid,
        bytes: b64(uuidBytes),
        roundtrip: bytesToUuid(uuidBytes),
    };

    // === Key serialization ===
    vectors.key_serialization = {
        signing_private: b64(signKp.privateKey),
        signing_public: b64(signKp.publicKey),
        encryption_private: b64(encKp.privateKey),
        encryption_public: b64(encKp.publicKey),
    };

    // Write output
    const outPath = join(__dirname, "vectors.json");
    writeFileSync(outPath, JSON.stringify(vectors, null, 2));
    console.log(`Written to ${outPath}`);
    console.log(`Keys: ${Object.keys(vectors).join(", ")}`);
}

main().catch(e => { console.error(e); process.exit(1); });

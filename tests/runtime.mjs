import * as anchor from "@coral-xyz/anchor";
import {
  Keypair,
  PublicKey,
  SystemProgram,
  LAMPORTS_PER_SOL
} from "@solana/web3.js";
import { createHash } from "node:crypto";
import { readFileSync } from "node:fs";
import assert from "node:assert/strict";

const provider = anchor.AnchorProvider.env();
anchor.setProvider(provider);

const idl = JSON.parse(
  readFileSync("target/idl/sfm_rollup.json", "utf8")
);

const program = new anchor.Program(idl, provider);
const admin = provider.wallet.publicKey;
const attacker = Keypair.generate();

const [statePda] = PublicKey.findProgramAddressSync(
  [Buffer.from("rollup_state")],
  program.programId
);

const hash = x =>
  [...createHash("sha256").update(x).digest()];

const canonicalRoot = hash("AUTHORIZED_BATCH");
const attackerRoot = hash("ATTACKER_BATCH");
const invalidLeaf = hash("INVALID_LEAF");

let passed = 0;

async function check(name, fn) {
  await fn();
  console.log("PASS:", name);
  passed++;
}

async function mustReject(fn, name, expectedCode = null) {
  let failure = null;

  try {
    await fn();
  } catch (err) {
    failure = err;
  }

  assert.ok(failure, `${name} unexpectedly succeeded`);

  if (expectedCode !== null) {
    const actualCode =
      failure?.error?.errorCode?.code ??
      failure?.errorCode?.code ??
      null;

    assert.equal(
      actualCode,
      expectedCode,
      `${name}: unexpected failure: ${String(failure)}`
    );
  }
}

function submit(root, signer, count = 1) {
  return program.methods
    .submitBatch(root, new anchor.BN(count))
    .accounts({
      authority: signer.publicKey,
      rollupState: statePda,
      systemProgram: SystemProgram.programId
    })
    .signers(signer === attacker ? [attacker] : [])
    .rpc();
}

function verify(leaf, root) {
  return program.methods
    .verifyProof(leaf, [], root)
    .accounts({ rollupState: statePda })
    .rpc();
}

console.log("PROGRAM_ID=", program.programId.toBase58());
console.log("TEST_ADMIN=", admin.toBase58());
console.log("TEST_STATE=", statePda.toBase58());

const airdrop = await provider.connection.requestAirdrop(
  attacker.publicKey, LAMPORTS_PER_SOL
);
await provider.connection.confirmTransaction(
  airdrop, "confirmed"
);

await check("SC08-01 attacker cannot initialize state", async () => {
  await mustReject(
    () => submit(attackerRoot, attacker),
    "unauthorized initialization",
    "Unauthorized"
  );
  const state = await provider.connection.getAccountInfo(statePda);
  assert.equal(state, null);
});

await check("SC08-02 proof unavailable before initialization", async () => {
  await mustReject(
    () => verify(canonicalRoot, canonicalRoot),
    "proof before initialization"
  );
});

const adminSigner = { publicKey: admin };

await check("SC08-03 administrator initializes batch", async () => {
  await submit(canonicalRoot, adminSigner);
  const state = await program.account.rollupState.fetch(statePda);
  assert.deepEqual([...state.merkleRoot], canonicalRoot);
  assert.equal(state.authority.toBase58(), admin.toBase58());
  assert.equal(state.initialized, true);
});

await check("SC08-04 attacker cannot replace root", async () => {
  await mustReject(
    () => submit(attackerRoot, attacker),
    "unauthorized replacement",
    "Unauthorized"
  );
  const state = await program.account.rollupState.fetch(statePda);
  assert.deepEqual([...state.merkleRoot], canonicalRoot);
});

await check("SC08-05 canonical proof accepted", async () => {
  await verify(canonicalRoot, canonicalRoot);
});

await check("SC08-06 arbitrary root rejected", async () => {
  await mustReject(
    () => verify(attackerRoot, attackerRoot),
    "arbitrary root",
    "RootMismatch"
  );
});

await check("SC08-07 tampered leaf rejected", async () => {
  await mustReject(
    () => verify(invalidLeaf, canonicalRoot),
    "tampered leaf",
    "InvalidProof"
  );
});

await check("SC08-08 administrator can update batch", async () => {
  await submit(attackerRoot, adminSigner, 2);
  const state = await program.account.rollupState.fetch(statePda);
  assert.deepEqual([...state.merkleRoot], attackerRoot);
  assert.equal(state.txCount.toString(), "2");
});

console.log(`SC08_RUNTIME_PASS=${passed}/8`);
assert.equal(passed, 8);

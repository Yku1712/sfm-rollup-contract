use anchor_lang::prelude::*;
use sha2::{Digest, Sha256};

// Valid Base58 dummy ID for compilation purposes
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod sfm_rollup {
    use super::*;

    pub fn submit_batch(
        ctx: Context<SubmitBatch>,
        merkle_root: [u8; 32],
        tx_count: u64,
    ) -> Result<()> {
        // Fail closed unless a real deployment authority is configured.
        let configured = configured_authority()?;
        require_keys_eq!(
            ctx.accounts.authority.key(),
            configured,
            RollupError::Unauthorized
        );

        let rollup_state = &mut ctx.accounts.rollup_state;

        validate_batch_authority(ctx.accounts.authority.key(), rollup_state, configured)?;

        if !rollup_state.initialized {
            rollup_state.authority = configured;
            rollup_state.initialized = true;
        }

        require!(tx_count > 0, RollupError::InvalidBatch);
        require!(merkle_root != [0u8; 32], RollupError::InvalidBatch);

        rollup_state.merkle_root = merkle_root;
        rollup_state.tx_count = tx_count;
        rollup_state.last_updated = Clock::get()?.unix_timestamp;

        msg!("New SFM Batch submitted! Root: {:?}", merkle_root);
        Ok(())
    }

    pub fn verify_proof(
        ctx: Context<VerifyProof>,
        leaf: [u8; 32],
        proof: Vec<[u8; 32]>,
        root: [u8; 32],
    ) -> Result<bool> {
        // The supplied root is retained for API compatibility,
        // but it must equal the canonical on-chain root.
        validate_bound_proof(&ctx.accounts.rollup_state, leaf, proof, root)
    }
}

// No fallback authority. An unconfigured build cannot submit batches.
fn configured_authority() -> Result<Pubkey> {
    let value =
        option_env!("SFM_ROLLUP_INITIAL_AUTHORITY").ok_or(RollupError::AuthorityNotConfigured)?;

    value
        .parse::<Pubkey>()
        .map_err(|_| error!(RollupError::AuthorityNotConfigured))
}

fn validate_batch_authority(signer: Pubkey, state: &RollupState, configured: Pubkey) -> Result<()> {
    require_keys_eq!(signer, configured, RollupError::Unauthorized);

    if state.initialized {
        require_keys_eq!(state.authority, configured, RollupError::Unauthorized);
    }

    Ok(())
}

fn validate_bound_proof(
    state: &RollupState,
    leaf: [u8; 32],
    proof: Vec<[u8; 32]>,
    supplied_root: [u8; 32],
) -> Result<bool> {
    require!(state.initialized, RollupError::NotInitialized);
    require!(
        supplied_root == state.merkle_root,
        RollupError::RootMismatch
    );

    let valid = verify_merkle_proof(leaf, proof, state.merkle_root);

    require!(valid, RollupError::InvalidProof);
    Ok(true)
}

// Helper: SHA-256 of two 32-byte hashes concatenated (raw bytes)
fn sha256_pair(a: &[u8; 32], b: &[u8; 32]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(a);
    hasher.update(b);
    hasher.finalize().into()
}

// Helper: SHA-256 of arbitrary data
fn sha256_bytes(data: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(data);
    hasher.finalize().into()
}

// Pure function to verify the Merkle Proof
pub fn verify_merkle_proof(leaf: [u8; 32], proof: Vec<[u8; 32]>, root: [u8; 32]) -> bool {
    let mut computed_hash = leaf;
    for p in proof {
        if computed_hash <= p {
            computed_hash = sha256_pair(&computed_hash, &p);
        } else {
            computed_hash = sha256_pair(&p, &computed_hash);
        }
    }
    computed_hash == root
}

#[derive(Accounts)]
pub struct SubmitBatch<'info> {
    #[account(mut)]
    pub authority: Signer<'info>,

    #[account(
        init_if_needed,
        payer = authority,
        space = 8 + 32 + 8 + 8 + 32 + 1,
        seeds = [b"rollup_state"],
        bump
    )]
    pub rollup_state: Account<'info, RollupState>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyProof<'info> {
    #[account(
        seeds = [b"rollup_state"],
        bump
    )]
    pub rollup_state: Account<'info, RollupState>,
}

#[account]
pub struct RollupState {
    pub merkle_root: [u8; 32],
    pub tx_count: u64,
    pub last_updated: i64,
    pub authority: Pubkey,
    pub initialized: bool,
}

#[error_code]
pub enum RollupError {
    #[msg("The provided Merkle proof is invalid.")]
    InvalidProof,

    #[msg("Unauthorized rollup authority")]
    Unauthorized,

    #[msg("Rollup authority not configured")]
    AuthorityNotConfigured,

    #[msg("Rollup state is not initialized")]
    NotInitialized,

    #[msg("Proof root does not match on-chain state")]
    RootMismatch,

    #[msg("Invalid rollup batch")]
    InvalidBatch,
}

// UNIT TESTS
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_valid_merkle_proof() {
        // Construct a dummy tree of 4 leaves (A, B, C, D)
        let leaf_a = sha256_bytes(b"A");
        let leaf_b = sha256_bytes(b"B");
        let leaf_c = sha256_bytes(b"C");
        let leaf_d = sha256_bytes(b"D");

        // Level 1: AB and CD
        let node_ab = sha256_pair(&leaf_a, &leaf_b);
        let node_cd = sha256_pair(&leaf_c, &leaf_d);

        // Level 2: Root (ABCD)
        let root = sha256_pair(&node_ab, &node_cd);

        // Proof for Leaf A: [Leaf B, Node CD]
        let proof_for_a = vec![leaf_b, node_cd];

        // 1. Verify valid proof
        assert_eq!(
            verify_merkle_proof(leaf_a, proof_for_a.clone(), root),
            true,
            "Valid proof should return true"
        );

        // 2. Verify invalid proof (tampering with leaf)
        let fake_leaf = sha256_bytes(b"FAKE");
        assert_eq!(
            verify_merkle_proof(fake_leaf, proof_for_a, root),
            false,
            "Fake leaf should return false"
        );
    }
}

// CROSS-LANGUAGE COMPATIBILITY TESTS
// These vectors were generated by the JavaScript backend (test_merkle.cjs).
// If these tests pass, the JS and Rust implementations are mathematically identical.
#[cfg(test)]
mod cross_compat_tests {
    use super::*;

    fn hex_to_bytes(hex: &str) -> [u8; 32] {
        let bytes = hex::decode(hex).expect("Invalid hex string");
        let mut arr = [0u8; 32];
        arr.copy_from_slice(&bytes);
        arr
    }

    #[test]
    fn test_js_rust_cross_compatibility() {
        // Test vectors generated by JS backend (test_merkle.cjs)
        let leaf_a =
            hex_to_bytes("559aead08264d5795d3909718cdd05abd49572e84fe55590eef31a88a08fdffd");
        let leaf_b =
            hex_to_bytes("df7e70e5021544f4834bbee64a9e3789febc4be81470df629cad6ddb03320a5c");
        let node_cd =
            hex_to_bytes("2219e32655222934f7c1c527341c80b6e4fdc80d2ba7546aa87b0809b7fd7f5b");
        let expected_root =
            hex_to_bytes("c8f544cf6452807ca62fe6a50477d19faca3147959aa206efab622d394f40097");

        // Proof for leaf A = [leaf B, node CD]
        let proof = vec![leaf_b, node_cd];

        // Verify: the JS-generated proof must be accepted by the Rust contract
        assert!(
            verify_merkle_proof(leaf_a, proof.clone(), expected_root),
            "FAIL: JS-generated proof should verify in Rust. Hash logic mismatch!"
        );

        // Also verify that a tampered proof is rejected
        let fake_leaf = sha256_bytes(b"FAKE");
        assert!(
            !verify_merkle_proof(fake_leaf, proof, expected_root),
            "FAIL: Fake proof should not verify!"
        );

        println!("Cross-language Merkle compatibility: PASS");
    }
}

#[cfg(test)]
mod security_guard_tests {
    use super::*;

    fn state(authority: Pubkey, root: [u8; 32], initialized: bool) -> RollupState {
        RollupState {
            merkle_root: root,
            tx_count: 1,
            last_updated: 0,
            authority,
            initialized,
        }
    }

    #[test]
    fn unauthorized_signer_rejected() {
        let admin = Pubkey::new_from_array([1u8; 32]);
        let attacker = Pubkey::new_from_array([2u8; 32]);
        let s = state(admin, [3u8; 32], true);

        assert!(validate_batch_authority(attacker, &s, admin).is_err());
    }

    #[test]
    fn authorized_signer_accepted() {
        let admin = Pubkey::new_from_array([1u8; 32]);
        let s = state(admin, [3u8; 32], true);

        assert!(validate_batch_authority(admin, &s, admin).is_ok());
    }

    #[test]
    fn arbitrary_valid_merkle_root_rejected() {
        let admin = Pubkey::new_from_array([1u8; 32]);
        let canonical = [3u8; 32];
        let attacker_root = [9u8; 32];
        let s = state(admin, canonical, true);

        // Empty proof mathematically validates leaf == root.
        assert!(verify_merkle_proof(attacker_root, vec![], attacker_root));

        // The actual guard must reject the noncanonical root.
        assert!(validate_bound_proof(&s, attacker_root, vec![], attacker_root).is_err());
    }

    #[test]
    fn uninitialized_state_rejected() {
        let admin = Pubkey::new_from_array([1u8; 32]);
        let root = [3u8; 32];
        let s = state(admin, root, false);

        assert!(validate_bound_proof(&s, root, vec![], root).is_err());
    }

    #[test]
    fn configured_authority_missing_rejected() {
        if option_env!("SFM_ROLLUP_INITIAL_AUTHORITY").is_none() {
            assert!(configured_authority().is_err());
        }
    }
}

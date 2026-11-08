use anchor_lang::prelude::*;
use sha2::{Sha256, Digest};

// Valid Base58 dummy ID for compilation purposes
declare_id!("Fg6PaFpoGXkYsidMpWTK6W2BeZ7FEfcYkg476zPFsLnS");

#[program]
pub mod sfm_rollup {
    use super::*;

    pub fn submit_batch(ctx: Context<SubmitBatch>, merkle_root: [u8; 32], tx_count: u64) -> Result<()> {
        let rollup_state = &mut ctx.accounts.rollup_state;
        rollup_state.merkle_root = merkle_root;
        rollup_state.tx_count = tx_count;
        rollup_state.last_updated = Clock::get()?.unix_timestamp;

        msg!("New SFM Batch submitted! Root: {:?}", merkle_root);
        Ok(())
    }

    pub fn verify_proof(
        _ctx: Context<VerifyProof>,
        leaf: [u8; 32],
        proof: Vec<[u8; 32]>,
        root: [u8; 32]
    ) -> Result<bool> {
        let is_valid = verify_merkle_proof(leaf, proof, root);
        require!(is_valid, RollupError::InvalidProof);
        Ok(is_valid)
    }
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
pub fn verify_merkle_proof(
    leaf: [u8; 32],
    proof: Vec<[u8; 32]>,
    root: [u8; 32]
) -> bool {
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
        space = 8 + 32 + 8 + 8,
        seeds = [b"rollup_state"],
        bump
    )]
    pub rollup_state: Account<'info, RollupState>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct VerifyProof<'info> {
    pub rollup_state: Account<'info, RollupState>,
}

#[account]
pub struct RollupState {
    pub merkle_root: [u8; 32],
    pub tx_count: u64,
    pub last_updated: i64,
}

#[error_code]
pub enum RollupError {
    #[msg("The provided Merkle proof is invalid.")]
    InvalidProof,
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

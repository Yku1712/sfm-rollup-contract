use anchor_lang::prelude::*;
use solana_program::hash::hashv;

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

// Pure function to verify the Merkle Proof
pub fn verify_merkle_proof(
    leaf: [u8; 32],
    proof: Vec<[u8; 32]>,
    root: [u8; 32]
) -> bool {
    let mut computed_hash = leaf;
    for p in proof {
        if computed_hash <= p {
            computed_hash = hashv(&[&computed_hash[..], &p[..]]).to_bytes();
        } else {
            computed_hash = hashv(&[&p[..], &computed_hash[..]]).to_bytes();
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
        let leaf_a = hashv(&[b"A"]).to_bytes();
        let leaf_b = hashv(&[b"B"]).to_bytes();
        let leaf_c = hashv(&[b"C"]).to_bytes();
        let leaf_d = hashv(&[b"D"]).to_bytes();

        // Level 1: AB and CD
        let node_ab = hashv(&[&leaf_a[..], &leaf_b[..]]).to_bytes();
        let node_cd = hashv(&[&leaf_c[..], &leaf_d[..]]).to_bytes();

        // Level 2: Root (ABCD)
        let root = hashv(&[&node_ab[..], &node_cd[..]]).to_bytes();

        // Proof for Leaf A: [Leaf B, Node CD]
        let proof_for_a = vec![leaf_b, node_cd];

        // 1. Verify valid proof
        assert_eq!(
            verify_merkle_proof(leaf_a, proof_for_a.clone(), root),
            true,
            "Valid proof should return true"
        );

        // 2. Verify invalid proof (tampering with leaf)
        let fake_leaf = hashv(&[b"FAKE"]).to_bytes();
        assert_eq!(
            verify_merkle_proof(fake_leaf, proof_for_a, root),
            false,
            "Fake leaf should return false"
        );
    }
}

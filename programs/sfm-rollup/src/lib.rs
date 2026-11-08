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
        let mut computed_hash = leaf;

        for p in proof {
            // Sort the pair lexicographically to match standard Merkle tree logic
            if computed_hash <= p {
                computed_hash = hashv(&[&computed_hash[..], &p[..]]).to_bytes();
            } else {
                computed_hash = hashv(&[&p[..], &computed_hash[..]]).to_bytes();
            }
        }

        let is_valid = computed_hash == root;
        require!(is_valid, RollupError::InvalidProof);

        Ok(is_valid)
    }
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

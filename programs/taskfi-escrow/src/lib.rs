use anchor_lang::prelude::*;
use anchor_spl::token::{self, Token, TokenAccount, Transfer};
use anchor_spl::associated_token::AssociatedToken;

declare_id!("EscrowTaskFi1111111111111111111111111111111");

#[program]
pub mod taskfi_escrow {
    use super::*;

    /// Initialize an escrow for a job payment
    pub fn initialize_escrow(
        ctx: Context<InitializeEscrow>,
        job_id: String,
        amount: u64,
        deadline: i64,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        escrow.hirer = ctx.accounts.hirer.key();
        escrow.freelancer = ctx.accounts.freelancer.key();
        escrow.job_id = job_id;
        escrow.amount = amount;
        escrow.deadline = deadline;
        escrow.is_released = false;
        escrow.is_disputed = false;
        escrow.created_at = Clock::get()?.unix_timestamp;
        escrow.bump = *ctx.bumps.get("escrow").unwrap();

        // Transfer tokens from hirer to escrow account
        let cpi_ctx = CpiContext::new(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.hirer_token_account.to_account_info(),
                to: ctx.accounts.escrow_token_account.to_account_info(),
                authority: ctx.accounts.hirer.to_account_info(),
            },
        );
        token::transfer(cpi_ctx, amount)?;

        emit!(EscrowCreated {
            escrow: escrow.key(),
            hirer: escrow.hirer,
            freelancer: escrow.freelancer,
            job_id: escrow.job_id.clone(),
            amount: escrow.amount,
            deadline: escrow.deadline,
        });

        Ok(())
    }

    /// Release payment to freelancer (called by hirer or admin)
    pub fn release_payment(ctx: Context<ReleasePayment>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        require!(!escrow.is_released, EscrowError::AlreadyReleased);
        require!(!escrow.is_disputed, EscrowError::InDispute);

        // Only hirer or platform admin can release
        let signer = ctx.accounts.signer.key();
        require!(
            signer == escrow.hirer || signer == ctx.accounts.platform_admin.key(),
            EscrowError::UnauthorizedRelease
        );

        // Transfer tokens from escrow to freelancer
        let escrow_seeds = &[
            b"escrow",
            escrow.job_id.as_bytes(),
            &[escrow.bump],
        ];
        let signer_seeds = &[&escrow_seeds[..]];

        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.escrow_token_account.to_account_info(),
                to: ctx.accounts.freelancer_token_account.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, escrow.amount)?;

        escrow.is_released = true;
        escrow.released_at = Some(Clock::get()?.unix_timestamp);

        emit!(PaymentReleased {
            escrow: escrow.key(),
            freelancer: escrow.freelancer,
            amount: escrow.amount,
            released_by: signer,
        });

        Ok(())
    }

    /// Initiate dispute (called by hirer or freelancer)
    pub fn initiate_dispute(ctx: Context<InitiateDispute>, reason: String) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        require!(!escrow.is_released, EscrowError::AlreadyReleased);
        require!(!escrow.is_disputed, EscrowError::AlreadyDisputed);

        let signer = ctx.accounts.signer.key();
        require!(
            signer == escrow.hirer || signer == escrow.freelancer,
            EscrowError::UnauthorizedDispute
        );

        escrow.is_disputed = true;
        escrow.dispute_reason = Some(reason.clone());
        escrow.disputed_at = Some(Clock::get()?.unix_timestamp);

        emit!(DisputeInitiated {
            escrow: escrow.key(),
            initiated_by: signer,
            reason,
        });

        Ok(())
    }

    /// Resolve dispute (called by platform admin only)
    pub fn resolve_dispute(
        ctx: Context<ResolveDispute>,
        hirer_amount: u64,
        freelancer_amount: u64,
    ) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        require!(escrow.is_disputed, EscrowError::NotInDispute);
        require!(!escrow.is_released, EscrowError::AlreadyReleased);
        require!(
            hirer_amount + freelancer_amount == escrow.amount,
            EscrowError::InvalidSplitAmount
        );

        let escrow_seeds = &[
            b"escrow",
            escrow.job_id.as_bytes(),
            &[escrow.bump],
        ];
        let signer_seeds = &[&escrow_seeds[..]];

        // Transfer freelancer's portion
        if freelancer_amount > 0 {
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.escrow_token_account.to_account_info(),
                    to: ctx.accounts.freelancer_token_account.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                signer_seeds,
            );
            token::transfer(cpi_ctx, freelancer_amount)?;
        }

        // Transfer hirer's portion (refund)
        if hirer_amount > 0 {
            let cpi_ctx = CpiContext::new_with_signer(
                ctx.accounts.token_program.to_account_info(),
                Transfer {
                    from: ctx.accounts.escrow_token_account.to_account_info(),
                    to: ctx.accounts.hirer_token_account.to_account_info(),
                    authority: ctx.accounts.escrow.to_account_info(),
                },
                signer_seeds,
            );
            token::transfer(cpi_ctx, hirer_amount)?;
        }

        escrow.is_released = true;
        escrow.released_at = Some(Clock::get()?.unix_timestamp);

        emit!(DisputeResolved {
            escrow: escrow.key(),
            hirer_amount,
            freelancer_amount,
            resolved_by: ctx.accounts.admin.key(),
        });

        Ok(())
    }

    /// Emergency refund (called by platform admin only, for emergencies)
    pub fn emergency_refund(ctx: Context<EmergencyRefund>) -> Result<()> {
        let escrow = &mut ctx.accounts.escrow;
        
        require!(!escrow.is_released, EscrowError::AlreadyReleased);

        let escrow_seeds = &[
            b"escrow",
            escrow.job_id.as_bytes(),
            &[escrow.bump],
        ];
        let signer_seeds = &[&escrow_seeds[..]];

        // Refund full amount to hirer
        let cpi_ctx = CpiContext::new_with_signer(
            ctx.accounts.token_program.to_account_info(),
            Transfer {
                from: ctx.accounts.escrow_token_account.to_account_info(),
                to: ctx.accounts.hirer_token_account.to_account_info(),
                authority: ctx.accounts.escrow.to_account_info(),
            },
            signer_seeds,
        );
        token::transfer(cpi_ctx, escrow.amount)?;

        escrow.is_released = true;
        escrow.released_at = Some(Clock::get()?.unix_timestamp);

        emit!(EmergencyRefundIssued {
            escrow: escrow.key(),
            amount: escrow.amount,
            refunded_by: ctx.accounts.admin.key(),
        });

        Ok(())
    }
}

#[derive(Accounts)]
#[instruction(job_id: String)]
pub struct InitializeEscrow<'info> {
    #[account(
        init,
        payer = hirer,
        space = Escrow::SIZE,
        seeds = [b"escrow", job_id.as_bytes()],
        bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    #[account(mut)]
    pub hirer: Signer<'info>,
    
    /// CHECK: Freelancer public key, validated in business logic
    pub freelancer: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub hirer_token_account: Account<'info, TokenAccount>,
    
    #[account(
        init,
        payer = hirer,
        associated_token::mint = hirer_token_account.mint,
        associated_token::authority = escrow,
    )]
    pub escrow_token_account: Account<'info, TokenAccount>,
    
    pub system_program: Program<'info, System>,
    pub token_program: Program<'info, Token>,
    pub associated_token_program: Program<'info, AssociatedToken>,
    pub rent: Sysvar<'info, Rent>,
}

#[derive(Accounts)]
pub struct ReleasePayment<'info> {
    #[account(
        mut,
        seeds = [b"escrow", escrow.job_id.as_bytes()],
        bump = escrow.bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    pub signer: Signer<'info>,
    
    /// CHECK: Platform admin key, validated in business logic
    pub platform_admin: UncheckedAccount<'info>,
    
    #[account(mut)]
    pub escrow_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        associated_token::mint = escrow_token_account.mint,
        associated_token::authority = escrow.freelancer,
    )]
    pub freelancer_token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct InitiateDispute<'info> {
    #[account(
        mut,
        seeds = [b"escrow", escrow.job_id.as_bytes()],
        bump = escrow.bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    pub signer: Signer<'info>,
}

#[derive(Accounts)]
pub struct ResolveDispute<'info> {
    #[account(
        mut,
        seeds = [b"escrow", escrow.job_id.as_bytes()],
        bump = escrow.bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    pub admin: Signer<'info>,
    
    #[account(mut)]
    pub escrow_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        associated_token::mint = escrow_token_account.mint,
        associated_token::authority = escrow.freelancer,
    )]
    pub freelancer_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        associated_token::mint = escrow_token_account.mint,
        associated_token::authority = escrow.hirer,
    )]
    pub hirer_token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
pub struct EmergencyRefund<'info> {
    #[account(
        mut,
        seeds = [b"escrow", escrow.job_id.as_bytes()],
        bump = escrow.bump
    )]
    pub escrow: Account<'info, Escrow>,
    
    pub admin: Signer<'info>,
    
    #[account(mut)]
    pub escrow_token_account: Account<'info, TokenAccount>,
    
    #[account(
        mut,
        associated_token::mint = escrow_token_account.mint,
        associated_token::authority = escrow.hirer,
    )]
    pub hirer_token_account: Account<'info, TokenAccount>,
    
    pub token_program: Program<'info, Token>,
}

#[account]
pub struct Escrow {
    pub hirer: Pubkey,
    pub freelancer: Pubkey,
    pub job_id: String,
    pub amount: u64,
    pub deadline: i64,
    pub is_released: bool,
    pub is_disputed: bool,
    pub dispute_reason: Option<String>,
    pub created_at: i64,
    pub released_at: Option<i64>,
    pub disputed_at: Option<i64>,
    pub bump: u8,
}

impl Escrow {
    pub const SIZE: usize = 8 + // discriminator
        32 + // hirer
        32 + // freelancer
        4 + 64 + // job_id (string)
        8 + // amount
        8 + // deadline
        1 + // is_released
        1 + // is_disputed
        1 + 4 + 200 + // dispute_reason (Option<String>)
        8 + // created_at
        1 + 8 + // released_at (Option<i64>)
        1 + 8 + // disputed_at (Option<i64>)
        1; // bump
}

#[event]
pub struct EscrowCreated {
    pub escrow: Pubkey,
    pub hirer: Pubkey,
    pub freelancer: Pubkey,
    pub job_id: String,
    pub amount: u64,
    pub deadline: i64,
}

#[event]
pub struct PaymentReleased {
    pub escrow: Pubkey,
    pub freelancer: Pubkey,
    pub amount: u64,
    pub released_by: Pubkey,
}

#[event]
pub struct DisputeInitiated {
    pub escrow: Pubkey,
    pub initiated_by: Pubkey,
    pub reason: String,
}

#[event]
pub struct DisputeResolved {
    pub escrow: Pubkey,
    pub hirer_amount: u64,
    pub freelancer_amount: u64,
    pub resolved_by: Pubkey,
}

#[event]
pub struct EmergencyRefundIssued {
    pub escrow: Pubkey,
    pub amount: u64,
    pub refunded_by: Pubkey,
}

#[error_code]
pub enum EscrowError {
    #[msg("Payment has already been released")]
    AlreadyReleased,
    
    #[msg("Escrow is currently in dispute")]
    InDispute,
    
    #[msg("Escrow is not in dispute")]
    NotInDispute,
    
    #[msg("Escrow is already disputed")]
    AlreadyDisputed,
    
    #[msg("Unauthorized to release payment")]
    UnauthorizedRelease,
    
    #[msg("Unauthorized to initiate dispute")]
    UnauthorizedDispute,
    
    #[msg("Invalid split amount for dispute resolution")]
    InvalidSplitAmount,
}
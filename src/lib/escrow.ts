import {
  Connection,
  PublicKey,
  Transaction,
  TransactionInstruction,
  Keypair,
  SystemProgram,
  SYSVAR_RENT_PUBKEY,
  ConfirmOptions,
} from '@solana/web3.js'
import {
  TOKEN_PROGRAM_ID,
  ASSOCIATED_TOKEN_PROGRAM_ID,
  getAssociatedTokenAddress,
  createAssociatedTokenAccountInstruction,
} from '@solana/spl-token'
import { Program, AnchorProvider, web3, BN, Idl } from '@project-serum/anchor'
import { getConnection } from './solana'

// Program ID - this should match the one in the smart contract
export const ESCROW_PROGRAM_ID = new PublicKey('EscrowTaskFi1111111111111111111111111111111')

// Platform admin public key (should be configurable)
export const PLATFORM_ADMIN_KEY = new PublicKey('AdminTaskFi1111111111111111111111111111111')

// USDC mint address for mainnet/devnet
export const USDC_MINT = new PublicKey('EPjFWdd5AufqSSqeM2qN1xzybapC8G4wEGGkZwyTDt1v')

export interface EscrowAccount {
  hirer: PublicKey
  freelancer: PublicKey
  jobId: string
  amount: BN
  deadline: BN
  isReleased: boolean
  isDisputed: boolean
  disputeReason?: string
  createdAt: BN
  releasedAt?: BN
  disputedAt?: BN
  bump: number
}

export class EscrowService {
  private connection: Connection
  private program: Program | null = null

  constructor() {
    this.connection = getConnection()
  }

  // Initialize the program with a wallet
  initializeProgram(wallet: any) {
    const provider = new AnchorProvider(this.connection, wallet, {
      commitment: 'confirmed',
    })
    // In a real implementation, you'd load the IDL from the deployed program
    // For now, we'll create a minimal interface
    this.program = new Program({} as Idl, ESCROW_PROGRAM_ID, provider)
  }

  // Get escrow PDA for a job
  getEscrowPDA(jobId: string): [PublicKey, number] {
    return PublicKey.findProgramAddressSync(
      [Buffer.from('escrow'), Buffer.from(jobId)],
      ESCROW_PROGRAM_ID
    )
  }

  // Create escrow account for a job
  async createEscrow(
    hirer: PublicKey,
    freelancer: PublicKey,
    jobId: string,
    amount: number,
    deadline: number,
    wallet: any
  ): Promise<string> {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    const [escrowPDA] = this.getEscrowPDA(jobId)
    
    // Get token accounts
    const hirerTokenAccount = await getAssociatedTokenAddress(USDC_MINT, hirer)
    const escrowTokenAccount = await getAssociatedTokenAddress(USDC_MINT, escrowPDA, true)

    const transaction = new Transaction()

    // Create escrow token account if it doesn't exist
    try {
      await this.connection.getAccountInfo(escrowTokenAccount)
    } catch {
      transaction.add(
        createAssociatedTokenAccountInstruction(
          hirer,
          escrowTokenAccount,
          escrowPDA,
          USDC_MINT
        )
      )
    }

    // Add initialize escrow instruction
    const initializeIx = await this.program.methods
      .initializeEscrow(jobId, new BN(amount), new BN(deadline))
      .accounts({
        escrow: escrowPDA,
        hirer,
        freelancer,
        hirerTokenAccount,
        escrowTokenAccount,
        systemProgram: SystemProgram.programId,
        tokenProgram: TOKEN_PROGRAM_ID,
        associatedTokenProgram: ASSOCIATED_TOKEN_PROGRAM_ID,
        rent: SYSVAR_RENT_PUBKEY,
      })
      .instruction()

    transaction.add(initializeIx)

    // Send transaction
    const signature = await wallet.sendTransaction(transaction, this.connection)
    await this.connection.confirmTransaction(signature, 'confirmed')

    return signature
  }

  // Release payment to freelancer
  async releasePayment(
    jobId: string,
    freelancer: PublicKey,
    wallet: any
  ): Promise<string> {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    const [escrowPDA] = this.getEscrowPDA(jobId)
    const escrowTokenAccount = await getAssociatedTokenAddress(USDC_MINT, escrowPDA, true)
    const freelancerTokenAccount = await getAssociatedTokenAddress(USDC_MINT, freelancer)

    const transaction = new Transaction()

    // Create freelancer token account if it doesn't exist
    try {
      await this.connection.getAccountInfo(freelancerTokenAccount)
    } catch {
      transaction.add(
        createAssociatedTokenAccountInstruction(
          wallet.publicKey,
          freelancerTokenAccount,
          freelancer,
          USDC_MINT
        )
      )
    }

    // Add release payment instruction
    const releaseIx = await this.program.methods
      .releasePayment()
      .accounts({
        escrow: escrowPDA,
        signer: wallet.publicKey,
        platformAdmin: PLATFORM_ADMIN_KEY,
        escrowTokenAccount,
        freelancerTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .instruction()

    transaction.add(releaseIx)

    const signature = await wallet.sendTransaction(transaction, this.connection)
    await this.connection.confirmTransaction(signature, 'confirmed')

    return signature
  }

  // Initiate dispute
  async initiateDispute(
    jobId: string,
    reason: string,
    wallet: any
  ): Promise<string> {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    const [escrowPDA] = this.getEscrowPDA(jobId)

    const transaction = new Transaction()

    const disputeIx = await this.program.methods
      .initiateDispute(reason)
      .accounts({
        escrow: escrowPDA,
        signer: wallet.publicKey,
      })
      .instruction()

    transaction.add(disputeIx)

    const signature = await wallet.sendTransaction(transaction, this.connection)
    await this.connection.confirmTransaction(signature, 'confirmed')

    return signature
  }

  // Resolve dispute (admin only)
  async resolveDispute(
    jobId: string,
    hirer: PublicKey,
    freelancer: PublicKey,
    hirerAmount: number,
    freelancerAmount: number,
    wallet: any
  ): Promise<string> {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    const [escrowPDA] = this.getEscrowPDA(jobId)
    const escrowTokenAccount = await getAssociatedTokenAddress(USDC_MINT, escrowPDA, true)
    const hirerTokenAccount = await getAssociatedTokenAddress(USDC_MINT, hirer)
    const freelancerTokenAccount = await getAssociatedTokenAddress(USDC_MINT, freelancer)

    const transaction = new Transaction()

    const resolveIx = await this.program.methods
      .resolveDispute(new BN(hirerAmount), new BN(freelancerAmount))
      .accounts({
        escrow: escrowPDA,
        admin: wallet.publicKey,
        escrowTokenAccount,
        hirerTokenAccount,
        freelancerTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .instruction()

    transaction.add(resolveIx)

    const signature = await wallet.sendTransaction(transaction, this.connection)
    await this.connection.confirmTransaction(signature, 'confirmed')

    return signature
  }

  // Get escrow account data
  async getEscrowAccount(jobId: string): Promise<EscrowAccount | null> {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    try {
      const [escrowPDA] = this.getEscrowPDA(jobId)
      const escrowAccount = await this.program.account.escrow.fetch(escrowPDA)
      return escrowAccount as EscrowAccount
    } catch (error) {
      console.error('Error fetching escrow account:', error)
      return null
    }
  }

  // Check if escrow exists for a job
  async escrowExists(jobId: string): Promise<boolean> {
    const escrow = await this.getEscrowAccount(jobId)
    return escrow !== null
  }

  // Emergency refund (admin only)
  async emergencyRefund(
    jobId: string,
    hirer: PublicKey,
    wallet: any
  ): Promise<string> {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    const [escrowPDA] = this.getEscrowPDA(jobId)
    const escrowTokenAccount = await getAssociatedTokenAddress(USDC_MINT, escrowPDA, true)
    const hirerTokenAccount = await getAssociatedTokenAddress(USDC_MINT, hirer)

    const transaction = new Transaction()

    const refundIx = await this.program.methods
      .emergencyRefund()
      .accounts({
        escrow: escrowPDA,
        admin: wallet.publicKey,
        escrowTokenAccount,
        hirerTokenAccount,
        tokenProgram: TOKEN_PROGRAM_ID,
      })
      .instruction()

    transaction.add(refundIx)

    const signature = await wallet.sendTransaction(transaction, this.connection)
    await this.connection.confirmTransaction(signature, 'confirmed')

    return signature
  }

  // Listen to escrow events
  subscribeToEscrowEvents(jobId: string, callback: (event: any) => void) {
    if (!this.program) {
      throw new Error('Program not initialized')
    }

    const [escrowPDA] = this.getEscrowPDA(jobId)
    
    // Subscribe to account changes
    const subscriptionId = this.connection.onAccountChange(
      escrowPDA,
      callback,
      'confirmed'
    )

    return () => {
      this.connection.removeAccountChangeListener(subscriptionId)
    }
  }
}

// Helper functions
export const formatEscrowAmount = (amount: BN): number => {
  return amount.toNumber() / 1_000_000 // USDC has 6 decimals
}

export const parseEscrowAmount = (amount: number): BN => {
  return new BN(amount * 1_000_000) // Convert to USDC base units
}

export const isEscrowExpired = (deadline: BN): boolean => {
  const now = Math.floor(Date.now() / 1000)
  return deadline.toNumber() < now
}

// Export singleton instance
export const escrowService = new EscrowService()
import { PublicKey, Connection, Transaction } from '@solana/web3.js'
import { escrowService, EscrowService } from './escrow'
import { prisma } from './prisma'
import { getConnection } from './solana'

export interface PaymentService {
  createEscrowPayment: (params: CreateEscrowParams) => Promise<PaymentResult>
  releasePayment: (params: ReleasePaymentParams) => Promise<PaymentResult>
  disputePayment: (params: DisputePaymentParams) => Promise<PaymentResult>
  resolveDispute: (params: ResolveDisputeParams) => Promise<PaymentResult>
  getPaymentStatus: (jobId: string) => Promise<PaymentStatus>
}

export interface CreateEscrowParams {
  jobId: string
  hirerWallet: string
  freelancerWallet: string
  amount: number
  deadline?: Date
  wallet: any
}

export interface ReleasePaymentParams {
  jobId: string
  wallet: any
}

export interface DisputePaymentParams {
  jobId: string
  reason: string
  wallet: any
}

export interface ResolveDisputeParams {
  jobId: string
  hirerAmount: number
  freelancerAmount: number
  wallet: any
}

export interface PaymentResult {
  success: boolean
  transactionHash?: string
  error?: string
  payment?: any
}

export interface PaymentStatus {
  exists: boolean
  status?: 'PENDING' | 'ESCROW' | 'RELEASED' | 'REFUNDED' | 'DISPUTED'
  amount?: number
  escrowAddress?: string
  isDisputed?: boolean
  canRelease?: boolean
  canWithdraw?: boolean
}

export class TaskFiPaymentService implements PaymentService {
  private escrowService: EscrowService
  private connection: Connection

  constructor() {
    this.escrowService = escrowService
    this.connection = getConnection()
  }

  async createEscrowPayment({
    jobId,
    hirerWallet,
    freelancerWallet,
    amount,
    deadline,
    wallet
  }: CreateEscrowParams): Promise<PaymentResult> {
    try {
      // Initialize escrow service with wallet
      this.escrowService.initializeProgram(wallet)

      // Check if escrow already exists
      const exists = await this.escrowService.escrowExists(jobId)
      if (exists) {
        return {
          success: false,
          error: 'Escrow already exists for this job'
        }
      }

      // Create escrow on blockchain
      const deadlineTimestamp = deadline ? Math.floor(deadline.getTime() / 1000) : Math.floor(Date.now() / 1000) + (30 * 24 * 60 * 60) // 30 days default

      const transactionHash = await this.escrowService.createEscrow(
        new PublicKey(hirerWallet),
        new PublicKey(freelancerWallet),
        jobId,
        amount * 1_000_000, // Convert to USDC base units
        deadlineTimestamp,
        wallet
      )

      // Get escrow PDA for database record
      const [escrowPDA] = this.escrowService.getEscrowPDA(jobId)

      // Create payment record in database
      const payment = await prisma.payment.create({
        data: {
          amount,
          currency: 'USDC',
          status: 'ESCROW',
          escrowAddress: escrowPDA.toString(),
          transactionHash,
          payerId: hirerWallet, // This should be user ID, not wallet address
          jobId,
        }
      })

      // Update job status
      await prisma.job.update({
        where: { id: jobId },
        data: { status: 'IN_PROGRESS' }
      })

      return {
        success: true,
        transactionHash,
        payment
      }
    } catch (error) {
      console.error('Create escrow payment error:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to create escrow payment'
      }
    }
  }

  async releasePayment({ jobId, wallet }: ReleasePaymentParams): Promise<PaymentResult> {
    try {
      this.escrowService.initializeProgram(wallet)

      // Get job and payment details
      const job = await prisma.job.findUnique({
        where: { id: jobId },
        include: {
          payments: { where: { status: 'ESCROW' } },
          applications: { where: { isAccepted: true } }
        }
      })

      if (!job || job.payments.length === 0) {
        return {
          success: false,
          error: 'No active escrow payment found for this job'
        }
      }

      const payment = job.payments[0]
      const acceptedApplication = job.applications[0]

      if (!acceptedApplication) {
        return {
          success: false,
          error: 'No accepted freelancer found'
        }
      }

      // Get freelancer wallet address
      const freelancer = await prisma.user.findUnique({
        where: { id: acceptedApplication.freelancerId },
        select: { walletAddress: true }
      })

      if (!freelancer) {
        return {
          success: false,
          error: 'Freelancer not found'
        }
      }

      // Release payment on blockchain
      const transactionHash = await this.escrowService.releasePayment(
        jobId,
        new PublicKey(freelancer.walletAddress),
        wallet
      )

      // Update payment status in database
      const updatedPayment = await prisma.payment.update({
        where: { id: payment.id },
        data: {
          status: 'RELEASED',
          releaseDate: new Date(),
          transactionHash: transactionHash
        }
      })

      // Update job status
      await prisma.job.update({
        where: { id: jobId },
        data: { status: 'COMPLETED' }
      })

      // Update freelancer earnings
      await prisma.user.update({
        where: { id: acceptedApplication.freelancerId },
        data: {
          totalEarned: { increment: payment.amount }
        }
      })

      return {
        success: true,
        transactionHash,
        payment: updatedPayment
      }
    } catch (error) {
      console.error('Release payment error:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to release payment'
      }
    }
  }

  async disputePayment({ jobId, reason, wallet }: DisputePaymentParams): Promise<PaymentResult> {
    try {
      this.escrowService.initializeProgram(wallet)

      // Initiate dispute on blockchain
      const transactionHash = await this.escrowService.initiateDispute(jobId, reason, wallet)

      // Update payment status in database
      const payment = await prisma.payment.findFirst({
        where: { jobId, status: 'ESCROW' }
      })

      if (!payment) {
        return {
          success: false,
          error: 'No active escrow payment found'
        }
      }

      const updatedPayment = await prisma.payment.update({
        where: { id: payment.id },
        data: {
          status: 'DISPUTED',
          disputeReason: reason
        }
      })

      // Update job status
      await prisma.job.update({
        where: { id: jobId },
        data: { status: 'DISPUTED' }
      })

      return {
        success: true,
        transactionHash,
        payment: updatedPayment
      }
    } catch (error) {
      console.error('Dispute payment error:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to dispute payment'
      }
    }
  }

  async resolveDispute({
    jobId,
    hirerAmount,
    freelancerAmount,
    wallet
  }: ResolveDisputeParams): Promise<PaymentResult> {
    try {
      this.escrowService.initializeProgram(wallet)

      // Get job details
      const job = await prisma.job.findUnique({
        where: { id: jobId },
        include: {
          hirer: true,
          payments: { where: { status: 'DISPUTED' } },
          applications: { where: { isAccepted: true }, include: { freelancer: true } }
        }
      })

      if (!job || job.payments.length === 0) {
        return {
          success: false,
          error: 'No disputed payment found for this job'
        }
      }

      const payment = job.payments[0]
      const freelancer = job.applications[0]?.freelancer

      if (!freelancer) {
        return {
          success: false,
          error: 'Freelancer not found'
        }
      }

      // Resolve dispute on blockchain
      const transactionHash = await this.escrowService.resolveDispute(
        jobId,
        new PublicKey(job.hirer.walletAddress),
        new PublicKey(freelancer.walletAddress),
        hirerAmount * 1_000_000, // Convert to USDC base units
        freelancerAmount * 1_000_000,
        wallet
      )

      // Update payment status
      const updatedPayment = await prisma.payment.update({
        where: { id: payment.id },
        data: {
          status: 'RELEASED',
          releaseDate: new Date(),
          transactionHash: transactionHash
        }
      })

      // Update job status
      await prisma.job.update({
        where: { id: jobId },
        data: { status: 'COMPLETED' }
      })

      // Update user balances
      if (freelancerAmount > 0) {
        await prisma.user.update({
          where: { id: freelancer.id },
          data: { totalEarned: { increment: freelancerAmount } }
        })
      }

      return {
        success: true,
        transactionHash,
        payment: updatedPayment
      }
    } catch (error) {
      console.error('Resolve dispute error:', error)
      return {
        success: false,
        error: error instanceof Error ? error.message : 'Failed to resolve dispute'
      }
    }
  }

  async getPaymentStatus(jobId: string): Promise<PaymentStatus> {
    try {
      // Check database payment status
      const payment = await prisma.payment.findFirst({
        where: { jobId },
        orderBy: { createdAt: 'desc' }
      })

      if (!payment) {
        return { exists: false }
      }

      // Check blockchain escrow status
      const escrowAccount = await this.escrowService.getEscrowAccount(jobId)

      return {
        exists: true,
        status: payment.status as any,
        amount: payment.amount,
        escrowAddress: payment.escrowAddress || undefined,
        isDisputed: escrowAccount?.isDisputed || false,
        canRelease: !escrowAccount?.isReleased && !escrowAccount?.isDisputed,
        canWithdraw: escrowAccount?.isReleased || false
      }
    } catch (error) {
      console.error('Get payment status error:', error)
      return { exists: false }
    }
  }

  // Helper method to check if user can perform payment actions
  async canUserReleasePayment(jobId: string, userId: string): Promise<boolean> {
    try {
      const job = await prisma.job.findUnique({
        where: { id: jobId },
        select: { hirerId: true, status: true }
      })

      return job?.hirerId === userId && job.status === 'IN_PROGRESS'
    } catch (error) {
      return false
    }
  }

  async canUserDisputePayment(jobId: string, userId: string): Promise<boolean> {
    try {
      const job = await prisma.job.findUnique({
        where: { id: jobId },
        include: {
          applications: { where: { isAccepted: true } }
        }
      })

      const isHirer = job?.hirerId === userId
      const isFreelancer = job?.applications.some(app => app.freelancerId === userId)

      return (isHirer || isFreelancer) && job.status === 'IN_PROGRESS'
    } catch (error) {
      return false
    }
  }
}

// Export singleton instance
export const paymentService = new TaskFiPaymentService()

// Utility functions for payment formatting
export const formatPaymentAmount = (amount: number, currency = 'USDC'): string => {
  return `${amount.toLocaleString()} ${currency}`
}

export const calculatePlatformFee = (amount: number, feePercentage = 2.5): number => {
  return Math.round((amount * feePercentage / 100) * 100) / 100
}

export const calculateNetAmount = (amount: number, feePercentage = 2.5): number => {
  return amount - calculatePlatformFee(amount, feePercentage)
}
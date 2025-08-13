import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const initializeEscrowSchema = z.object({
  escrowAddress: z.string().min(32).max(44), // Solana public key length
  transactionHash: z.string().min(64).max(88), // Solana transaction signature
  amount: z.number().min(0), // Verify amount matches
})

const releaseEscrowSchema = z.object({
  transactionHash: z.string().min(64).max(88),
  releaseToFreelancer: z.boolean().default(true),
})

const disputeEscrowSchema = z.object({
  reason: z.string().min(10).max(500),
  evidence: z.array(z.string()).max(10).default([]), // URLs to evidence files
})


// POST /api/payments/[id]/escrow - Initialize escrow on blockchain
export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const escrowData = initializeEscrowSchema.parse(body)

    // Find payment and verify ownership
    const payment = await prisma.payment.findUnique({
      where: { id: params.id },
      include: {
        job: {
          select: {
            id: true,
            title: true,
            freelancerId: true,
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
              }
            }
          }
        },
        gig: {
          select: {
            id: true,
            title: true,
            freelancerId: true,
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
              }
            }
          }
        }
      }
    })

    if (!payment) {
      return NextResponse.json({ error: 'Payment not found' }, { status: 404 })
    }

    // Only payer can initialize escrow
    if (payment.fromUserId !== session.user.id) {
      return NextResponse.json({ error: 'Only payment owner can initialize escrow' }, { status: 403 })
    }

    // Payment must be in PENDING status
    if (payment.status !== 'PENDING') {
      return NextResponse.json({ 
        error: 'Payment must be in pending status to initialize escrow' 
      }, { status: 400 })
    }

    // Verify amount matches
    if (Math.abs(escrowData.amount - payment.amount) > 0.01) {
      return NextResponse.json({ 
        error: 'Escrow amount does not match payment amount' 
      }, { status: 400 })
    }

    // Update payment with escrow details
    const updatedPayment = await prisma.$transaction(async (tx) => {
      const updated = await tx.payment.update({
        where: { id: params.id },
        data: {
          status: 'ESCROW',
          escrowAddress: escrowData.escrowAddress,
          transactionHash: escrowData.transactionHash,
          releaseDate: new Date(Date.now() + 7 * 24 * 60 * 60 * 1000), // 7 days from now
        },
        include: {
          job: {
            select: {
              id: true,
              title: true,
            }
          },
          gig: {
            select: {
              id: true,
              title: true,
            }
          }
        }
      })

      // Notify freelancer that escrow is funded
      const freelancerId = payment.job?.freelancerId || payment.gig?.freelancerId
      if (freelancerId) {
        await tx.notification.create({
          data: {
            userId: freelancerId,
            type: 'escrow_funded',
            title: 'Escrow Funded',
            message: `Escrow has been funded for ${payment.amount} ${payment.currency}. You can start working!`,
            metadata: {
              paymentId: payment.id,
              escrowAddress: escrowData.escrowAddress,
              amount: payment.amount,
              currency: payment.currency,
              jobId: payment.job?.id,
              gigId: payment.gig?.id,
            }
          }
        })
      }

      return updated
    })

    return NextResponse.json({ 
      payment: updatedPayment,
      escrow: {
        address: escrowData.escrowAddress,
        transactionHash: escrowData.transactionHash,
        status: 'FUNDED',
        releaseDate: updatedPayment.releaseDate,
      }
    });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Initialize escrow error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// PUT /api/payments/[id]/escrow - Release or dispute escrow
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const body = await request.json()
    const action = body.action as 'release' | 'dispute'

    if (!action || !['release', 'dispute'].includes(action)) {
      return NextResponse.json({ error: 'Action must be either "release" or "dispute"' }, { status: 400 })
    }

    // Find payment and verify it has escrow
    const payment = await prisma.payment.findUnique({
      where: { id: params.id },
      include: {
        job: {
          select: {
            id: true,
            title: true,
          }
        },
        gig: {
          select: {
            id: true,
            title: true,
          }
        }
      }
    })

    if (!payment) {
      return NextResponse.json({ error: 'Payment not found' }, { status: 404 })
    }

    if (payment.status !== 'ESCROW') {
      return NextResponse.json({ error: 'Payment must be in escrow to perform this action' }, { status: 400 })
    }

    if (!payment.escrowAddress) {
      return NextResponse.json({ error: 'Payment does not have an escrow address' }, { status: 400 })
    }

    const freelancerId = payment.toUserId

    if (action === 'release') {
      // Only payer or admin can release escrow
      const canRelease = 
        payment.fromUserId === session.user.id || 
        PermissionService.canAccessUserManagement(session.user.role)

      if (!canRelease) {
        return NextResponse.json({ error: 'Only payment owner or admin can release escrow' }, { status: 403 })
      }

      const releaseData = releaseEscrowSchema.parse(body)

      const updatedPayment = await prisma.$transaction(async (tx) => {
        const updated = await tx.payment.update({
          where: { id: params.id },
          data: {
            status: 'RELEASED',
            transactionHash: releaseData.transactionHash,
            releaseDate: new Date(),
          }
        })

        // Update job status if completed
        if (payment.job) {
          await tx.job.update({
            where: { id: payment.job.id },
            data: { status: 'COMPLETED' }
          })
        }

        // Notify freelancer
        if (freelancerId) {
          await tx.notification.create({
            data: {
              userId: freelancerId,
              type: 'payment_released',
              title: 'Payment Released!',
              message: `Your payment of ${payment.amount} ${payment.currency} has been released from escrow`,
              metadata: {
                paymentId: payment.id,
                transactionHash: releaseData.transactionHash,
                amount: payment.amount,
                currency: payment.currency,
              }
            }
          })
        }

        return updated
      })

      return NextResponse.json({ 
        payment: updatedPayment,
        message: 'Escrow released successfully'
      })

    } else if (action === 'dispute') {
      // Only payer can dispute
      if (payment.fromUserId !== session.user.id) {
        return NextResponse.json({ error: 'Only payment owner can dispute escrow' }, { status: 403 })
      }

      const disputeData = disputeEscrowSchema.parse(body)

      const updatedPayment = await prisma.$transaction(async (tx) => {
        const updated = await tx.payment.update({
          where: { id: params.id },
          data: {
            status: 'DISPUTED',
            disputeReason: disputeData.reason,
          }
        })

        // Notify admin
        const admins = await tx.user.findMany({
          where: { role: 'ADMIN' },
          select: { id: true }
        })

        for (const admin of admins) {
          await tx.notification.create({
            data: {
              userId: admin.id,
              type: 'escrow_disputed',
              title: 'Escrow Dispute',
              message: `Escrow dispute opened for ${payment.amount} ${payment.currency}`,
              metadata: {
                paymentId: payment.id,
                escrowAddress: payment.escrowAddress,
                disputeReason: disputeData.reason,
                evidence: disputeData.evidence,
                amount: payment.amount,
                payerId: payment.fromUserId,
                freelancerId: freelancerId,
              }
            }
          })
        }

        // Notify freelancer
        if (freelancerId) {
          await tx.notification.create({
            data: {
              userId: freelancerId,
              type: 'escrow_disputed',
              title: 'Escrow Disputed',
              message: 'An escrow payment has been disputed. Please provide your response.',
              metadata: {
                paymentId: payment.id,
                disputeReason: disputeData.reason,
              }
            }
          })
        }

        return updated
      })

      return NextResponse.json({ 
        payment: updatedPayment,
        message: 'Dispute opened successfully. An admin will review the case.'
      })
    }
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
        { status: 400 }
      );
    }

    console.error('Escrow action error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

// GET /api/payments/[id]/escrow - Get escrow details
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions)
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 })
    }

    const payment = await prisma.payment.findUnique({
      where: { id: params.id },
      select: {
        id: true,
        amount: true,
        currency: true,
        status: true,
        escrowAddress: true,
        transactionHash: true,
        releaseDate: true,
        disputeReason: true,
        fromUserId: true,
        toUserId: true,
        job: {
          select: {
            id: true,
          }
        },
        gig: {
          select: {
            id: true,
          }
        }
      }
    })

    if (!payment) {
      return NextResponse.json({ error: 'Payment not found' }, { status: 404 })
    }

    const freelancerId = payment.toUserId

    // Check access permissions
    const canView = 
      payment.fromUserId === session.user.id ||
      freelancerId === session.user.id ||
      PermissionService.canAccessUserManagement(session.user.role)

    if (!canView) {
      return NextResponse.json({ error: 'Forbidden' }, { status: 403 })
    }

    if (!payment.escrowAddress) {
      return NextResponse.json({ error: 'Payment does not have escrow' }, { status: 400 })
    }

    const escrowInfo = {
      address: payment.escrowAddress,
      amount: payment.amount,
      currency: payment.currency,
      status: payment.status,
      transactionHash: payment.transactionHash,
      releaseDate: payment.releaseDate,
      disputeReason: payment.disputeReason,
      canRelease: payment.fromUserId === session.user.id || PermissionService.canAccessUserManagement(session.user.role),
      canDispute: payment.fromUserId === session.user.id && payment.status === 'ESCROW',
      autoReleaseDate: payment.releaseDate,
    }

    return NextResponse.json({ escrow: escrowInfo });
  } catch (error) {
    console.error('Get escrow error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
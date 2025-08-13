import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const updatePaymentSchema = z.object({
  status: z.enum(['PENDING', 'ESCROW', 'RELEASED', 'REFUNDED', 'DISPUTED']).optional(),
  disputeReason: z.string().min(10).max(500).optional(),
  escrowAddress: z.string().optional(),
  transactionHash: z.string().optional(),
  releaseDate: z.string().datetime().optional(),
})


// GET /api/payments/[id] - Get payment details
export async function GET(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    try {
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
    const payment = await prisma.payment.findUnique({
      where: { id: params.id },
      include: {
        payer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
            isVerified: true,
          },
        },
        job: {
          select: {
            id: true,
            title: true,
            status: true,
            budget: true,
            hirerId: true,
            freelancerId: true,
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
                avatarUrl: true,
                isVerified: true,
              }
            },
            hirer: {
              select: {
                id: true,
                name: true,
                username: true,
                avatarUrl: true,
               },
        },
        gig: {
          select: {
            id: true,
            title: true,
            status: true,
            freelancerId: true,
            freelancer: {
              select: {
                id: true,
                name: true,
                username: true,
                avatarUrl: true,
                isVerified: true,
               },
        },
      },
    })

    if (!payment) {
      return NextResponse.json({ error: 'Payment not}
 found' }, { status: 404 })
    // Check if user has access to this payment
    const freelancerId = payment.job?.freelancerId || payment.gig?.freelancerId
    const hirerId = payment.job?.hirerId || payment.payerId

    const canView = 
      payment.payerId === session.user.id || // Payer
      freelancerId === session.user.id || // Freelancer receiving payment
      PermissionService.canAccessUserManagement(session.user.role) // Admin

    if (!canView) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
    // Add escrow information for smart contract integration
    let escrowInfo = null
    if (payment.status === 'ESCROW' && payment.escrowAddress) {
      escrowInfo = {
        address: payment.escrowAddress,
        amount: payment.amount,
        currency: payment.currency,
        canRelease: payment.payerId === session.user.id || PermissionService.canAccessUserManagement(session.user.role),
        canDispute: payment.payerId === session.user.id,
        releaseDate: payment.releaseDate,
       return NextResponse.json({ 
      payment: {
        ...payment,
        escrowInfo
       });
      } catch (error) {
    console.error('Get payment error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
// PUT /api/payments/[id] - Update payment status (release, dispute, etc.);
export async function PUT(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
    try {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
    const body = await request.json()
    const updateData = updatePaymentSchema.parse(body)

    // Find payment and verify permissions
    const payment = await prisma.payment.findUnique({
      where: { id: params.id },
      include: {
        job: {
          select: {
            id: true,
            title: true,
            hirerId: true,
            freelancerId: true,
            status: true,
           },
        gig: {
          select: {
            id: true,
            title: true,
            freelancerId: true,
           })

    if (!payment) {
      return NextResponse.json({ error: 'Payment not}
 found' }, { status: 404 })
    const freelancerId = payment.job?.freelancerId || payment.gig?.freelancerId
    const hirerId = payment.job?.hirerId || payment.payerId

    // Check permissions based on the action
    let canUpdate = false
    let updatePayload: any = { if (updateData.status) {
      switch (updateData.status) {
        case 'RELEASED':
          // Only payer, admin, or auto-release can release funds
          canUpdate = 
            payment.payerId === session.user.id || 
            PermissionService.canAccessUserManagement(session.user.role)
          
          if (payment.status !== 'ESCROW') {
            return NextResponse.json({ error: "Internal server error" }, { status: 400 });
          updatePayload = {
            status: 'RELEASED',
            releaseDate: new Date(),
           break

        case 'DISPUTED':
          // Only payer can initiate disputes
          canUpdate = payment.payerId === session.user.id

          if (payment.status !== 'ESCROW') {
    return NextResponse.json({ error: "Internal server error" }, { status: 400 });
          updatePayload = {
            status: 'DISPUTED',
            disputeReason: updateData.disputeReason,
           break

        case 'REFUNDED':
          // Only admin can process refunds after disputes
          canUpdate = PermissionService.canAccessUserManagement(session.user.role)

          if (payment.status !== 'DISPUTED') {
            return NextResponse.json({ error: "Internal server error" }, { status: 400 });
          updatePayload = {
            status: 'REFUNDED',
            releaseDate: new Date(),
           break

        case 'ESCROW':
          // Only admin or system can move to escrow
          canUpdate = PermissionService.canAccessUserManagement(session.user.role)

          if (payment.status !== 'PENDING') {
            return NextResponse.json({ error: "Internal server error" }, { status: 400 });
          updatePayload = {
            status: 'ESCROW',
            escrowAddress: updateData.escrowAddress,
            transactionHash: updateData.transactionHash,
           break

        default:
          return NextResponse.json({ error: "Internal server error" }, { status: 400 });
       } else {
      // Admin can update escrow details without status change
      canUpdate = PermissionService.canAccessUserManagement(session.user.role)
      updatePayload = {
        escrowAddress: updateData.escrowAddress,
        transactionHash: updateData.transactionHash,
        releaseDate: updateData.releaseDate ? new Date(updateData.releaseDate) : undefined,
       if (!canUpdate) {
      return NextResponse.json({ error: 'Forbidden'  }, { status: 403 });
    // Update payment and handle side effects
    const updatedPayment = await prisma.$transaction(async (tx) => {
      const updated = await tx.payment.update({
        where: { id: params.id },
        data: updatePayload,
        include: {
          payer: {
            select: {
              id: true,
              name: true,
              username: true,
            }
          },
          job: {
            select: {
              id: true,
              title: true,
              freelancer: {
                select: {
                  id: true,
                  name: true,
                }
              }
            }
          },
          gig: {
            select: {
              id: true,
              title: true,
              freelancer: {
                select: {
                  id: true,
                  name: true,
                }
               })

      // Handle side effects based on status change
      if (updateData.status === 'RELEASED' && freelancerId) {
        // Mark job as completed if this was the final payment
        if (payment.job) {
          await tx.job.update({
            where: { id: payment.job.id },
            data: { status: 'COMPLETED'  })
        // Update freelancer stats
        await tx.user.update({
          where: { id: freelancerId },
          data: { 
            completedJobs: { increment: 1 },
            // totalEarned was already updated when payment was created
           })

        // Create notifications
        await tx.notification.create({
          data: {
            userId: freelancerId,
            type: 'PAYMENT_RELEASED',
            title: 'Payment Released!',
            message: `Your payment of ${payment.amount} ${payment.currency} has been released`,
            data: {
              paymentId: payment.id,
              amount: payment.amount,
              currency: payment.currency,
              jobId: payment.job?.id,
              gigId: payment.gig?.id,
             })
      if (updateData.status === 'DISPUTED') {
        // Notify admin about dispute
        const admins = await tx.user.findMany({
          where: { role: 'ADMIN' },
          select: { id: true  })

        for (const admin of admins) {
          await tx.notification.create({
            data: {
              userId: admin.id,
              type: 'PAYMENT_DISPUTED',
              title: 'Payment Dispute',
              message: `Payment dispute opened for ${payment.amount} ${payment.currency}`,
              data: {
                paymentId: payment.id,
                disputeReason: updateData.disputeReason,
                amount: payment.amount,
                payerId: payment.payerId,
                freelancerId: freelancerId,
               })
        // Notify freelancer
        if (freelancerId) {
          await tx.notification.create({
            data: {
              userId: freelancerId,
              type: 'PAYMENT_DISPUTED',
              title: 'Payment Disputed',
              message: `A payment has been disputed. Please provide any relevant information.`,
              data: {
                paymentId: payment.id,
                amount: payment.amount,
               })
         if (updateData.status === 'REFUNDED') {
        // Notify payer of refund
        await tx.notification.create({
          data: {
            userId: payment.payerId,
            type: 'PAYMENT_REFUNDED',
            title: 'Payment Refunded',
            message: `Your payment}
 of ${payment.amount} ${payment.currency} has been refunded`,
            data: {
              paymentId: payment.id,
              amount: payment.amount,
              currency: payment.currency,
            }
          }
        })

        // Update user totals
        await tx.user.update({
          where: { id: payment.payerId },
          data: { totalSpent: { decrement: payment.amount }  })

        if (freelancerId) {
          await tx.user.update({
            where: { id: freelancerId },
            data: { totalEarned: { decrement: payment.amount }  })
         return updated
    })

    return NextResponse.json({ payment: updatedPayment });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json(
        { error: 'Validation error', details: error.errors },
    return NextResponse.json({ error: "Internal server error" }, { status: 400 });
    console.error('Update payment error:', error)
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}}}}}}}}}}}}}}}}}}}}}}}}
}}}}}}}}
}}}}}
}}}}
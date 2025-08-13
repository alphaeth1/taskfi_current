import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'
import { prisma } from '@/lib/prisma'
import { z } from 'zod'

const purchaseSchema = z.object({
  packageIndex: z.number().min(0).max(2), // 0=basic, 1=standard, 2=premium
  requirements: z.string().min(10).max(2000),
  attachments: z.array(z.string()).max(5).default([]),
  customizations: z.string().max(1000).optional(),
  urgentDelivery: z.boolean().default(false), // 25% extra fee
})


// POST /api/gigs/[id]/purchase - Purchase a gig package
export async function POST(request: NextRequest, props: { params: Promise<{ id: string }> }) {
  const params = await props.params;
  try {
    const session = await getServerSession(authOptions);
    if (!session) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });
     // Only hirers and verified users can purchase gigs
    if (session.user.role !== 'HIRER' && session.user.role !== 'ADMIN') {
      return NextResponse.json({ error: 'Only hirers can purchase gigs' }, { status: 403 });
     const body = await request.json()
    const purchaseData = purchaseSchema.parse(body)

    // Verify gig exists and is active
    const gig = await prisma.gig.findUnique({
      where: { id: params.id },
      include: {
        freelancer: {
          select: {
            id: true,
            name: true,
            username: true,
            avatarUrl: true,
            rating: true,
            isVerified: true,
            isActive: true,
          },
        },
      },
    })

    if (!gig) {
      return NextResponse.json({ error: 'Gig not found' }, { status: 404 });
     if (gig.status !== 'ACTIVE') {
      return NextResponse.json({ error: 'This gig is not currently available' }, { status: 400 });
     if (!gig.freelancer.isActive) {
      return NextResponse.json({ error: 'This freelancer is not currently active' }, { status: 400 });
     // Can't purchase your own gig
    if (gig.freelancerId === session.user.id) {
      return NextResponse.json({ error: 'Cannot purchase your own gig' }, { status: 400 });
     // Validate package index
    const packages = gig.packages as any[]
    if (purchaseData.packageIndex >= packages.length) {
      return NextResponse.json({ error: 'Invalid package selected' }, { status: 400 });
     const selectedPackage = packages[purchaseData.packageIndex]
    
    // Calculate total amount (with urgent delivery fee if applicable)
    let totalAmount = selectedPackage.price
    if (purchaseData.urgentDelivery) {
      totalAmount = totalAmount * 1.25 // 25% extra for urgent delivery
     // Check if user has sufficient balance (for now, we'll assume they do)
    // In a real app, you'd check their wallet balance or payment method

    // Calculate delivery date
    let deliveryDays = selectedPackage.deliveryDays
    if (purchaseData.urgentDelivery) {
      deliveryDays = Math.ceil(deliveryDays / 2) // Half the delivery time
     const expectedDelivery = new Date()
    expectedDelivery.setDate(expectedDelivery.getDate() + deliveryDays)

    // Create payment record with escrow
    const payment = await prisma.$transaction(async (tx) => {
      // Create the payment record
      const payment = await tx.payment.create({
        data: {
          amount: totalAmount,
          status: 'ESCROW', // Money goes to escrow
          payerId: session.user.id,
          gigId: gig.id,
          packageDetails: {
            packageIndex: purchaseData.packageIndex,
            packageName: selectedPackage.name,
            originalPrice: selectedPackage.price,
            urgentDelivery: purchaseData.urgentDelivery,
            requirements: purchaseData.requirements,
            attachments: purchaseData.attachments,
            customizations: purchaseData.customizations,
            deliveryDays: deliveryDays,
            expectedDelivery: expectedDelivery.toISOString(),
            revisions: selectedPackage.revisions,
            features: selectedPackage.features,
          },
          releaseDate: expectedDelivery,
        },
        include: {
          freelancer: {
            select: {
              id: true,
              name: true,
              username: true,
              avatarUrl: true,
            }
          },
          gig: {
            select: {
              id: true,
              title: true,
            }
          });

      // Update gig order count
      await tx.gig.update({
        where: { id: gig.id },
        data: { orderCount: { increment: 1 }  })

      // Update freelancer total earned (pending)
      await tx.user.update({
        where: { id: gig.freelancerId },
        data: { totalEarned: { increment: totalAmount }  })

      // Update buyer total spent
      await tx.user.update({
        where: { id: session.user.id },
        data: { totalSpent: { increment: totalAmount }  })

      // Create notification for freelancer
      await tx.notification.create({
        data: {
          userId: gig.freelancerId,
          type: 'NEW_ORDER',
          title: 'New Gig Order!',
          message: `${session.user.name} purchased your gig: ${gig.title}`,
          data: {
            gigId: gig.id,
            paymentId: payment.id,
            packageName: selectedPackage.name,
            amount: totalAmount,
            buyerId: session.user.id
           })

      // Create notification for buyer
      await tx.notification.create({
        data: {
          userId: session.user.id,
          type: 'ORDER_CONFIRMED',
          title: 'Order Confirmed',
          message: `Your order for "${gig.title}" has been confirmed. The freelancer will start working on it soon.`,
          data: {
            gigId: gig.id,
            paymentId: payment.id,
            freelancerId: gig.freelancerId,
            expectedDelivery: expectedDelivery.toISOString()
           })

      // Start a message thread for this order
      await tx.message.create({
        data: {
          senderId: session.user.id,
          receiverId: gig.freelancerId,
          content: `Hi! I just purchased your gig "${gig.title}". Here are my requirements:\n\n${purchaseData.requirements}${purchaseData.customizations ? '\n\nAdditional customizations:\n' + purchaseData.customizations : ''}`,
          type: 'ORDER_MESSAGE',
          orderId: payment.id,
         })

      return payment
    });

    return NextResponse.json({ 
      payment,
      message: 'Gig purchased successfully! Funds are in escrow and will be released upon delivery.',
      orderId: payment.id,
      expectedDelivery,
    }, { status: 201 });
  } catch (error) {
    if (error instanceof z.ZodError) {
      return NextResponse.json({ error: "Invalid purchase data" }, { status: 400 });
     console.error('Purchase gig error:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}
}}}}
}}}}}}}}}}}
}}
}}
}
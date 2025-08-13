import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function POST(
  request: NextRequest,
  { params }: { params: { id: string } }) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const gigId = params.id;
    const body = await request.json();
    const { packageIndex, packageData } = body;

    // Validate input
    if (packageIndex === undefined || !packageData) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     // Get gig details
    const gig = await prisma.gig.findUnique({
      where: { id: gigId },
      include: {
        freelancer: {
          select: {
            id: true,
            name: true,
            username: true,
            walletAddress: true,
          },
        },
      },
    });

    if (!gig) {
      return NextResponse.json({ error: 'Gig not found' }, { status: 404 });
     // Check if user is trying to order their own gig
    if (gig.freelancerId === session.user.id) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     // Get current user details
    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        name: true,
        username: true,
        walletAddress: true,
      },
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
     // Create gig order (using JobApplication model for now - in a real app you'd have a separate GigOrder model)
    const order = await prisma.jobApplication.create({
      data: {
        freelancerId: gig.freelancerId,
        gigId: gigId,
        coverLetter: `Gig order: ${packageData.name} package`,
        proposedBudget: packageData.price,
        estimatedDays: packageData.deliveryDays,
        attachments: [],
        isAccepted: true, // Auto-accept gig orders
      },
    });

    // Create payment in escrow
    const payment = await prisma.payment.create({
      data: {
        amount: packageData.price,
        currency: 'USDC',
        status: 'ESCROW',
        fromUserId: session.user.id,
        toUserId: gig.freelancerId,
        gigId: gigId,
        escrowAddress: `escrow_${Date.now()}_${Math.random().toString(36).substring(2)}`, // Mock escrow address
      },
    });

    // Update gig order count
    await prisma.gig.update({
      where: { id: gigId },
      data: {
        orderCount: {
          increment: 1,
        },
      },
    });

    // Create notifications
    await Promise.all([
      // Notify freelancer of new order
      prisma.notification.create({
        data: {
          title: 'New Gig Order!',
          message: `${user.name} ordered your "${gig.title}" gig (${packageData.name} package)`,
          type: 'gig_order',
          userId: gig.freelancerId,
          actionUrl: `/gigs/${gigId}/orders/${order.id}`,
          metadata: {
            gigId,
            orderId: order.id,
            packageName: packageData.name,
            amount: packageData.price,
          },
        },
      }),
      // Notify buyer of successful order
      prisma.notification.create({
        data: {
          title: 'Order Confirmed',
          message: `Your order for "${gig.title}" has been confirmed. ${gig.freelancer.name} will start working on it.`,
          type: 'order_confirmation',
          userId: session.user.id,
          actionUrl: `/orders/${order.id}`,
          metadata: {
            gigId,
            orderId: order.id,
            packageName: packageData.name,
            amount: packageData.price,
          },
        },
      }),
    ]);

    return NextResponse.json({
      success: true,
      orderId: order.id,
      paymentId: payment.id,
      message: 'Gig order created successfully',
      order: {
        id: order.id,
        gigTitle: gig.title,
        freelancerName: gig.freelancer.name,
        packageName: packageData.name,
        amount: packageData.price,
        deliveryDays: packageData.deliveryDays,
        status: 'IN_PROGRESS',
      },
    });
    } catch (error) {
    console.error('Error creating gig order:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }
}

}}
}}
}}
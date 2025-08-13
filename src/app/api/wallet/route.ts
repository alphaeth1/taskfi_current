import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth/next';
import { authOptions } from '@/lib/auth';
import { prisma } from '@/lib/prisma';

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session?.user) {
      return NextResponse.json({ error: 'Authentication required' }, { status: 401 });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        id: true,
        walletAddress: true,
        totalEarned: true,
        totalSpent: true
      }
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
    }

    // Calculate in-app wallet balance (earnings - withdrawals)
    const transactions = await prisma.payment.findMany({
      where: {
        OR: [
          { fromUserId: session.user.id },
          { toUserId: session.user.id }
        ]
      },
      select: {
        amount: true,
        status: true,
        fromUserId: true,
        toUserId: true,
      }
    });

    let walletBalance = 0;
    transactions.forEach(transaction => {
      if (transaction.status === 'RELEASED') {
        if (transaction.toUserId === session.user.id) {
          // Money received
          walletBalance += transaction.amount;
        } else if (transaction.fromUserId === session.user.id) {
          // Money sent
          walletBalance -= transaction.amount;
        }
      }
    });

    return NextResponse.json({
      walletAddress: user.walletAddress,
      balance: walletBalance,
      totalEarned: user.totalEarned || 0,
      totalSpent: user.totalSpent || 0,
      transactions: transactions.slice(0, 10), // Recent 10 transactions
    });
  } catch (error) {
    console.error('Wallet error:', error);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}
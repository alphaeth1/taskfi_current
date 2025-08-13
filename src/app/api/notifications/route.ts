import { NextRequest, NextResponse } from 'next/server';
import { getServerSession } from 'next-auth';
import { authOptions } from '@/lib/auth';
import { PrismaClient } from '@prisma/client';

const prisma = new PrismaClient();

export async function GET(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const { searchParams } = new URL(request.url);
    const page = parseInt(searchParams.get('page') || '1');
    const limit = parseInt(searchParams.get('limit') || '20');
    const unreadOnly = searchParams.get('unreadOnly') === 'true';
    const type = searchParams.get('type');
    const offset = (page - 1) * limit;

    // Build filter conditions
    const where: any = {
      userId: session.user.id,
    };

    if (unreadOnly) {
      where.isRead = false;
     if (type && type !== 'all') {
      where.type = type;
     // Get notifications
    const notifications = await prisma.notification.findMany({
      where,
      orderBy: { createdAt: 'desc' },
      take: limit,
      skip: offset,
    });

    // Get unread count
    const unreadCount = await prisma.notification.count({
      where: {
        userId: session.user.id,
        isRead: false,
      },
    });

    // Get total count for pagination
    const totalCount = await prisma.notification.count({
      where,
    });

    return NextResponse.json({
      notifications,
      unreadCount,
      totalCount,
      hasMore: notifications.length === limit,
      currentPage: page,
      totalPages: Math.ceil(totalCount / limit),
    });
  } catch (error) {
    console.error('Error fetching notifications:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   export async function PATCH(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const body = await request.json();
    const { action, notificationIds } = body;

    if (action === 'markAsRead') {
      if (notificationIds && Array.isArray(notificationIds)) {
        // Mark specific notifications as read
        await prisma.notification.updateMany({
          where: {
            id: { in: notificationIds },
            userId: session.user.id,
          },
          data: {
            isRead: true,
          },
        });
      } else {
        // Mark all notifications as read
        await prisma.notification.updateMany({
          where: {
            userId: session.user.id,
            isRead: false,
          },
          data: {
            isRead: true,
          },
        });
       return NextResponse.json({
        message: 'Notifications marked as read',
        success: true,
      });
     if (action === 'delete') {
      if (notificationIds && Array.isArray(notificationIds)) {
        await prisma.notification.deleteMany({
          where: {
            id: { in: notificationIds },
            userId: session.user.id,
          },
        });

        return NextResponse.json({
          message: 'Notifications deleted',
          success: true,
        });
      }
    }

    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}}
}
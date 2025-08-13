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
     const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        notificationSettings: true,
      },
    });

    if (!user) {
      return NextResponse.json({ error: 'User not found' }, { status: 404 });
     // Default settings if none exist
    const defaultSettings = {
      emailNotifications: true,
      pushNotifications: true,
      jobAlerts: true,
      paymentAlerts: true,
      messageAlerts: true,
      marketingEmails: false,
      weeklyDigest: true,
      projectDeadlines: true,
    };

    const settings = user.notificationSettings || defaultSettings;

    return NextResponse.json(settings);
    } catch (error) {
    console.error('Error fetching notification settings:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
   export async function PUT(request: NextRequest) {
  try {
    const session = await getServerSession(authOptions);
    if (!session || !session.user) {
      return NextResponse.json({ error: 'Unauthorized'  }, { status: 401 });;
     const body = await request.json();
    const {
      emailNotifications,
      pushNotifications,
      jobAlerts,
      paymentAlerts,
      messageAlerts,
      marketingEmails,
      weeklyDigest,
      projectDeadlines,
    } = body;

    // Validate required fields
    if (
      typeof emailNotifications !== 'boolean' ||
      typeof pushNotifications !== 'boolean' ||
      typeof jobAlerts !== 'boolean' ||
      typeof paymentAlerts !== 'boolean' ||
      typeof messageAlerts !== 'boolean'
    ) {
      return NextResponse.json({ error: "Internal server error" }, { status: 400 });
     const updatedUser = await prisma.user.update({
      where: { id: session.user.id },
      data: {
        notificationSettings: {
          emailNotifications,
          pushNotifications,
          jobAlerts,
          paymentAlerts,
          messageAlerts,
          marketingEmails: marketingEmails || false,
          weeklyDigest: weeklyDigest !== false,
          projectDeadlines: projectDeadlines !== false,
        },
      },
      select: {
        notificationSettings: true,
      },
    });

    return NextResponse.json({
      message: 'Notification settings updated successfully',
      settings: updatedUser.notificationSettings,
    });
  } catch (error) {
    console.error('Error updating notification settings:', error);
    return NextResponse.json({ error: "Internal server error" }, { status: 500 });
  }


}
}
}
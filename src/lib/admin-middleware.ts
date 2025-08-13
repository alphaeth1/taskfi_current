import { NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions, PermissionService } from '@/lib/auth'

// Admin route protection middleware
export async function requireAdmin() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
  }

  if (!PermissionService.canAccessAdminPanel(session.user.role)) {
    return NextResponse.json({ 
      error: 'Admin access required. Only administrators can access this resource.' 
    }, { status: 403 })
  }

  return null // No error, continue
}

// Admin page protection for frontend
export async function requireAdminAccess() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    return {
      redirect: {
        destination: '/auth/signin?callbackUrl=' + encodeURIComponent('/admin'),
        permanent: false,
      }
    }
  }

  if (!PermissionService.canAccessAdminPanel(session.user.role)) {
    return {
      redirect: {
        destination: '/?error=admin_required',
        permanent: false,
      }
    }
  }

  return {
    props: {
      user: session.user,
    }
  }
}

// Check if user can manage users
export async function requireUserManagement() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
  }

  if (!PermissionService.canAccessUserManagement(session.user.role)) {
    return NextResponse.json({ 
      error: 'User management access required' 
    }, { status: 403 })
  }

  return null
}

// Check if user can manage categories
export async function requireCategoryManagement() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
  }

  if (!PermissionService.canManageCategories(session.user.role)) {
    return NextResponse.json({ 
      error: 'Category management access required' 
    }, { status: 403 })
  }

  return null
}

// Check if user can moderate disputes
export async function requireDisputeModeration() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
  }

  if (!PermissionService.canModerateDisputes(session.user.role)) {
    return NextResponse.json({ 
      error: 'Dispute moderation access required' 
    }, { status: 403 })
  }

  return null
}

// Utility function to get admin session or throw error
export async function getAdminSession() {
  const session = await getServerSession(authOptions)
  
  if (!session) {
    throw new Error('Authentication required')
  }

  if (!PermissionService.canAccessAdminPanel(session.user.role)) {
    throw new Error('Admin access required')
  }

  return session
}

// Utility to verify admin status for components
export async function verifyAdminAccess(userId: string): Promise<boolean> {
  try {
    const user = await prisma?.user.findUnique({
      where: { id: userId },
      select: { role: true, isActive: true }
    })

    if (!user || !user.isActive) {
      return false
    }

    return PermissionService.canAccessAdminPanel(user.role)
  } catch (error) {
    console.error('Admin verification error:', error)
    return false
  }
}
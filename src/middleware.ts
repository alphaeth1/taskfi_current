import { withAuth } from 'next-auth/middleware'
import { NextResponse } from 'next/server'
import type { NextRequest } from 'next/server'

export default withAuth(
  function middleware(req: NextRequest) {
    const token = req.nextauth.token
    const pathname = req.nextUrl.pathname

    // Protect admin routes
    if (pathname.startsWith('/admin')) {
      if (!token) {
        const url = new URL('/auth/signin', req.url)
        url.searchParams.set('callbackUrl', pathname)
        return NextResponse.redirect(url)
      }

      if (token.user?.role !== 'ADMIN') {
        const url = new URL('/', req.url)
        url.searchParams.set('error', 'admin_required')
        return NextResponse.redirect(url)
      }
    }

    // Protect API admin routes
    if (pathname.startsWith('/api/admin')) {
      if (!token) {
        return NextResponse.json({ error: 'Authentication required' }, { status: 401 })
      }

      if (token.user?.role !== 'ADMIN') {
        return NextResponse.json({ 
          error: 'Admin access required. Only administrators can access this resource.' 
        }, { status: 403 })
      }
    }

    // Protect dashboard routes based on role
    if (pathname.startsWith('/dashboard')) {
      if (!token) {
        const url = new URL('/auth/signin', req.url)
        url.searchParams.set('callbackUrl', pathname)
        return NextResponse.redirect(url)
      }

      // Extract dashboard type from path
      const pathSegments = pathname.split('/')
      const dashboardType = pathSegments[2] // /dashboard/[type]/...

      if (dashboardType === 'freelancer' && token.user?.role !== 'FREELANCER') {
        const url = new URL('/dashboard', req.url)
        url.searchParams.set('error', 'role_mismatch')
        return NextResponse.redirect(url)
      }

      if (dashboardType === 'hirer' && token.user?.role !== 'HIRER') {
        const url = new URL('/dashboard', req.url)
        url.searchParams.set('error', 'role_mismatch')
        return NextResponse.redirect(url)
      }

      if (dashboardType === 'admin' && token.user?.role !== 'ADMIN') {
        const url = new URL('/dashboard', req.url)
        url.searchParams.set('error', 'admin_required')
        return NextResponse.redirect(url)
      }
    }

    // Protect onboarding - only for new users without complete profiles
    if (pathname === '/onboarding') {
      if (!token) {
        const url = new URL('/auth/signin', req.url)
        url.searchParams.set('callbackUrl', pathname)
        return NextResponse.redirect(url)
      }

      // If user has username, they've completed onboarding
      if (token.user?.username) {
        return NextResponse.redirect(new URL('/dashboard', req.url))
      }
    }

    return NextResponse.next()
  },
  {
    callbacks: {
      authorized: ({ token, req }) => {
        // Allow public routes
        const publicRoutes = ['/', '/auth/signin', '/api/auth', '/browse']
        const pathname = req.nextUrl.pathname

        if (publicRoutes.some(route => pathname.startsWith(route))) {
          return true
        }

        // Require authentication for protected routes
        return !!token
      },
    },
  }
)

export const config = {
  matcher: [
    /*
     * Match all request paths except for the ones starting with:
     * - _next/static (static files)
     * - _next/image (image optimization files)
     * - favicon.ico (favicon file)
     * - public (public files)
     */
    '/((?!_next/static|_next/image|favicon.ico|public).*)',
  ],
}
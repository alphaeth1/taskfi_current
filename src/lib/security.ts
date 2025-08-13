import { NextRequest, NextResponse } from 'next/server'
import { getServerSession } from 'next-auth'
import { authOptions } from './auth'
import { rateLimits } from './rate-limit'
import { handleApiError, AuthenticationError, AuthorizationError } from './error-handler'
import { z } from 'zod'

// Security headers
export const securityHeaders = {
  'X-Frame-Options': 'DENY',
  'X-Content-Type-Options': 'nosniff',
  'X-XSS-Protection': '1; mode=block',
  'Referrer-Policy': 'strict-origin-when-cross-origin',
  'Permissions-Policy': 'camera=(), microphone=(), geolocation=()',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-eval'; style-src 'self' 'unsafe-inline'; img-src 'self' data: https:; font-src 'self' data:;",
}

// CORS headers
export const corsHeaders = {
  'Access-Control-Allow-Origin': process.env.NODE_ENV === 'production' 
    ? 'https://your-domain.com' 
    : '*',
  'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, PATCH, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Requested-With',
  'Access-Control-Max-Age': '86400', // 24 hours
}

// Role-based permissions
export enum Permission {
  // User permissions
  READ_PROFILE = 'read:profile',
  UPDATE_PROFILE = 'update:profile',
  DELETE_PROFILE = 'delete:profile',
  
  // Job permissions
  CREATE_JOB = 'create:job',
  READ_JOB = 'read:job',
  UPDATE_JOB = 'update:job',
  DELETE_JOB = 'delete:job',
  APPLY_JOB = 'apply:job',
  
  // Gig permissions
  CREATE_GIG = 'create:gig',
  READ_GIG = 'read:gig',
  UPDATE_GIG = 'update:gig',
  DELETE_GIG = 'delete:gig',
  PURCHASE_GIG = 'purchase:gig',
  
  // Payment permissions
  CREATE_PAYMENT = 'create:payment',
  READ_PAYMENT = 'read:payment',
  RELEASE_PAYMENT = 'release:payment',
  DISPUTE_PAYMENT = 'dispute:payment',
  
  // Message permissions
  SEND_MESSAGE = 'send:message',
  READ_MESSAGE = 'read:message',
  
  // Admin permissions
  ADMIN_USERS = 'admin:users',
  ADMIN_JOBS = 'admin:jobs',
  ADMIN_PAYMENTS = 'admin:payments',
  ADMIN_ANALYTICS = 'admin:analytics',
  ADMIN_CATEGORIES = 'admin:categories',
}

// Role to permissions mapping
const rolePermissions: Record<string, Permission[]> = {
  FREELANCER: [
    Permission.READ_PROFILE,
    Permission.UPDATE_PROFILE,
    Permission.READ_JOB,
    Permission.APPLY_JOB,
    Permission.CREATE_GIG,
    Permission.READ_GIG,
    Permission.UPDATE_GIG,
    Permission.DELETE_GIG,
    Permission.READ_PAYMENT,
    Permission.DISPUTE_PAYMENT,
    Permission.SEND_MESSAGE,
    Permission.READ_MESSAGE,
  ],
  HIRER: [
    Permission.READ_PROFILE,
    Permission.UPDATE_PROFILE,
    Permission.CREATE_JOB,
    Permission.READ_JOB,
    Permission.UPDATE_JOB,
    Permission.DELETE_JOB,
    Permission.READ_GIG,
    Permission.PURCHASE_GIG,
    Permission.CREATE_PAYMENT,
    Permission.READ_PAYMENT,
    Permission.RELEASE_PAYMENT,
    Permission.DISPUTE_PAYMENT,
    Permission.SEND_MESSAGE,
    Permission.READ_MESSAGE,
  ],
  ADMIN: Object.values(Permission), // Admin has all permissions
}

// Check if user has permission
export function hasPermission(userRole: string, permission: Permission): boolean {
  const permissions = rolePermissions[userRole] || []
  return permissions.includes(permission)
}

// Security middleware configuration
export interface SecurityConfig {
  requireAuth?: boolean
  permissions?: Permission[]
  rateLimitType?: 'api' | 'auth' | 'upload' | 'admin'
  validateInput?: z.ZodSchema
  allowedMethods?: string[]
  skipCors?: boolean
}

// Main security middleware
export function withSecurity(config: SecurityConfig = {}) {
  return function securityMiddleware(
    handler: (request: NextRequest, context?: any) => Promise<NextResponse>
  ) {
    return async (request: NextRequest, context?: any) => {
      try {
        // Handle OPTIONS request for CORS
        if (request.method === 'OPTIONS') {
          return new NextResponse(null, {
            status: 200,
            headers: {
              ...corsHeaders,
              ...securityHeaders,
            },
          })
        }

        // Check allowed methods
        if (config.allowedMethods && !config.allowedMethods.includes(request.method)) {
          return NextResponse.json(
            { error: 'Method not allowed' },
            { 
              status: 405,
              headers: {
                'Allow': config.allowedMethods.join(', '),
                ...securityHeaders,
              }
            }
          )
        }

        // Apply rate limiting
        if (config.rateLimitType) {
          const rateLimiter = rateLimits[config.rateLimitType]
          const rateLimitResponse = await rateLimiter(request)
          if (rateLimitResponse) {
            return rateLimitResponse
          }
        }

        // Authentication check
        let session = null
        if (config.requireAuth) {
          session = await getServerSession(authOptions)
          if (!session || !session.user) {
            throw new AuthenticationError('Authentication required')
          }
        }

        // Authorization check
        if (config.permissions && config.permissions.length > 0 && session) {
          const userRole = session.user.role
          const hasRequiredPermission = config.permissions.some(permission => 
            hasPermission(userRole, permission)
          )
          
          if (!hasRequiredPermission) {
            throw new AuthorizationError('Insufficient permissions for this action')
          }
        }

        // Input validation
        if (config.validateInput && ['POST', 'PUT', 'PATCH'].includes(request.method)) {
          try {
            const body = await request.json()
            config.validateInput.parse(body)
          } catch (error) {
            if (error instanceof z.ZodError) {
              return NextResponse.json(
                {
                  error: 'Validation error',
                  details: error.errors.map(err => ({
                    field: err.path.join('.'),
                    message: err.message,
                  })),
                },
                { status: 400, headers: securityHeaders }
              )
            }
            throw error
          }
        }

        // Execute the actual handler
        const response = await handler(request, context)

        // Add security headers to response
        Object.entries(securityHeaders).forEach(([key, value]) => {
          response.headers.set(key, value)
        })

        // Add CORS headers if not skipped
        if (!config.skipCors) {
          Object.entries(corsHeaders).forEach(([key, value]) => {
            response.headers.set(key, value)
          })
        }

        return response
      } catch (error) {
        return handleApiError(error, request)
      }
    }
  }
}

// Specific middleware functions for common patterns
export const requireAuth = withSecurity({ requireAuth: true })

export const requireAdmin = withSecurity({
  requireAuth: true,
  permissions: [Permission.ADMIN_USERS],
  rateLimitType: 'admin',
})

export const requireFreelancer = withSecurity({
  requireAuth: true,
  permissions: [Permission.CREATE_GIG],
  rateLimitType: 'api',
})

export const requireHirer = withSecurity({
  requireAuth: true,
  permissions: [Permission.CREATE_JOB],
  rateLimitType: 'api',
})

export const withUploadSecurity = withSecurity({
  requireAuth: true,
  rateLimitType: 'upload',
  allowedMethods: ['POST'],
})

export const withAuthSecurity = withSecurity({
  rateLimitType: 'auth',
  allowedMethods: ['POST'],
})

// Resource ownership check
export async function checkResourceOwnership(
  request: NextRequest,
  resourceType: 'job' | 'gig' | 'message' | 'payment',
  resourceId: string,
  allowAdmin: boolean = true
): Promise<boolean> {
  const session = await getServerSession(authOptions)
  if (!session) return false

  const userId = session.user.id
  const userRole = session.user.role

  // Admin bypass
  if (allowAdmin && userRole === 'ADMIN') {
    return true
  }

  // Check ownership based on resource type
  // This would typically query the database to check ownership
  // For now, we'll implement basic checks
  try {
    switch (resourceType) {
      case 'job':
        // Check if user is the job creator
        // const job = await prisma.job.findUnique({ where: { id: resourceId } })
        // return job?.hirerId === userId
        return true // Placeholder
      
      case 'gig':
        // Check if user is the gig creator
        // const gig = await prisma.gig.findUnique({ where: { id: resourceId } })
        // return gig?.freelancerId === userId
        return true // Placeholder
      
      case 'message':
        // Check if user is sender or receiver
        // const message = await prisma.message.findUnique({ where: { id: resourceId } })
        // return message?.senderId === userId || message?.receiverId === userId
        return true // Placeholder
      
      case 'payment':
        // Check if user is involved in the payment
        // const payment = await prisma.payment.findUnique({ where: { id: resourceId } })
        // return payment?.fromUserId === userId || payment?.toUserId === userId
        return true // Placeholder
      
      default:
        return false
    }
  } catch (error) {
    console.error('Error checking resource ownership:', error)
    return false
  }
}

// Input sanitization helpers
export function sanitizeHtml(input: string): string {
  return input
    .replace(/<script[^>]*>.*?<\/script>/gi, '')
    .replace(/<iframe[^>]*>.*?<\/iframe>/gi, '')
    .replace(/<object[^>]*>.*?<\/object>/gi, '')
    .replace(/<embed[^>]*>/gi, '')
    .replace(/javascript:/gi, '')
    .replace(/on\w+\s*=/gi, '')
}

export function sanitizeFileName(fileName: string): string {
  return fileName
    .replace(/[^a-zA-Z0-9.-]/g, '_')
    .replace(/\.{2,}/g, '.')
    .substring(0, 255)
}

// IP address extraction
export function getClientIP(request: NextRequest): string {
  const forwarded = request.headers.get('x-forwarded-for')
  const realIP = request.headers.get('x-real-ip')
  const cfIP = request.headers.get('cf-connecting-ip')
  
  if (forwarded) return forwarded.split(',')[0].trim()
  if (realIP) return realIP
  if (cfIP) return cfIP
  
  return request.ip || 'unknown'
}

// CSRF token validation (for forms)
export function generateCSRFToken(): string {
  return crypto.randomUUID()
}

export function validateCSRFToken(provided: string, expected: string): boolean {
  return provided === expected
}
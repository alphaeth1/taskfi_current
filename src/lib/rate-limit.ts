import { NextRequest, NextResponse } from 'next/server'

// Simple in-memory rate limiter for development
// In production, use Redis or a proper rate limiting service
interface RateLimitStore {
  [key: string]: {
    count: number
    resetTime: number
  }
}

const store: RateLimitStore = {}

export interface RateLimitConfig {
  windowMs: number // Time window in milliseconds
  maxRequests: number // Maximum requests per window
  message?: string
  skipSuccessfulRequests?: boolean
}

export function createRateLimiter(config: RateLimitConfig) {
  return async (request: NextRequest) => {
    const ip = getClientIP(request)
    const key = `${ip}:${request.nextUrl.pathname}`
    const now = Date.now()
    
    // Clean up expired entries
    if (store[key] && now > store[key].resetTime) {
      delete store[key]
    }
    
    // Initialize or update counter
    if (!store[key]) {
      store[key] = {
        count: 1,
        resetTime: now + config.windowMs
      }
    } else {
      store[key].count++
    }
    
    // Check if limit exceeded
    if (store[key].count > config.maxRequests) {
      return NextResponse.json(
        { 
          error: config.message || 'Too many requests',
          retryAfter: Math.ceil((store[key].resetTime - now) / 1000)
        },
        { 
          status: 429,
          headers: {
            'Retry-After': Math.ceil((store[key].resetTime - now) / 1000).toString(),
            'X-RateLimit-Limit': config.maxRequests.toString(),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': new Date(store[key].resetTime).toISOString()
          }
        }
      )
    }
    
    return null // Allow request to proceed
  }
}

// Common rate limit configurations
export const rateLimits = {
  // Strict limits for auth endpoints
  auth: createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5,
    message: 'Too many authentication attempts, please try again later'
  }),
  
  // Medium limits for API endpoints
  api: createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 100,
    message: 'API rate limit exceeded'
  }),
  
  // Strict limits for file uploads
  upload: createRateLimiter({
    windowMs: 60 * 60 * 1000, // 1 hour
    maxRequests: 20,
    message: 'Upload rate limit exceeded'
  }),
  
  // Very strict for admin operations
  admin: createRateLimiter({
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 50,
    message: 'Admin operation rate limit exceeded'
  })
}

function getClientIP(request: NextRequest): string {
  // Check various headers for the real IP
  const forwarded = request.headers.get('x-forwarded-for')
  const realIP = request.headers.get('x-real-ip')
  const cfIP = request.headers.get('cf-connecting-ip')
  
  if (forwarded) {
    return forwarded.split(',')[0].trim()
  }
  
  if (realIP) {
    return realIP
  }
  
  if (cfIP) {
    return cfIP
  }
  
  // Fallback to connection IP (may not work in all environments)
  return request.ip || 'unknown'
}

// Utility function to apply rate limiting to API routes
export function withRateLimit(
  rateLimiter: (request: NextRequest) => Promise<NextResponse | null>,
  handler: (request: NextRequest, context?: any) => Promise<NextResponse>
) {
  return async (request: NextRequest, context?: any) => {
    // Apply rate limiting
    const rateLimitResponse = await rateLimiter(request)
    if (rateLimitResponse) {
      return rateLimitResponse
    }
    
    // Proceed with the actual handler
    return handler(request, context)
  }
}

// Clean up expired entries periodically (run every 10 minutes)
if (typeof window === 'undefined') {
  setInterval(() => {
    const now = Date.now()
    Object.keys(store).forEach(key => {
      if (store[key] && now > store[key].resetTime) {
        delete store[key]
      }
    })
  }, 10 * 60 * 1000)
}
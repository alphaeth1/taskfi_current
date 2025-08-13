import { NextResponse } from 'next/server'
import { ZodError } from 'zod'
import { Prisma } from '@prisma/client'

// Custom error classes
export class AppError extends Error {
  constructor(
    public message: string,
    public statusCode: number = 500,
    public code?: string,
    public field?: string
  ) {
    super(message)
    this.name = 'AppError'
  }
}

export class ValidationError extends AppError {
  constructor(message: string, field?: string) {
    super(message, 400, 'VALIDATION_ERROR', field)
    this.name = 'ValidationError'
  }
}

export class AuthenticationError extends AppError {
  constructor(message: string = 'Authentication required') {
    super(message, 401, 'AUTHENTICATION_ERROR')
    this.name = 'AuthenticationError'
  }
}

export class AuthorizationError extends AppError {
  constructor(message: string = 'Insufficient permissions') {
    super(message, 403, 'AUTHORIZATION_ERROR')
    this.name = 'AuthorizationError'
  }
}

export class NotFoundError extends AppError {
  constructor(message: string = 'Resource not found') {
    super(message, 404, 'NOT_FOUND_ERROR')
    this.name = 'NotFoundError'
  }
}

export class ConflictError extends AppError {
  constructor(message: string) {
    super(message, 409, 'CONFLICT_ERROR')
    this.name = 'ConflictError'
  }
}

export class RateLimitError extends AppError {
  constructor(message: string = 'Too many requests', retryAfter?: number) {
    super(message, 429, 'RATE_LIMIT_ERROR')
    this.name = 'RateLimitError'
    if (retryAfter) {
      this.message += `. Retry after ${retryAfter} seconds`
    }
  }
}

export class ExternalServiceError extends AppError {
  constructor(service: string, message: string = 'External service error') {
    super(`${service}: ${message}`, 502, 'EXTERNAL_SERVICE_ERROR')
    this.name = 'ExternalServiceError'
  }
}

// Error response interface
interface ErrorResponse {
  error: string
  message: string
  code?: string
  field?: string
  details?: any
  timestamp: string
  path?: string
}

// Main error handler function
export function handleApiError(error: unknown, request?: Request): NextResponse<ErrorResponse> {
  let statusCode = 500
  let message = 'Internal server error'
  let code = 'INTERNAL_ERROR'
  let field: string | undefined
  let details: any = undefined

  // Handle different error types
  if (error instanceof AppError) {
    statusCode = error.statusCode
    message = error.message
    code = error.code || 'APP_ERROR'
    field = error.field
  } else if (error instanceof ZodError) {
    statusCode = 400
    message = 'Validation error'
    code = 'VALIDATION_ERROR'
    details = error.errors.map(err => ({
      field: err.path.join('.'),
      message: err.message,
      code: err.code,
    }))
  } else if (error instanceof Prisma.PrismaClientKnownRequestError) {
    statusCode = 400
    code = 'DATABASE_ERROR'
    
    switch (error.code) {
      case 'P2002':
        message = 'A record with this information already exists'
        if (error.meta?.target) {
          field = Array.isArray(error.meta.target) 
            ? error.meta.target[0] as string 
            : error.meta.target as string
          message = `${field} already exists`
        }
        break
      case 'P2025':
        statusCode = 404
        message = 'Record not found'
        break
      case 'P2003':
        message = 'Invalid reference to related record'
        break
      case 'P2014':
        message = 'Invalid ID provided'
        break
      default:
        message = 'Database operation failed'
    }
  } else if (error instanceof Prisma.PrismaClientUnknownRequestError) {
    statusCode = 500
    message = 'Database connection error'
    code = 'DATABASE_CONNECTION_ERROR'
  } else if (error instanceof Prisma.PrismaClientValidationError) {
    statusCode = 400
    message = 'Invalid data provided'
    code = 'DATABASE_VALIDATION_ERROR'
  } else if (error instanceof Error) {
    message = error.message
    
    // Handle specific known errors
    if (error.message.includes('Rate limit')) {
      statusCode = 429
      code = 'RATE_LIMIT_ERROR'
    } else if (error.message.includes('Unauthorized')) {
      statusCode = 401
      code = 'AUTHENTICATION_ERROR'
    } else if (error.message.includes('Forbidden')) {
      statusCode = 403
      code = 'AUTHORIZATION_ERROR'
    } else if (error.message.includes('Not found')) {
      statusCode = 404
      code = 'NOT_FOUND_ERROR'
    }
  }

  // Log error for monitoring (in production, send to logging service)
  console.error('API Error:', {
    error: error instanceof Error ? error.message : error,
    stack: error instanceof Error ? error.stack : undefined,
    statusCode,
    code,
    field,
    path: request?.url,
    timestamp: new Date().toISOString(),
  })

  // Create error response
  const errorResponse: ErrorResponse = {
    error: getErrorTitle(statusCode),
    message: sanitizeErrorMessage(message, statusCode),
    code,
    field,
    details,
    timestamp: new Date().toISOString(),
    path: request?.url,
  }

  // Remove undefined fields
  Object.keys(errorResponse).forEach(key => {
    if (errorResponse[key as keyof ErrorResponse] === undefined) {
      delete errorResponse[key as keyof ErrorResponse]
    }
  })

  return NextResponse.json(errorResponse, { 
    status: statusCode,
    headers: {
      'Content-Type': 'application/json',
    }
  })
}

// Utility functions
function getErrorTitle(statusCode: number): string {
  switch (statusCode) {
    case 400: return 'Bad Request'
    case 401: return 'Unauthorized'
    case 403: return 'Forbidden'
    case 404: return 'Not Found'
    case 409: return 'Conflict'
    case 422: return 'Unprocessable Entity'
    case 429: return 'Too Many Requests'
    case 500: return 'Internal Server Error'
    case 502: return 'Bad Gateway'
    case 503: return 'Service Unavailable'
    default: return 'Error'
  }
}

function sanitizeErrorMessage(message: string, statusCode: number): string {
  // In production, don't expose internal error details
  if (process.env.NODE_ENV === 'production' && statusCode >= 500) {
    return 'An internal error occurred. Please try again later.'
  }
  return message
}

// Success response helper
export function successResponse<T>(
  data: T, 
  message: string = 'Success', 
  statusCode: number = 200
): NextResponse {
  return NextResponse.json({
    success: true,
    message,
    data,
    timestamp: new Date().toISOString(),
  }, { status: statusCode })
}

// Async error handler wrapper for API routes
export function asyncHandler<T extends any[], R>(
  handler: (...args: T) => Promise<R>
) {
  return async (...args: T): Promise<R | NextResponse> => {
    try {
      return await handler(...args)
    } catch (error) {
      return handleApiError(error)
    }
  }
}

// Validation error handler
export function handleValidationErrors(errors: ZodError): ValidationError {
  const firstError = errors.errors[0]
  const field = firstError.path.join('.')
  const message = firstError.message
  return new ValidationError(`${field}: ${message}`, field)
}

// Database constraint error handler
export function handleDatabaseConstraintError(error: Prisma.PrismaClientKnownRequestError): AppError {
  switch (error.code) {
    case 'P2002': {
      const target = error.meta?.target as string[] | string
      const field = Array.isArray(target) ? target[0] : target
      return new ConflictError(`${field} already exists`)
    }
    case 'P2025':
      return new NotFoundError('Record not found')
    case 'P2003':
      return new ValidationError('Invalid reference to related record')
    case 'P2014':
      return new ValidationError('Invalid ID provided')
    default:
      return new AppError('Database operation failed', 400, error.code)
  }
}

// External service error handler
export function handleExternalServiceError(service: string, error: Error): ExternalServiceError {
  return new ExternalServiceError(service, error.message)
}

// Rate limit error with retry after
export function createRateLimitError(retryAfterSeconds: number): RateLimitError {
  return new RateLimitError('Rate limit exceeded', retryAfterSeconds)
}

// Helper to check if error is a specific type
export function isAppError(error: unknown): error is AppError {
  return error instanceof AppError
}

export function isValidationError(error: unknown): error is ValidationError {
  return error instanceof ValidationError
}

export function isAuthenticationError(error: unknown): error is AuthenticationError {
  return error instanceof AuthenticationError
}

export function isAuthorizationError(error: unknown): error is AuthorizationError {
  return error instanceof AuthorizationError
}

export function isNotFoundError(error: unknown): error is NotFoundError {
  return error instanceof NotFoundError
}

// Error codes enum for consistent error handling
export enum ErrorCodes {
  VALIDATION_ERROR = 'VALIDATION_ERROR',
  AUTHENTICATION_ERROR = 'AUTHENTICATION_ERROR',
  AUTHORIZATION_ERROR = 'AUTHORIZATION_ERROR',
  NOT_FOUND_ERROR = 'NOT_FOUND_ERROR',
  CONFLICT_ERROR = 'CONFLICT_ERROR',
  RATE_LIMIT_ERROR = 'RATE_LIMIT_ERROR',
  DATABASE_ERROR = 'DATABASE_ERROR',
  EXTERNAL_SERVICE_ERROR = 'EXTERNAL_SERVICE_ERROR',
  INTERNAL_ERROR = 'INTERNAL_ERROR',
}
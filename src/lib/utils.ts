import { clsx, type ClassValue } from "clsx"
import { twMerge } from "tailwind-merge"

export function cn(...inputs: ClassValue[]) {
  return twMerge(clsx(inputs))
}

// Generate username from name
export function generateUsername(name: string): string {
  const cleanName = name.toLowerCase().replace(/[^a-z0-9]/g, '')
  const randomSuffix = Math.floor(Math.random() * 10000)
  return `${cleanName}${randomSuffix}`
}

// Debounce function for delayed execution
export function debounce<T extends (...args: any[]) => any>(
  func: T,
  delay: number
): (...args: Parameters<T>) => void {
  let timeoutId: NodeJS.Timeout
  return (...args: Parameters<T>) => {
    clearTimeout(timeoutId)
    timeoutId = setTimeout(() => func(...args), delay)
  }
}

// Generate secure nonce for wallet verification
export function generateNonce(): string {
  if (typeof window !== 'undefined' && window.crypto && window.crypto.getRandomValues) {
    const array = new Uint8Array(32)
    window.crypto.getRandomValues(array)
    return Array.from(array, byte => byte.toString(16).padStart(2, '0')).join('')
  }
  // Fallback for server-side (still better than Math.random)
  const crypto = require('crypto')
  return crypto.randomBytes(32).toString('hex')
}
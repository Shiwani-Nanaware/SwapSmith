import { NextRequest, NextResponse } from 'next/server';

interface RateLimitConfig {
  windowMs: number; // Time window in milliseconds
  maxRequests: number; // Max requests per window
  keyGenerator?: (req: NextRequest) => string; // Custom key generator
}

interface RateLimitEntry {
  count: number;
  resetTime: number;
}

// In-memory store (use Redis in production)
const rateLimitStore = new Map<string, RateLimitEntry>();

/**
 * Rate limiting middleware for API routes
 */
export function rateLimit(config: RateLimitConfig) {
  return async (req: NextRequest): Promise<NextResponse | null> => {
    const now = Date.now();
    const key = config.keyGenerator ? config.keyGenerator(req) : getDefaultKey(req);
    
    // Clean up expired entries
    if (rateLimitStore.size > 10000) {
      for (const [k, entry] of rateLimitStore.entries()) {
        if (now > entry.resetTime) {
          rateLimitStore.delete(k);
        }
      }
    }
    
    const entry = rateLimitStore.get(key);
    
    if (!entry || now > entry.resetTime) {
      // First request or window expired
      rateLimitStore.set(key, {
        count: 1,
        resetTime: now + config.windowMs
      });
      return null; // Allow request
    }
    
    if (entry.count >= config.maxRequests) {
      // Rate limit exceeded
      return NextResponse.json(
        { 
          error: 'Rate limit exceeded',
          retryAfter: Math.ceil((entry.resetTime - now) / 1000)
        },
        { 
          status: 429,
          headers: {
            'Retry-After': Math.ceil((entry.resetTime - now) / 1000).toString(),
            'X-RateLimit-Limit': config.maxRequests.toString(),
            'X-RateLimit-Remaining': '0',
            'X-RateLimit-Reset': entry.resetTime.toString()
          }
        }
      );
    }
    
    // Increment counter
    entry.count++;
    rateLimitStore.set(key, entry);
    
    return null; // Allow request
  };
}

function getDefaultKey(req: NextRequest): string {
  // Use IP address or user ID if available
  const forwarded = req.headers.get('x-forwarded-for');
  const ip = forwarded ? forwarded.split(',')[0] : req.headers.get('x-real-ip') || 'unknown';
  const userAgent = req.headers.get('user-agent') || '';
  return `${ip}:${userAgent.slice(0, 50)}`;
}

// Predefined rate limit configurations
export const rateLimitConfigs = {
  // Strict limits for authentication endpoints
  auth: {
    windowMs: 15 * 60 * 1000, // 15 minutes
    maxRequests: 5 // 5 attempts per 15 minutes
  },
  
  // Moderate limits for API endpoints
  api: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 60 // 60 requests per minute
  },
  
  // Stricter limits for write operations
  write: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 20 // 20 writes per minute
  },
  
  // Very strict for sensitive operations
  sensitive: {
    windowMs: 60 * 1000, // 1 minute
    maxRequests: 5 // 5 requests per minute
  }
};

/**
 * Wrapper for API route handlers with rate limiting
 */
export function withRateLimit<T extends any[]>(
  handler: (...args: T) => Promise<NextResponse>,
  config: RateLimitConfig
) {
  return async (...args: T): Promise<NextResponse> => {
    const req = args[0] as NextRequest;
    
    const rateLimitResponse = await rateLimit(config)(req);
    if (rateLimitResponse) {
      return rateLimitResponse;
    }
    
    return handler(...args);
  };
}
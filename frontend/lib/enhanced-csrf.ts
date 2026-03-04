import { NextRequest, NextResponse } from 'next/server';
import { cookies } from 'next/headers';
import crypto from 'crypto';

/**
 * Enhanced CSRF protection with token-based validation
 * for App Router (app/api/*) endpoints
 */

const CSRF_TOKEN_HEADER = 'x-csrf-token';
const CSRF_COOKIE_NAME = 'csrf-token';
const CSRF_SECRET = process.env.CSRF_SECRET || 'default-csrf-secret-change-in-production';

/**
 * Generate a CSRF token
 */
export function generateCSRFToken(): string {
  return crypto.randomBytes(32).toString('hex');
}

/**
 * Verify CSRF token from request
 */
export function verifyCSRFToken(request: NextRequest): boolean {
  const method = request.method;
  
  // Skip CSRF for safe methods
  if (['GET', 'HEAD', 'OPTIONS'].includes(method)) {
    return true;
  }
  
  const tokenFromHeader = request.headers.get(CSRF_TOKEN_HEADER);
  const tokenFromCookie = request.cookies.get(CSRF_COOKIE_NAME)?.value;
  
  if (!tokenFromHeader || !tokenFromCookie) {
    return false;
  }
  
  // Constant-time comparison to prevent timing attacks
  return crypto.timingSafeEqual(
    Buffer.from(tokenFromHeader, 'hex'),
    Buffer.from(tokenFromCookie, 'hex')
  );
}

/**
 * CSRF middleware for App Router
 */
export function withCSRFProtection(
  handler: (request: NextRequest, ...args: any[]) => Promise<NextResponse>
) {
  return async (request: NextRequest, ...args: any[]): Promise<NextResponse> => {
    // Verify CSRF token for state-changing requests
    if (!verifyCSRFToken(request)) {
      return NextResponse.json(
        { error: 'CSRF token validation failed' },
        { status: 403 }
      );
    }
    
    return handler(request, ...args);
  };
}

/**
 * Set CSRF token in cookie (call this in your layout or auth flow)
 */
export async function setCSRFToken(): Promise<string> {
  const token = generateCSRFToken();
  const cookieStore = await cookies();
  
  cookieStore.set(CSRF_COOKIE_NAME, token, {
    httpOnly: false, // Must be accessible to JavaScript for header inclusion
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    path: '/',
    maxAge: 60 * 60 * 24 // 24 hours
  });
  
  return token;
}

/**
 * Get CSRF token from cookies
 */
export async function getCSRFToken(): Promise<string | null> {
  const cookieStore = await cookies();
  return cookieStore.get(CSRF_COOKIE_NAME)?.value || null;
}

/**
 * Enhanced origin validation with more strict checks
 */
export function validateOrigin(request: NextRequest): boolean {
  const origin = request.headers.get('origin');
  const referer = request.headers.get('referer');
  const host = request.headers.get('host');
  
  const allowedOrigins = process.env.ALLOWED_ORIGINS?.split(',') || [
    'http://localhost:3000',
    'http://localhost:3001',
    'https://swapsmith.ai',
    'https://www.swapsmith.ai'
  ];
  
  // For same-origin requests, check host header
  if (!origin && referer) {
    try {
      const refererUrl = new URL(referer);
      return refererUrl.host === host;
    } catch {
      return false;
    }
  }
  
  // Check origin against allowed list
  if (origin) {
    return allowedOrigins.includes(origin);
  }
  
  return false;
}

/**
 * Complete CSRF protection combining token and origin validation
 */
export function completeCSRFProtection(request: NextRequest): boolean {
  return verifyCSRFToken(request) && validateOrigin(request);
}
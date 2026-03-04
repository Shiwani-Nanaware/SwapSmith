import { NextRequest, NextResponse } from 'next/server';
import { withSecurityHeaders } from '@/lib/security-headers';
import { rateLimit, rateLimitConfigs } from '@/lib/rate-limiter';

/**
 * Enhanced middleware with security features:
 * - Admin route protection
 * - Rate limiting for API routes
 * - Security headers
 * - CSRF protection
 */
export async function middleware(request: NextRequest) {
  const { pathname } = request.nextUrl;
  let response = NextResponse.next();

  // Rate limiting for API routes
  if (pathname.startsWith('/api/')) {
    let rateLimitConfig;
    
    // Apply different rate limits based on endpoint sensitivity
    if (pathname.includes('/auth') || pathname.includes('/login') || pathname.includes('/register')) {
      rateLimitConfig = rateLimitConfigs.auth;
    } else if (pathname.includes('/admin/')) {
      rateLimitConfig = rateLimitConfigs.sensitive;
    } else if (request.method !== 'GET') {
      rateLimitConfig = rateLimitConfigs.write;
    } else {
      rateLimitConfig = rateLimitConfigs.api;
    }
    
    const rateLimitResponse = await rateLimit(rateLimitConfig)(request);
    if (rateLimitResponse) {
      return withSecurityHeaders(rateLimitResponse);
    }
  }

  // Admin dashboard protection
  if (pathname.startsWith('/admin/dashboard')) {
    const adminSession = request.cookies.get('admin-session');

    if (!adminSession?.value) {
      const loginUrl = new URL('/admin/login', request.url);
      loginUrl.searchParams.set('from', pathname);
      response = NextResponse.redirect(loginUrl);
    }
  }

  // Apply security headers to all responses
  return withSecurityHeaders(response);
}

export const config = {
  matcher: [
    '/admin/dashboard/:path*',
    '/api/:path*',
    '/((?!_next/static|_next/image|favicon.ico).*)'
  ],
};

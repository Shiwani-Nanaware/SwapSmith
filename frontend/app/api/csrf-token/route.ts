import { NextRequest, NextResponse } from 'next/server';
import { setCSRFToken } from '@/lib/enhanced-csrf';

/**
 * GET /api/csrf-token
 * Endpoint to generate and set CSRF token for client-side requests
 */
export async function GET(request: NextRequest) {
  try {
    const token = await setCSRFToken();
    
    return NextResponse.json({
      token,
      message: 'CSRF token generated and set in cookie'
    });
  } catch (error) {
    console.error('Error generating CSRF token:', error);
    return NextResponse.json(
      { error: 'Failed to generate CSRF token' },
      { status: 500 }
    );
  }
}
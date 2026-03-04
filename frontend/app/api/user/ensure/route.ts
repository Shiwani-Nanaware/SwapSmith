import { NextRequest, NextResponse } from 'next/server';
import { ensureUserExists } from '@/lib/user-service';
import { withRateLimit, rateLimitConfigs } from '@/lib/rate-limiter';
import { withCSRFProtection } from '@/lib/enhanced-csrf';

/**
 * POST /api/user/ensure
 * Ensures a user exists in the database and returns their ID
 */
export const POST = withRateLimit(withCSRFProtection(async (request: NextRequest) => {
  try {
    const { firebaseUid, walletAddress } = await request.json();

    if (!firebaseUid) {
      return NextResponse.json(
        { error: 'firebaseUid is required' },
        { status: 400 }
      );
    }

    const userId = await ensureUserExists(firebaseUid, walletAddress);

    return NextResponse.json({ 
      success: true, 
      userId 
    });
  } catch (error) {
    console.error('Error ensuring user:', error);
    return NextResponse.json(
      { error: 'Internal server error' },
      { status: 500 }
    );
  }
}), rateLimitConfigs.write);

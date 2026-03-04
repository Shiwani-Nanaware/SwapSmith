import { NextResponse } from 'next/server';
import { triggerManualRefresh } from '@/lib/price-refresh-cron';
import { withRateLimit, rateLimitConfigs } from '@/lib/rate-limiter';
import { withCSRFProtection } from '@/lib/enhanced-csrf';

/**
 * POST /api/prices/refresh - Manually trigger a price refresh
 * 
 * This endpoint allows manual triggering of the price refresh process.
 * Useful for testing or force-refreshing the cache.
 */
export const POST = withRateLimit(withCSRFProtection(async () => {
  try {
    console.log('[Prices Refresh API] Manual refresh triggered');
    
    // Trigger the manual refresh
    await triggerManualRefresh();
    
    return NextResponse.json({
      success: true,
      message: 'Price refresh completed successfully',
      timestamp: new Date().toISOString(),
    });
    
  } catch (error) {
    console.error('[Prices Refresh API] Error during manual refresh:', error);
    return NextResponse.json(
      { 
        success: false,
        error: 'Failed to refresh prices',
        details: error instanceof Error ? error.message : 'Unknown error'
      },
      { status: 500 }
    );
  }
}), rateLimitConfigs.write);

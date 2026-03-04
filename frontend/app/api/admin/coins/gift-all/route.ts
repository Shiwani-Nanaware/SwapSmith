import { NextResponse } from 'next/server';
import { verifyAdminToken } from '@/lib/adminAuth';
import { giftAllUsers } from '@/lib/admin-service';
import { withRateLimit, rateLimitConfigs } from '@/lib/rate-limiter';
import { withCSRFProtection } from '@/lib/enhanced-csrf';

export const POST = withRateLimit(withCSRFProtection(async (req: Request) => {
  try {
    const authHeader = req.headers.get('authorization') ?? '';
    const admin = await verifyAdminToken(authHeader);
    if (!admin) {
      return NextResponse.json({ error: 'Unauthorized' }, { status: 401 });
    }

    const body = await req.json().catch(() => ({}));
    const amount = Number(body.amount);
    if (!amount || amount <= 0 || !Number.isFinite(amount)) {
      return NextResponse.json({ error: 'Invalid amount' }, { status: 400 });
    }

    const result = await giftAllUsers({
      adminId:   admin.uid,
      adminEmail: admin.email ?? 'unknown',
      amount,
      note:      body.note ?? `Broadcast gift of ${amount} coins`,
    });

    return NextResponse.json({ ok: true, ...result });
  } catch (err) {
    console.error('[admin/coins/gift-all] error:', err);
    return NextResponse.json({ error: 'Internal server error' }, { status: 500 });
  }
}), rateLimitConfigs.sensitive);

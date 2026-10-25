const corsHeaders = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Headers': 'apikey, authorization, content-type',
  'Access-Control-Allow-Methods': 'POST, OPTIONS',
  'Content-Type': 'application/json',
};

function json(body: unknown, status = 200) {
  return new Response(JSON.stringify(body), { status, headers: corsHeaders });
}

Deno.serve(async (request) => {
  if (request.method === 'OPTIONS') return new Response('ok', { headers: corsHeaders });
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);

  const supabaseUrl = Deno.env.get('SUPABASE_URL') || '';
  const publishableKey = Deno.env.get('SUPABASE_ANON_KEY') || '';
  const serviceKey = Deno.env.get('SUPABASE_SERVICE_ROLE_KEY') || '';
  if (!supabaseUrl || !publishableKey || !serviceKey) return json({ error: 'server_configuration' }, 500);

  let input: { email?: string; password?: string; deviceId?: string; captchaToken?: string };
  try {
    input = await request.json();
  } catch {
    return json({ error: 'invalid_request' }, 400);
  }

  const email = String(input.email || '').trim().toLowerCase();
  const password = String(input.password || '');
  const deviceId = String(input.deviceId || '').trim();
  const captchaToken = String(input.captchaToken || '').trim();
  if (!email || !password || !deviceId || !captchaToken || deviceId.length > 200 || captchaToken.length > 4096) {
    return json({ error: 'invalid_request' }, 400);
  }

  const serviceHeaders = {
    apikey: serviceKey,
    Authorization: `Bearer ${serviceKey}`,
    'Content-Type': 'application/json',
  };
  const lockQuery = new URL(`${supabaseUrl}/rest/v1/lcb_login_locks`);
  lockQuery.searchParams.set('select', 'failures,locked_until');
  lockQuery.searchParams.set('email', `eq.${email}`);
  lockQuery.searchParams.set('device_id', `eq.${deviceId}`);
  lockQuery.searchParams.set('limit', '1');
  let lockResponse: Response | null = null;
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      lockResponse = await fetch(lockQuery, { headers: serviceHeaders });
      if (lockResponse.ok) break;
    } catch (_) {
      // A transient REST/network failure should get one quick retry.
    }
  }
  if (!lockResponse || !lockResponse.ok) return json({ error: 'lock_check_failed' }, 500);
  const rows = await lockResponse.json();
  const activeLock = rows[0];
  const lockedUntil = activeLock?.locked_until ? Date.parse(activeLock.locked_until) : 0;
  if (lockedUntil > Date.now()) {
    return json({ error: 'device_locked', retryAfter: Math.ceil((lockedUntil - Date.now()) / 1000) }, 429);
  }

  const authResponse = await fetch(`${supabaseUrl}/auth/v1/token?grant_type=password`, {
    method: 'POST',
    headers: { apikey: publishableKey, 'Content-Type': 'application/json' },
    body: JSON.stringify({
      email,
      password,
      gotrue_meta_security: { captcha_token: captchaToken },
    }),
  });

  if (authResponse.ok) {
    const deleteLock = new URL(`${supabaseUrl}/rest/v1/lcb_login_locks`);
    deleteLock.searchParams.set('email', `eq.${email}`);
    deleteLock.searchParams.set('device_id', `eq.${deviceId}`);
    const deleteResponse = await fetch(deleteLock, { method: 'DELETE', headers: serviceHeaders });
    if (!deleteResponse.ok) return json({ error: 'lock_clear_failed' }, 500);
    return new Response(await authResponse.text(), { status: 200, headers: corsHeaders });
  }

  let authError: { error_code?: string; code?: string } = {};
  try { authError = await authResponse.json(); } catch { /* use generic error */ }
  const errorCode = authError.error_code || authError.code || '';
  if (errorCode !== 'invalid_credentials') return json({ error: 'login_failed' }, authResponse.status);

  const failureResponse = await fetch(`${supabaseUrl}/rest/v1/rpc/lcb_record_login_failure`, {
    method: 'POST',
    headers: serviceHeaders,
    body: JSON.stringify({ p_email: email, p_device_id: deviceId }),
  });
  if (!failureResponse.ok) return json({ error: 'failure_record_failed' }, 500);
  const failureRows = await failureResponse.json();
  const failure = failureRows[0] || { failures: 1, locked_until: null };
  const failureLockUntil = failure.locked_until ? Date.parse(failure.locked_until) : 0;
  if (failureLockUntil > Date.now()) {
    return json({ error: 'device_locked', retryAfter: Math.ceil((failureLockUntil - Date.now()) / 1000) }, 429);
  }
  return json({ error: 'invalid_credentials', remainingAttempts: Math.max(0, 5 - Number(failure.failures || 0)) }, 401);
});

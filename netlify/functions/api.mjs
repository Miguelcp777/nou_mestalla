/**
 * API de la base de datos de la penya (Netlify Functions + Netlify Blobs).
 *
 * El servidor NUNCA ve datos en claro: cada socio cifra sus datos en su navegador con la
 * clave pública del capitán (RSA-OAEP + AES-GCM). La clave privada se guarda cifrada con
 * la contraseña del capitán (PBKDF2 + AES-GCM) y solo se descifra en su navegador.
 *
 * Rutas:
 *   GET  /api/config    → estado público (configurada, clave pública, sal de autenticación)
 *   POST /api/setup     → configuración inicial (requiere SETUP_TOKEN, solo una vez)
 *   POST /api/submit    → un socio envía (o actualiza) un registro cifrado
 *   POST /api/withdraw  → un socio retira su registro con su token
 *   POST /api/admin     → acciones del capitán (login | delete | purge), con authToken
 *   POST /api/reset     → borra todo, incluida la configuración (requiere SETUP_TOKEN)
 */
import { getStore } from '@netlify/blobs';
import { createHash, randomBytes, randomUUID, timingSafeEqual } from 'node:crypto';

const MAX_BODY = 48 * 1024;
const MAX_RECORDS = 500;

const json = (data, status = 200) => new Response(JSON.stringify(data), {
  status,
  headers: { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' }
});
const sha = s => createHash('sha256').update(String(s)).digest('hex');
const same = (a, b) => {
  const A = Buffer.from(String(a)), B = Buffer.from(String(b));
  return A.length === B.length && timingSafeEqual(A, B);
};
const isB64 = (s, max) => typeof s === 'string' && s.length > 0 && s.length <= max && /^[A-Za-z0-9+/=_-]+$/.test(s);
const isIter = n => Number.isInteger(n) && n >= 100000 && n <= 5000000;
const normCode = c => String(c ?? '').trim().toUpperCase();
const sleep = ms => new Promise(r => setTimeout(r, ms));
const validPayload = p => p && isB64(p.wk, 1200) && isB64(p.iv, 40) && isB64(p.ct, 40000);

/* ---------- Limitador de intentos por IP ---------- */
const tKey = ip => 'throttle/' + sha(ip || 'desconocida').slice(0, 32);
async function lockedFor(store, ip) {
  const t = await store.get(tKey(ip), { type: 'json' });
  return t && t.until > Date.now() ? Math.ceil((t.until - Date.now()) / 1000) : 0;
}
async function registerFail(store, ip) {
  const now = Date.now();
  let t = (await store.get(tKey(ip), { type: 'json' })) || { n: 0, until: 0, last: 0 };
  if (now - (t.last || 0) > 60 * 60e3) t = { n: 0, until: 0 }; // los fallos caducan tras 1 h sin intentos
  t.n += 1; t.last = now;
  if (t.n >= 5) t.until = now + Math.min(60 * 60e3, 60e3 * 2 ** (t.n - 5)); // 1, 2, 4… min (máx. 1 h)
  await store.setJSON(tKey(ip), t);
  await sleep(600);
}
const clearFails = (store, ip) => store.delete(tKey(ip));

async function allRecords(store) {
  const { blobs } = await store.list({ prefix: 'rec/' });
  const out = await Promise.all(blobs.map(b => store.get(b.key, { type: 'json' })));
  return out.filter(Boolean);
}

export default async (req, context) => {
  const store = getStore({ name: 'penya', consistency: 'strong' });
  const route = new URL(req.url).pathname.replace(/^\/api\/?/, '').replace(/\/(index\.html?)?$/, '');
  const ip = context.ip;
  const setupToken = Netlify.env.get('SETUP_TOKEN');

  try {
    if (req.method === 'GET' && route === 'config') {
      const c = await store.get('config', { type: 'json' });
      return json(c ? { configured: true, publicKey: c.publicKey, authSalt: c.authSalt, authIter: c.authIter } : { configured: false });
    }
    if (req.method !== 'POST') return json({ error: 'Método no permitido' }, 405);

    const raw = await req.text();
    if (raw.length > MAX_BODY) return json({ error: 'Petición demasiado grande' }, 413);
    let body;
    try { body = JSON.parse(raw); } catch { return json({ error: 'JSON no válido' }, 400); }

    switch (route) {
      case 'setup': {
        if (!setupToken) return json({ error: 'Falta configurar SETUP_TOKEN en Netlify' }, 503);
        const wait = await lockedFor(store, ip);
        if (wait) return json({ error: `Demasiados intentos. Espera ${wait} s.` }, 429);
        if (!same(body.setupToken, setupToken)) { await registerFail(store, ip); return json({ error: 'Token de configuración incorrecto' }, 403); }
        if (await store.get('config')) return json({ error: 'La base de datos ya está configurada' }, 409);
        const e = body.encPriv || {};
        const code = normCode(body.code);
        if (!isB64(body.publicKey, 1000) || !isB64(e.salt, 64) || !isB64(e.iv, 40) || !isB64(e.ct, 4000) || !isIter(e.iter) ||
            !isB64(body.authSalt, 64) || !isIter(body.authIter) || !isB64(body.authToken, 100) || code.length < 4 || code.length > 40) {
          return json({ error: 'Datos de configuración no válidos' }, 400);
        }
        await store.setJSON('config', {
          publicKey: body.publicKey,
          encPriv: { salt: e.salt, iv: e.iv, ct: e.ct, iter: e.iter },
          authSalt: body.authSalt, authIter: body.authIter, authHash: sha(body.authToken),
          codeHash: sha(code), createdAt: new Date().toISOString()
        });
        await clearFails(store, ip);
        return json({ ok: true });
      }

      case 'submit': {
        const c = await store.get('config', { type: 'json' });
        if (!c) return json({ error: 'El capitán aún no ha activado la recepción de datos' }, 409);
        const wait = await lockedFor(store, ip);
        if (wait) return json({ error: `Demasiados intentos. Espera ${wait} s.` }, 429);
        if (!same(sha(normCode(body.code)), c.codeHash)) { await registerFail(store, ip); return json({ error: 'Código de la penya incorrecto' }, 403); }
        if (!validPayload(body.payload)) return json({ error: 'Datos cifrados no válidos' }, 400);
        await clearFails(store, ip);
        const payload = { v: 1, wk: body.payload.wk, iv: body.payload.iv, ct: body.payload.ct };
        const now = new Date().toISOString();

        if (body.id && body.token) {
          const key = 'rec/' + String(body.id).replace(/[^a-zA-Z0-9-]/g, '');
          const old = await store.get(key, { type: 'json' });
          if (old && same(sha(body.token), old.tokenHash)) {
            await store.setJSON(key, { ...old, payload, updatedAt: now });
            return json({ ok: true, id: old.id, token: body.token, updated: true });
          }
          // Si ya no existe (p. ej. el capitán lo borró), se crea uno nuevo.
        }
        const { blobs } = await store.list({ prefix: 'rec/' });
        if (blobs.length >= MAX_RECORDS) return json({ error: 'Se ha alcanzado el máximo de registros' }, 507);
        const id = randomUUID(), token = randomBytes(24).toString('base64url');
        await store.setJSON('rec/' + id, { id, tokenHash: sha(token), createdAt: now, updatedAt: now, payload });
        return json({ ok: true, id, token, updated: false });
      }

      case 'withdraw': {
        const key = 'rec/' + String(body.id || '').replace(/[^a-zA-Z0-9-]/g, '');
        const old = await store.get(key, { type: 'json' });
        if (!old) return json({ ok: true, missing: true });
        if (!same(sha(body.token), old.tokenHash)) return json({ error: 'No autorizado' }, 403);
        await store.delete(key);
        return json({ ok: true });
      }

      case 'admin': {
        const c = await store.get('config', { type: 'json' });
        if (!c) return json({ error: 'La base de datos no está configurada' }, 409);
        const wait = await lockedFor(store, ip);
        if (wait) return json({ error: `Demasiados intentos. Espera ${wait} s.` }, 429);
        if (!isB64(body.authToken, 100) || !same(sha(body.authToken), c.authHash)) {
          await registerFail(store, ip);
          return json({ error: 'Contraseña incorrecta' }, 403);
        }
        await clearFails(store, ip);
        if (body.action === 'login') {
          const records = (await allRecords(store)).map(({ tokenHash, ...r }) => r);
          return json({ ok: true, encPriv: c.encPriv, records });
        }
        if (body.action === 'delete') {
          await store.delete('rec/' + String(body.id || '').replace(/[^a-zA-Z0-9-]/g, ''));
          return json({ ok: true });
        }
        if (body.action === 'purge') {
          const { blobs } = await store.list({ prefix: 'rec/' });
          await Promise.all(blobs.map(b => store.delete(b.key)));
          return json({ ok: true, deleted: blobs.length });
        }
        return json({ error: 'Acción desconocida' }, 400);
      }

      case 'reset': {
        if (!setupToken) return json({ error: 'Falta configurar SETUP_TOKEN en Netlify' }, 503);
        const wait = await lockedFor(store, ip);
        if (wait) return json({ error: `Demasiados intentos. Espera ${wait} s.` }, 429);
        if (!same(body.setupToken, setupToken)) { await registerFail(store, ip); return json({ error: 'Token de configuración incorrecto' }, 403); }
        const { blobs } = await store.list();
        await Promise.all(blobs.map(b => store.delete(b.key)));
        return json({ ok: true, deleted: blobs.length });
      }

      default:
        return json({ error: 'Ruta no encontrada' }, 404);
    }
  } catch (err) {
    console.error(err);
    return json({ error: 'Error interno del servidor' }, 500);
  }
};

export const config = { path: '/api/*' };

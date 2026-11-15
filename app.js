const STORAGE_KEY = 'control_parental_state_v3';
const DEVICE_FP_KEY = 'control_parental_device_fp_v1';
const UI_PREFS_KEY = 'control_parental_ui_v1';
const PASSWORD_PEPPER = 'JOSE_ALBERTO_CP_MASTER_2026'; // solo para la huella de la contraseña del panel

// La contraseña del panel del programador NO se guarda en texto plano: solo su huella (hash).
// Para cambiarla: abre la consola del navegador con la app cargada, ejecuta
//   hashMasterPassword('TU-NUEVA-CLAVE')
// y pega el resultado aquí.
const PROGRAMMER_MASTER_PASS_HASH = 'a04174ee00248536';

// Intervalo mínimo entre envíos de sincronización mientras un cronómetro está en marcha
const CLOUD_PUSH_MIN_INTERVAL_MS = 15000;

// ===== Utilidades de almacenamiento seguras =====
// localStorage puede lanzar excepciones (Safari en modo privado, cuota llena, almacenamiento bloqueado).
function safeStorageGet(key) {
  try { return window.localStorage.getItem(key); } catch (e) { return null; }
}

function safeStorageSet(key, value) {
  try {
    window.localStorage.setItem(key, value);
    return true;
  } catch (e) {
    console.warn('No se pudo guardar en el almacenamiento local:', e);
    return false;
  }
}

// structuredClone no existe en iOS < 15.4: alternativa compatible
const deepClone = typeof structuredClone === 'function'
  ? (obj) => structuredClone(obj)
  : (obj) => JSON.parse(JSON.stringify(obj));

// Fecha local AAAA-MM-DD (toISOString usa UTC y en España el "nuevo día" llegaba a la 1:00 o las 2:00)
function getLocalDateKey(ts = Date.now()) {
  const d = new Date(ts);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function getLocalMidnightTs(ts = Date.now()) {
  const d = new Date(ts);
  d.setHours(0, 0, 0, 0);
  return d.getTime();
}

function toSafeSeconds(value) {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : 0;
}

function randomToken(length) {
  const alphabet = 'ABCDEFGHJKLMNPQRSTUVWXYZ23456789';
  let out = '';
  if (window.crypto && typeof window.crypto.getRandomValues === 'function') {
    const bytes = new Uint8Array(length);
    window.crypto.getRandomValues(bytes);
    for (let i = 0; i < length; i++) out += alphabet[bytes[i] % alphabet.length];
  } else {
    for (let i = 0; i < length; i++) out += alphabet[Math.floor(Math.random() * alphabet.length)];
  }
  return out;
}

// Obtener o crear huella única e intransferible para este aparato (iPhone, iPad, Móvil/Tablet Android o PC)
let volatileDeviceFp = null;
function getOrCreateDeviceFingerprint() {
  let fp = safeStorageGet(DEVICE_FP_KEY);
  if (fp && /^DEV-[A-Z0-9-]{3,20}$/.test(fp)) return fp; // acepta también las huellas antiguas
  fp = volatileDeviceFp || `DEV-${randomToken(4)}-${randomToken(4)}`;
  volatileDeviceFp = fp;
  safeStorageSet(DEVICE_FP_KEY, fp);
  return fp;
}

const CURRENT_DEVICE_FP = getOrCreateDeviceFingerprint();

// =====================================================================
// LICENCIAS FIRMADAS DIGITALMENTE (ECDSA P-256 + SHA-256)
// ---------------------------------------------------------------------
// Las claves se firman con la CLAVE PRIVADA del programador, que NUNCA
// viaja dentro de la app (está en PROGRAMADOR-PRIVADO/ y no se incluye
// en el ZIP). La app solo contiene la CLAVE PÚBLICA, que sirve para
// comprobar firmas pero no para crearlas: leer este código no permite
// fabricar licencias.
// La verificación está escrita en JavaScript puro (sin WebCrypto) para
// que sea síncrona y funcione igual en https, en file:// y en iOS antiguos.
// =====================================================================

const LICENSE_PUBLIC_KEY_HEX =
  '047154b6d033fc85f23f8e2866c521db8b9225042195caba2a279b740c5e2a48c8' +
  '77d6e9acac7d7701983681dd8ccfe8f9297194f297d855d98a5e0a366aed9249';

const LICENSE_KEY_PREFIX = 'CP2';
const BASE32_ALPHABET = '0123456789ABCDEFGHJKMNPQRSTVWXYZ'; // Crockford: sin I, L, O, U

function normalizeHolderName(name) {
  return String(name || '').trim().toUpperCase().replace(/\s+/g, '-');
}

// Mensaje exacto que firma la herramienta del programador
function buildLicenseMessage(holder, maxDevices, maxChildren) {
  return `${LICENSE_KEY_PREFIX}|${holder}|${maxDevices}|${maxChildren}`;
}

function base32Decode(str) {
  const clean = String(str).toUpperCase().replace(/O/g, '0').replace(/[IL]/g, '1');
  const out = [];
  let buffer = 0;
  let bits = 0;
  for (const ch of clean) {
    const val = BASE32_ALPHABET.indexOf(ch);
    if (val === -1) return null;
    buffer = (buffer << 5) | val;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((buffer >>> bits) & 0xff);
    }
  }
  return new Uint8Array(out);
}

function bytesToBigInt(bytes) {
  let hex = '';
  for (const b of bytes) hex += b.toString(16).padStart(2, '0');
  return hex ? BigInt('0x' + hex) : 0n;
}

// --- SHA-256 en JavaScript puro ---
const SHA256_K = new Uint32Array([
  0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
  0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
  0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
  0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
  0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
  0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
  0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
  0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]);

function utf8Bytes(str) {
  return new TextEncoder().encode(str);
}

function sha256(bytes) {
  const len = bytes.length;
  const padded = new Uint8Array(((len + 9 + 63) >> 6) << 6);
  padded.set(bytes);
  padded[len] = 0x80;
  const bitLen = len * 8;
  const view = new DataView(padded.buffer);
  view.setUint32(padded.length - 8, Math.floor(bitLen / 0x100000000));
  view.setUint32(padded.length - 4, bitLen >>> 0);

  const H = new Uint32Array([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19]);
  const W = new Uint32Array(64);
  const rotr = (x, n) => (x >>> n) | (x << (32 - n));
  for (let off = 0; off < padded.length; off += 64) {
    for (let i = 0; i < 16; i++) W[i] = view.getUint32(off + i * 4);
    for (let i = 16; i < 64; i++) {
      const s0 = rotr(W[i - 15], 7) ^ rotr(W[i - 15], 18) ^ (W[i - 15] >>> 3);
      const s1 = rotr(W[i - 2], 17) ^ rotr(W[i - 2], 19) ^ (W[i - 2] >>> 10);
      W[i] = (W[i - 16] + s0 + W[i - 7] + s1) >>> 0;
    }
    let [a, b, c, d, e, f, g, h] = H;
    for (let i = 0; i < 64; i++) {
      const S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
      const ch = (e & f) ^ (~e & g);
      const t1 = (h + S1 + ch + SHA256_K[i] + W[i]) >>> 0;
      const S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
      const maj = (a & b) ^ (a & c) ^ (b & c);
      const t2 = (S0 + maj) >>> 0;
      h = g; g = f; f = e; e = (d + t1) >>> 0;
      d = c; c = b; b = a; a = (t1 + t2) >>> 0;
    }
    H[0] = (H[0] + a) >>> 0; H[1] = (H[1] + b) >>> 0; H[2] = (H[2] + c) >>> 0; H[3] = (H[3] + d) >>> 0;
    H[4] = (H[4] + e) >>> 0; H[5] = (H[5] + f) >>> 0; H[6] = (H[6] + g) >>> 0; H[7] = (H[7] + h) >>> 0;
  }
  const out = new Uint8Array(32);
  const outView = new DataView(out.buffer);
  H.forEach((v, i) => outView.setUint32(i * 4, v));
  return out;
}

// --- Curva elíptica P-256 (verificación ECDSA) ---
const P256 = {
  p: 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffffn,
  n: 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n,
  b: 0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604bn,
  gx: 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n,
  gy: 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n
};

function modN(a, m) {
  const r = a % m;
  return r >= 0n ? r : r + m;
}

function modPow(base, exp, m) {
  let result = 1n;
  base = modN(base, m);
  while (exp > 0n) {
    if (exp & 1n) result = (result * base) % m;
    base = (base * base) % m;
    exp >>= 1n;
  }
  return result;
}

function modInv(a, m) {
  return modPow(a, m - 2n, m); // m es primo (p y n de P-256)
}

// Puntos en coordenadas jacobianas [X, Y, Z]; Z = 0 representa el punto en el infinito
function ecDouble(P) {
  const { p } = P256;
  const [X, Y, Z] = P;
  if (Z === 0n || Y === 0n) return [0n, 1n, 0n];
  const delta = (Z * Z) % p;
  const gamma = (Y * Y) % p;
  const beta = (X * gamma) % p;
  const alpha = modN(3n * (X - delta) * (X + delta), p);
  const X3 = modN(alpha * alpha - 8n * beta, p);
  const Z3 = modN((Y + Z) * (Y + Z) - gamma - delta, p);
  const Y3 = modN(alpha * (4n * beta - X3) - 8n * gamma * gamma, p);
  return [X3, Y3, Z3];
}

function ecAdd(P, Q) {
  const { p } = P256;
  if (P[2] === 0n) return Q;
  if (Q[2] === 0n) return P;
  const [X1, Y1, Z1] = P;
  const [X2, Y2, Z2] = Q;
  const Z1Z1 = (Z1 * Z1) % p;
  const Z2Z2 = (Z2 * Z2) % p;
  const U1 = (X1 * Z2Z2) % p;
  const U2 = (X2 * Z1Z1) % p;
  const S1 = (Y1 * Z2 * Z2Z2) % p;
  const S2 = (Y2 * Z1 * Z1Z1) % p;
  if (U1 === U2) {
    return S1 === S2 ? ecDouble(P) : [0n, 1n, 0n];
  }
  const H = modN(U2 - U1, p);
  const R = modN(S2 - S1, p);
  const HH = (H * H) % p;
  const HHH = (H * HH) % p;
  const V = (U1 * HH) % p;
  const X3 = modN(R * R - HHH - 2n * V, p);
  const Y3 = modN(R * (V - X3) - S1 * HHH, p);
  const Z3 = (H * Z1 * Z2) % p;
  return [X3, Y3, Z3];
}

function ecAffineX(P) {
  const { p } = P256;
  const zInv = modInv(P[2], p);
  return (P[0] * zInv * zInv) % p;
}

function isOnP256(x, y) {
  const { p, b } = P256;
  if (x <= 0n || x >= p || y <= 0n || y >= p) return false;
  return modN(y * y - (x * x * x - 3n * x + b), p) === 0n;
}

let licensePublicPoint = null;
function getLicensePublicPoint() {
  if (licensePublicPoint) return licensePublicPoint;
  const hex = LICENSE_PUBLIC_KEY_HEX;
  if (hex.length !== 130 || !hex.startsWith('04')) throw new Error('Clave pública de licencias no válida');
  const x = BigInt('0x' + hex.slice(2, 66));
  const y = BigInt('0x' + hex.slice(66));
  if (!isOnP256(x, y)) throw new Error('La clave pública no pertenece a la curva P-256');
  licensePublicPoint = [x, y, 1n];
  return licensePublicPoint;
}

// Verifica una firma ECDSA P-256 en formato r||s (64 bytes) sobre SHA-256(mensaje)
function ecdsaP256Verify(messageBytes, signature64) {
  if (!signature64 || signature64.length !== 64) return false;
  const { n, gx, gy } = P256;
  const r = bytesToBigInt(signature64.slice(0, 32));
  const s = bytesToBigInt(signature64.slice(32));
  if (r <= 0n || r >= n || s <= 0n || s >= n) return false;
  const e = bytesToBigInt(sha256(messageBytes));
  const w = modInv(s, n);
  const u1 = (e * w) % n;
  const u2 = (r * w) % n;

  // Truco de Shamir: u1·G + u2·Q en una sola pasada
  const G = [gx, gy, 1n];
  const Q = getLicensePublicPoint();
  const GQ = ecAdd(G, Q);
  let R = [0n, 1n, 0n];
  for (let i = 255; i >= 0; i--) {
    R = ecDouble(R);
    const b1 = (u1 >> BigInt(i)) & 1n;
    const b2 = (u2 >> BigInt(i)) & 1n;
    if (b1 && b2) R = ecAdd(R, GQ);
    else if (b1) R = ecAdd(R, G);
    else if (b2) R = ecAdd(R, Q);
  }
  if (R[2] === 0n) return false;
  return modN(ecAffineX(R), n) === r;
}

// Las verificaciones se guardan en memoria: la sincronización revalida la licencia en cada mensaje
const licenseVerifyCache = new Map();

// Formato de clave: CP2-<dispositivos>D-<hijos>H-<firma en base32, en grupos de 5>
// Ej.: CP2-9D-2H-ABCDE-FGHJK-... (se aceptan espacios, saltos de línea y minúsculas al pegarla)
function verifyLicenseKey(holderName, licenseKey) {
  const holder = normalizeHolderName(holderName);
  const cleanKey = String(licenseKey || '').toUpperCase().replace(/\s+/g, '');
  const cacheId = `${holder}::${cleanKey}`;
  if (licenseVerifyCache.has(cacheId)) return licenseVerifyCache.get(cacheId);

  let result;
  const match = /^CP2-(\d{1,2})D-(\d{1,2})H-([0-9A-Z-]+)$/.exec(cleanKey);
  if (!holder) {
    result = { valid: false, reason: 'Escribe el nombre del titular exactamente como figura en tu licencia.' };
  } else if (!match) {
    result = /^CP-/.test(cleanKey)
      ? { valid: false, reason: 'Esta clave es del formato antiguo y ya no es válida. Solicita tu nueva clave al programador.' }
      : { valid: false, reason: 'Formato de clave inválido. Copia y pega la clave completa entregada por el programador.' };
  } else {
    const maxDevices = parseInt(match[1], 10);
    const maxChildren = parseInt(match[2], 10);
    const sigBytes = base32Decode(match[3].replace(/-/g, ''));
    let ok = false;
    try {
      ok = maxDevices >= 1 && maxChildren >= 1 && !!sigBytes && sigBytes.length >= 64 &&
        ecdsaP256Verify(utf8Bytes(buildLicenseMessage(holder, maxDevices, maxChildren)), sigBytes.slice(0, 64));
    } catch (e) {
      console.error('Error verificando licencia:', e);
      ok = false;
    }
    result = ok
      ? { valid: true, holder, maxDevices, maxChildren, key: cleanKey }
      : { valid: false, reason: '⛔ Licencia Personal e Intransferible: esta clave pertenece a otro titular, tiene otro cupo o ha sido alterada.' };
  }
  licenseVerifyCache.set(cacheId, result);
  return result;
}

// Huella (hash) de la contraseña del panel del programador (no se guarda en texto plano).
// Para cambiarla: en la consola del navegador ejecuta hashMasterPassword('NUEVA-CLAVE')
// y pega el resultado en PROGRAMMER_MASTER_PASS_HASH.
function hashMasterPassword(password) {
  const mix = (raw) => {
    let h1 = 0xdeadbeef ^ raw.length;
    let h2 = 0x41c6ce57 ^ raw.length;
    for (let i = 0; i < raw.length; i++) {
      const ch = raw.charCodeAt(i);
      h1 = Math.imul(h1 ^ ch, 2654435761);
      h2 = Math.imul(h2 ^ ch, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return (h2 >>> 0).toString(16).padStart(8, '0') + (h1 >>> 0).toString(16).padStart(8, '0');
  };
  let x = String(password || '');
  for (let i = 0; i < 5000; i++) x = mix(`CP-DEV|${x}|${PASSWORD_PEPPER}`);
  return x;
}

function verifyMasterPassword(password) {
  return hashMasterPassword(password) === PROGRAMMER_MASTER_PASS_HASH;
}

// Vuelve a comprobar la firma de la licencia guardada o recibida por sincronización.
// El cupo válido es SIEMPRE el que va firmado dentro de la clave.
function revalidateLicense(lic) {
  if (!lic || typeof lic !== 'object') return lic;
  if (!lic.isActivated) return lic;
  const res = verifyLicenseKey(lic.holderName, lic.licenseKey);
  if (!res.valid) {
    return { ...lic, isActivated: false };
  }
  return { ...lic, holderName: res.holder, licenseKey: res.key, maxDevices: res.maxDevices, maxChildren: res.maxChildren };
}

// Catálogo base amplio + soporte para añadir cualquier nueva app en tendencia
const APP_CATALOG = [
  { name: 'Roblox', category: 'Juegos', icon: '🎲', color: '#e11d48', defaultLimitMins: 60 },
  { name: 'TikTok', category: 'Redes Sociales', icon: '🎵', color: '#0f172a', defaultLimitMins: 45 },
  { name: 'YouTube', category: 'Videos', icon: '▶️', color: '#dc2626', defaultLimitMins: 60 },
  { name: 'Brawl Stars', category: 'Juegos', icon: '⭐', color: '#eab308', defaultLimitMins: 45 },
  { name: 'WhatsApp', category: 'Redes Sociales', icon: '💬', color: '#22c55e', defaultLimitMins: 60 },
  { name: 'Instagram', category: 'Redes Sociales', icon: '📸', color: '#db2777', defaultLimitMins: 45 },
  { name: 'Minecraft', category: 'Juegos', icon: '⛏️', color: '#16a34a', defaultLimitMins: 60 },
  { name: 'Fortnite', category: 'Juegos', icon: '🏆', color: '#7c3aed', defaultLimitMins: 60 },
  { name: 'Clash Royale', category: 'Juegos', icon: '👑', color: '#2563eb', defaultLimitMins: 45 },
  { name: 'Stumble Guys', category: 'Juegos', icon: '🏃', color: '#f97316', defaultLimitMins: 45 },
  { name: 'Pokémon TCG Pocket', category: 'Juegos', icon: '🃏', color: '#eab308', defaultLimitMins: 45 },
  { name: 'EA Sports FC / FIFA', category: 'Juegos', icon: '⚽', color: '#059669', defaultLimitMins: 60 },
  { name: 'Free Fire', category: 'Juegos', icon: '🔥', color: '#ea580c', defaultLimitMins: 60 },
  { name: 'Snapchat', category: 'Redes Sociales', icon: '👻', color: '#ca8a04', defaultLimitMins: 45 },
  { name: 'BeReal', category: 'Redes Sociales', icon: '📷', color: '#1e293b', defaultLimitMins: 30 },
  { name: 'CapCut', category: 'Videos', icon: '✂️', color: '#0f172a', defaultLimitMins: 45 },
  { name: 'Twitch', category: 'Videos', icon: '🟣', color: '#9333ea', defaultLimitMins: 45 },
  { name: 'Kick', category: 'Videos', icon: '🟢', color: '#16a34a', defaultLimitMins: 45 },
  { name: 'Discord', category: 'Redes Sociales', icon: '🎧', color: '#4f46e5', defaultLimitMins: 60 },
  { name: 'Netflix', category: 'Videos', icon: '🎬', color: '#b91c1c', defaultLimitMins: 60 },
  { name: 'YouTube Kids', category: 'Videos', icon: '🧒', color: '#ef4444', defaultLimitMins: 60 },
  { name: 'Spotify / Música', category: 'Videos', icon: '🎶', color: '#10b981', defaultLimitMins: 120 },
  { name: 'Duolingo', category: 'Educación', icon: '🦉', color: '#16a34a', defaultLimitMins: 90 },
  { name: 'Google Classroom', category: 'Educación', icon: '🏫', color: '#0284c7', defaultLimitMins: 120 }
];

// Lista inicial de los 9 dispositivos (3 iPhones + 6 iPads), totalmente editable y ampliable hasta el límite de la licencia
const DEFAULT_DEVICES = [
  { id: 'dev-iphone-1', name: 'iPhone 1 (Padre/Tutor)', type: 'iPhone', icon: '📱' },
  { id: 'dev-iphone-2', name: 'iPhone 2 (Madre/Tutora)', type: 'iPhone', icon: '📱' },
  { id: 'dev-iphone-3', name: 'iPhone 3 (Hijo/a)', type: 'iPhone', icon: '📱' },
  { id: 'dev-ipad-1', name: 'iPad 1', type: 'iPad', icon: '📲' },
  { id: 'dev-ipad-2', name: 'iPad 2', type: 'iPad', icon: '📲' },
  { id: 'dev-ipad-3', name: 'iPad 3', type: 'iPad', icon: '📲' },
  { id: 'dev-ipad-4', name: 'iPad 4', type: 'iPad', icon: '📲' },
  { id: 'dev-ipad-5', name: 'iPad 5', type: 'iPad', icon: '📲' },
  { id: 'dev-ipad-6', name: 'iPad 6', type: 'iPad', icon: '📲' }
];

const DEFAULT_CHILDREN = [
  { id: 'child-1', name: 'Hijo/a 1', age: '', avatar: '👦' }
];

const DEFAULT_STATE = {
  childName: 'Hijo/a 1',
  childAge: '',
  childAvatar: '👦',
  activeChildId: 'child-1',
  childrenList: deepClone(DEFAULT_CHILDREN),
  parentPin: '1234',
  isParentUnlocked: true,
  silentMode: true, // Modo Solo Medir activado por defecto (con opción de cortar en cualquier momento)
  activeDevice: 'iPhone 3 (Hijo/a)',
  familyDevices: deepClone(DEFAULT_DEVICES),
  customCatalogApps: [],
  // Sin licencia hasta que el cliente introduce su clave firmada (pantalla de activación)
  license: {
    isActivated: false,
    holderName: '',
    licenseKey: '',
    maxDevices: 1,
    maxChildren: 1,
    authorizedChildNames: [],
    registeredDeviceIds: [CURRENT_DEVICE_FP]
  },
  familySyncCode: '',
  syncRelayUrl: '', // vacío = servidor público por defecto (ntfy.sh)
  lastUpdatedAt: Date.now(),
  lastResetDate: getLocalDateKey(),
  globalDailyLimitSeconds: 180 * 60,
  categoryLimitsSeconds: {
    'Juegos': 90 * 60,
    'Redes Sociales': 60 * 60,
    'Videos': 60 * 60,
    'Educación': 120 * 60
  },
  apps: [
    {
      id: 'app-roblox',
      name: 'Roblox',
      category: 'Juegos',
      icon: '🎲',
      color: '#e11d48',
      isControlled: true,
      enforceCut: false,
      dailyLimitSeconds: 60 * 60,
      usedSeconds: 0,
      usedByDevice: {},
      usedByChild: {},
      runningDevice: 'iPad 1',
      runningChildId: 'child-1',
      runningChildName: 'Hijo/a 1',
      isRunning: false,
      lastTickTimestamp: null,
      manuallyBlocked: false,
      notes: 'Margen ajustable y corte en vivo disponible'
    },
    {
      id: 'app-tiktok',
      name: 'TikTok',
      category: 'Redes Sociales',
      icon: '🎵',
      color: '#0f172a',
      isControlled: true,
      enforceCut: false,
      dailyLimitSeconds: 45 * 60,
      usedSeconds: 0,
      usedByDevice: {},
      usedByChild: {},
      runningDevice: 'iPhone 3 (Hijo/a)',
      runningChildId: 'child-1',
      runningChildName: 'Hijo/a 1',
      isRunning: false,
      lastTickTimestamp: null,
      manuallyBlocked: false,
      notes: ''
    },
    {
      id: 'app-youtube',
      name: 'YouTube',
      category: 'Videos',
      icon: '▶️',
      color: '#dc2626',
      isControlled: true,
      enforceCut: false,
      dailyLimitSeconds: 60 * 60,
      usedSeconds: 0,
      usedByDevice: {},
      usedByChild: {},
      runningDevice: 'iPad 1',
      runningChildId: 'child-1',
      runningChildName: 'Hijo/a 1',
      isRunning: false,
      lastTickTimestamp: null,
      manuallyBlocked: false,
      notes: ''
    },
    {
      id: 'app-brawlstars',
      name: 'Brawl Stars',
      category: 'Juegos',
      icon: '⭐',
      color: '#eab308',
      isControlled: true,
      enforceCut: false,
      dailyLimitSeconds: 60 * 60,
      usedSeconds: 0,
      usedByDevice: {},
      usedByChild: {},
      runningDevice: 'iPhone 3 (Hijo/a)',
      runningChildId: 'child-1',
      runningChildName: 'Hijo/a 1',
      isRunning: false,
      lastTickTimestamp: null,
      manuallyBlocked: false,
      notes: ''
    },
    {
      id: 'app-minecraft',
      name: 'Minecraft',
      category: 'Juegos',
      icon: '⛏️',
      color: '#16a34a',
      isControlled: true,
      enforceCut: false,
      dailyLimitSeconds: 60 * 60,
      usedSeconds: 0,
      usedByDevice: {},
      usedByChild: {},
      runningDevice: 'iPad 2',
      runningChildId: 'child-1',
      runningChildName: 'Hijo/a 1',
      isRunning: false,
      lastTickTimestamp: null,
      manuallyBlocked: false,
      notes: ''
    },
    {
      id: 'app-whatsapp',
      name: 'WhatsApp',
      category: 'Redes Sociales',
      icon: '💬',
      color: '#22c55e',
      isControlled: false,
      enforceCut: false,
      dailyLimitSeconds: 60 * 60,
      usedSeconds: 0,
      usedByDevice: {},
      usedByChild: {},
      runningDevice: 'iPhone 3 (Hijo/a)',
      runningChildId: 'child-1',
      runningChildName: 'Hijo/a 1',
      isRunning: false,
      lastTickTimestamp: null,
      manuallyBlocked: false,
      notes: 'Comunicación familiar'
    }
  ]
};

let state = loadState();
let activeCategoryFilter = 'all';
let searchQuery = '';
let lastAlarmAppId = null;
let pendingProtectedAction = null;
let syncEventSource = null;

function getActiveChildObj() {
  if (!Array.isArray(state.childrenList) || state.childrenList.length === 0) {
    state.childrenList = deepClone(DEFAULT_CHILDREN);
  }
  return state.childrenList.find(c => c.id === state.activeChildId) || state.childrenList[0];
}

function syncActiveChildLegacyFields() {
  const activeChild = getActiveChildObj();
  if (activeChild) {
    state.activeChildId = activeChild.id;
    state.childName = activeChild.name;
    state.childAge = activeChild.age || '';
    state.childAvatar = activeChild.avatar || '👦';
  }
}

// ===== Reinicio diario y márgenes "base" =====
// Los botones "+15 min" amplían el margen solo para HOY. Guardamos el valor original
// (baseLimitSeconds / baseLimits) y lo restauramos automáticamente al cambiar de día.
function rememberBaseLimits(app) {
  if (app && !(Number.isFinite(app.baseLimitSeconds) && app.baseLimitSeconds > 0)) {
    app.baseLimitSeconds = app.dailyLimitSeconds;
  }
  if (!state.baseLimits) {
    state.baseLimits = {
      global: state.globalDailyLimitSeconds,
      categories: { ...state.categoryLimitsSeconds }
    };
  }
}

function applyDailyReset(target, todayKey, nowTs = Date.now(), stopRunning = true) {
  target.lastResetDate = todayKey;
  const midnight = getLocalMidnightTs(nowTs);
  (target.apps || []).forEach(app => {
    app.usedSeconds = 0;
    app.usedByDevice = {};
    app.usedByChild = {};
    app.manuallyBlocked = false; // un corte de ayer no debe seguir bloqueando hoy
    app.cutReason = '';
    if (Number.isFinite(app.baseLimitSeconds) && app.baseLimitSeconds > 0) {
      app.dailyLimitSeconds = app.baseLimitSeconds;
    }
    app.baseLimitSeconds = null;
    if (app.isRunning && !stopRunning) {
      // Sesión en marcha a medianoche: a partir de ahora solo cuenta el tiempo de hoy
      app.lastTickTimestamp = Math.max(midnight, Math.min(app.lastTickTimestamp || nowTs, nowTs));
    } else {
      app.isRunning = false;
      app.lastTickTimestamp = null;
    }
  });
  if (target.baseLimits) {
    if (Number.isFinite(target.baseLimits.global) && target.baseLimits.global > 0) {
      target.globalDailyLimitSeconds = target.baseLimits.global;
    }
    if (target.baseLimits.categories && typeof target.baseLimits.categories === 'object') {
      target.categoryLimitsSeconds = { ...target.categoryLimitsSeconds, ...target.baseLimits.categories };
    }
    target.baseLimits = null;
  }
}

// Comprueba en caliente si ha cambiado el día (la app puede quedarse abierta pasada la medianoche)
function checkDailyReset(nowTs = Date.now()) {
  const today = getLocalDateKey(nowTs);
  if (state.lastResetDate === today) return false;
  applyDailyReset(state, today, nowTs, false);
  const banner = document.getElementById('alarm-banner');
  if (banner) banner.classList.add('hidden');
  const overlay = document.getElementById('live-cut-overlay');
  if (overlay) overlay.classList.add('hidden');
  saveState();
  return true;
}

// ===== Saneado del estado (datos guardados o recibidos por sincronización) =====
function sanitizeUsageMap(map) {
  const clean = {};
  if (map && typeof map === 'object') {
    Object.entries(map).forEach(([name, value]) => {
      const sec = toSafeSeconds(value);
      if (sec > 0) clean[name] = sec;
    });
  }
  return clean;
}

function sanitizeApp(app, ctx) {
  app.id = app.id ? String(app.id) : `app-${Date.now()}-${randomToken(4)}`;
  app.name = String(app.name || 'App');
  app.category = app.category || 'Juegos';
  if (typeof app.isControlled !== 'boolean') app.isControlled = true;
  app.enforceCut = app.enforceCut === true;
  app.manuallyBlocked = app.manuallyBlocked === true;
  app.isRunning = app.isRunning === true;
  app.usedSeconds = toSafeSeconds(app.usedSeconds);
  app.dailyLimitSeconds = toSafeSeconds(app.dailyLimitSeconds) || 60 * 60;
  app.baseLimitSeconds = toSafeSeconds(app.baseLimitSeconds) || null;
  app.usedByDevice = sanitizeUsageMap(app.usedByDevice);
  app.usedByChild = sanitizeUsageMap(app.usedByChild);
  const ts = Number(app.lastTickTimestamp);
  if (app.isRunning) {
    app.lastTickTimestamp = Number.isFinite(ts) && ts > 0 ? ts : Date.now();
  } else {
    app.lastTickTimestamp = null;
  }
  if (!app.runningDevice) app.runningDevice = ctx.activeDevice || ctx.familyDevices[0].name;
  if (!app.runningChildName) app.runningChildName = ctx.childrenList[0].name;
  return app;
}

function normalizeState(parsed, { stopRunningOnNewDay = true } = {}) {
  if (!Array.isArray(parsed.familyDevices) || parsed.familyDevices.length === 0) {
    parsed.familyDevices = deepClone(DEFAULT_DEVICES);
  }
  if (!Array.isArray(parsed.childrenList) || parsed.childrenList.length === 0) {
    parsed.childrenList = [{
      id: 'child-1',
      name: parsed.childName || 'Hijo/a 1',
      age: parsed.childAge || '',
      avatar: parsed.childAvatar || '👦'
    }];
  }
  if (!parsed.activeChildId || !parsed.childrenList.some(c => c.id === parsed.activeChildId)) {
    parsed.activeChildId = parsed.childrenList[0].id;
  }
  if (!parsed.activeDevice || !parsed.familyDevices.some(d => d.name === parsed.activeDevice)) {
    parsed.activeDevice = parsed.familyDevices[2]?.name || parsed.familyDevices[0].name;
  }
  if (!Array.isArray(parsed.customCatalogApps)) parsed.customCatalogApps = [];
  if (!Array.isArray(parsed.apps)) parsed.apps = deepClone(DEFAULT_STATE.apps);
  parsed.apps = parsed.apps
    .filter(app => app && typeof app === 'object')
    .map(app => sanitizeApp(app, parsed));

  parsed.globalDailyLimitSeconds = toSafeSeconds(parsed.globalDailyLimitSeconds) || DEFAULT_STATE.globalDailyLimitSeconds;
  const cats = { ...DEFAULT_STATE.categoryLimitsSeconds, ...(parsed.categoryLimitsSeconds || {}) };
  Object.keys(cats).forEach(k => { cats[k] = toSafeSeconds(cats[k]); });
  parsed.categoryLimitsSeconds = cats;
  if (!/^\d{4}$/.test(String(parsed.parentPin || ''))) parsed.parentPin = DEFAULT_STATE.parentPin;
  parsed.silentMode = parsed.silentMode !== false;
  parsed.syncRelayUrl = normalizeRelayUrl(parsed.syncRelayUrl) || '';
  parsed.lastUpdatedAt = Number(parsed.lastUpdatedAt) || 0;

  if (!parsed.license || typeof parsed.license !== 'object') {
    parsed.license = deepClone(DEFAULT_STATE.license);
  }
  if (!parsed.license.maxChildren) parsed.license.maxChildren = 5;
  if (!Array.isArray(parsed.license.registeredDeviceIds)) {
    parsed.license.registeredDeviceIds = [CURRENT_DEVICE_FP];
  }
  parsed.license = revalidateLicense(parsed.license);

  const today = getLocalDateKey();
  if (parsed.lastResetDate !== today) {
    applyDailyReset(parsed, today, Date.now(), stopRunningOnNewDay);
  }

  const merged = { ...deepClone(DEFAULT_STATE), ...parsed };
  const activeChild = merged.childrenList.find(c => c.id === merged.activeChildId) || merged.childrenList[0];
  if (activeChild) {
    merged.childName = activeChild.name;
    merged.childAge = activeChild.age || '';
    merged.childAvatar = activeChild.avatar || '👦';
  }
  return merged;
}

function loadState() {
  const raw = safeStorageGet(STORAGE_KEY);
  if (!raw) return deepClone(DEFAULT_STATE);
  try {
    const parsed = JSON.parse(raw);
    if (!parsed || typeof parsed !== 'object') throw new Error('Estado no válido');
    return normalizeState(parsed, { stopRunningOnNewDay: true });
  } catch (e) {
    // Nunca se pierden los datos: se guarda una copia del contenido dañado antes de reiniciar
    console.error('Error cargando estado. Se guarda copia en *_corrupt_backup y se usan valores por defecto:', e);
    safeStorageSet(STORAGE_KEY + '_corrupt_backup', raw);
    return deepClone(DEFAULT_STATE);
  }
}

// Almacenamiento 100% en el dispositivo del usuario: no existe ningún servidor ni base de datos del programador
// - Acciones del padre/madre: guardan, marcan lastUpdatedAt y envían el estado completo.
// - Ticks del cronómetro (fromTick): guardan en local sin tocar lastUpdatedAt, para que un
//   "Cortar Ahora" enviado desde otro móvil nunca quede descartado por "ser más antiguo".
function saveState(skipCloudPush = false, { fromTick = false } = {}) {
  syncActiveChildLegacyFields();
  if (!fromTick) state.lastUpdatedAt = Date.now();
  safeStorageSet(STORAGE_KEY, JSON.stringify(state));
  if (!skipCloudPush && state.familySyncCode) {
    pushStateToCloud('full');
  }
}

// =====================================================================
// SINCRONIZACIÓN FAMILIAR CIFRADA DE EXTREMO A EXTREMO
// ---------------------------------------------------------------------
// - El código familiar NUNCA se envía. De él se derivan, en cada dispositivo:
//     · el canal (topic) = SHA-256 del código  -> no revela el código
//     · la clave AES-256 = PBKDF2-SHA256 (210.000 iteraciones) del código
// - Cada mensaje viaja cifrado con AES-256-GCM (confidencial y a prueba de
//   manipulaciones): el servidor de retransmisión (por defecto ntfy.sh, o el
//   servidor ntfy propio que elija la familia) solo ve datos
//   aleatorios. Sin el código nadie puede leer ni inyectar órdenes.
// - Se rechazan mensajes de otro día, propios, antiguos o mal firmados.
// - Si el navegador no ofrece criptografía segura (WebCrypto), la
//   sincronización se desactiva: jamás se envía nada en claro.
// =====================================================================

// Servidor de retransmisión efímero compatible con ntfy. NO es un servidor del programador:
// por defecto el servicio público ntfy.sh, y la familia puede indicar el suyo propio.
const DEFAULT_SYNC_RELAY_URL = 'https://ntfy.sh';

function normalizeRelayUrl(url) {
  const clean = String(url || '').trim();
  if (!clean) return '';
  try {
    const u = new URL(clean);
    if (u.protocol !== 'https:' || u.username || u.password || u.search || u.hash) return null;
    return u.origin + u.pathname.replace(/\/+$/, '');
  } catch (e) {
    return null;
  }
}

function getSyncRelayUrl() {
  return normalizeRelayUrl(state.syncRelayUrl) || DEFAULT_SYNC_RELAY_URL;
}
const SYNC_PBKDF2_ITERATIONS = 210000;
const SYNC_PROTOCOL_VERSION = 3;
const SYNC_MIN_CODE_LENGTH = 12;
const SYNC_CODE_ALPHABET = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789'; // sin 0/O ni 1/I/L para evitar confusiones

function normalizeSyncCode(code) {
  return String(code || '').trim().toUpperCase().replace(/\s+/g, '');
}

function isSyncCryptoAvailable() {
  return !!(window.crypto && window.crypto.subtle && typeof TextEncoder !== 'undefined');
}

// Genera un código como "K7PM-2QAX-9TRC-W4HZ" (16 caracteres aleatorios ≈ 79 bits de entropía)
function generateSecureSyncCode() {
  const groups = [];
  for (let g = 0; g < 4; g++) {
    let part = '';
    const bytes = new Uint8Array(4);
    window.crypto.getRandomValues(bytes);
    for (const b of bytes) part += SYNC_CODE_ALPHABET[b % SYNC_CODE_ALPHABET.length];
    groups.push(part);
  }
  return groups.join('-');
}

function evaluateSyncCode(code) {
  const c = normalizeSyncCode(code);
  if (!c) return { ok: false, level: 'empty', text: '' };
  const chars = c.replace(/-/g, '');
  const variety = new Set(chars).size;
  if (chars.length < SYNC_MIN_CODE_LENGTH) {
    return { ok: false, level: 'weak', text: `⛔ Demasiado corto: usa al menos ${SYNC_MIN_CODE_LENGTH} caracteres (mejor pulsa 🎲).` };
  }
  if (variety < 6) {
    return { ok: false, level: 'weak', text: '⛔ Demasiado repetitivo. Pulsa 🎲 para crear uno seguro.' };
  }
  if (chars.length < 16) {
    return { ok: true, level: 'medium', text: '🟠 Aceptable. Para máxima seguridad usa el código generado con 🎲.' };
  }
  return { ok: true, level: 'strong', text: '🟢 Código seguro.' };
}

function bytesToBase64(bytes) {
  let bin = '';
  const chunk = 0x8000;
  for (let i = 0; i < bytes.length; i += chunk) {
    bin += String.fromCharCode.apply(null, bytes.subarray(i, i + chunk));
  }
  return btoa(bin);
}

function base64ToBytes(b64) {
  const bin = atob(b64);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

function bytesToHex(buffer) {
  return [...new Uint8Array(buffer)].map(b => b.toString(16).padStart(2, '0')).join('');
}

async function transformBytes(bytes, stream) {
  const res = new Response(new Blob([bytes]).stream().pipeThrough(stream));
  return new Uint8Array(await res.arrayBuffer());
}

const canCompress = typeof CompressionStream !== 'undefined' && typeof DecompressionStream !== 'undefined';

// Caché de la clave derivada (PBKDF2 es lento a propósito: solo se calcula una vez por código)
let syncCryptoCache = { code: null, promise: null };

function getSyncCrypto() {
  const code = normalizeSyncCode(state.familySyncCode);
  if (syncCryptoCache.code === code && syncCryptoCache.promise) return syncCryptoCache.promise;
  const promise = (async () => {
    const enc = new TextEncoder();
    const topicHash = await crypto.subtle.digest('SHA-256', enc.encode(`controlparen-topic-v3|${code}`));
    const topic = 'cp3_' + bytesToHex(topicHash).slice(0, 40);
    const baseKey = await crypto.subtle.importKey('raw', enc.encode(code), 'PBKDF2', false, ['deriveKey']);
    const key = await crypto.subtle.deriveKey(
      { name: 'PBKDF2', salt: enc.encode(`controlparen-sync-v3|${topic}`), iterations: SYNC_PBKDF2_ITERATIONS, hash: 'SHA-256' },
      baseKey,
      { name: 'AES-GCM', length: 256 },
      false,
      ['encrypt', 'decrypt']
    );
    return { code, topic, key };
  })();
  syncCryptoCache = { code, promise };
  promise.catch(() => { if (syncCryptoCache.promise === promise) syncCryptoCache = { code: null, promise: null }; });
  return promise;
}

async function encryptSyncPayload(obj, cryptoCtx) {
  let bytes = new TextEncoder().encode(JSON.stringify(obj));
  const z = canCompress ? 1 : 0;
  if (z) bytes = await transformBytes(bytes, new CompressionStream('gzip'));
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const aad = new TextEncoder().encode(`controlparen|v${SYNC_PROTOCOL_VERSION}|z${z}|${cryptoCtx.topic}`);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: aad }, cryptoCtx.key, bytes));
  return JSON.stringify({ v: SYNC_PROTOCOL_VERSION, z, iv: bytesToBase64(iv), ct: bytesToBase64(ct) });
}

async function decryptSyncPayload(envelopeText, cryptoCtx) {
  const env = JSON.parse(envelopeText);
  if (!env || env.v !== SYNC_PROTOCOL_VERSION || typeof env.iv !== 'string' || typeof env.ct !== 'string') {
    throw new Error('Mensaje de sincronización no reconocido');
  }
  const z = env.z === 1 ? 1 : 0;
  if (z && !canCompress) throw new Error('Este navegador no puede descomprimir el mensaje');
  const aad = new TextEncoder().encode(`controlparen|v${SYNC_PROTOCOL_VERSION}|z${z}|${cryptoCtx.topic}`);
  let bytes = new Uint8Array(await crypto.subtle.decrypt(
    { name: 'AES-GCM', iv: base64ToBytes(env.iv), additionalData: aad },
    cryptoCtx.key,
    base64ToBytes(env.ct)
  ));
  if (z) bytes = await transformBytes(bytes, new DecompressionStream('gzip'));
  return JSON.parse(new TextDecoder().decode(bytes));
}

// Estado que se comparte: se excluyen los datos propios de cada dispositivo
function buildSyncPayload() {
  const { isParentUnlocked, activeDevice, familySyncCode, syncRelayUrl, ...shared } = state;
  return shared;
}

let cloudPushTimeout = null;
let lastUsagePushAt = 0;
function pushStateToCloud(kind = 'full') {
  if (!state.familySyncCode || !isSyncCryptoAvailable()) return;
  if (kind === 'usage') {
    const now = Date.now();
    if (now - lastUsagePushAt < CLOUD_PUSH_MIN_INTERVAL_MS) return;
    lastUsagePushAt = now;
    sendSyncMessage({
      type: 'CONTROLPAREN_USAGE',
      dateKey: state.lastResetDate,
      senderFp: CURRENT_DEVICE_FP,
      sentAt: now,
      apps: state.apps.map(a => ({
        id: a.id,
        usedSeconds: a.usedSeconds,
        usedByDevice: a.usedByDevice,
        usedByChild: a.usedByChild
      }))
    });
    return;
  }
  clearTimeout(cloudPushTimeout);
  cloudPushTimeout = setTimeout(() => {
    lastUsagePushAt = Date.now(); // el estado completo ya incluye los contadores
    sendSyncMessage({
      type: 'CONTROLPAREN_SYNC',
      updatedAt: state.lastUpdatedAt,
      dateKey: state.lastResetDate,
      senderFp: CURRENT_DEVICE_FP,
      sentAt: Date.now(),
      payload: buildSyncPayload()
    });
  }, 400);
}

async function sendSyncMessage(message) {
  if (!navigator.onLine || !state.familySyncCode || !isSyncCryptoAvailable()) return;
  try {
    const ctx = await getSyncCrypto();
    if (ctx.code !== normalizeSyncCode(state.familySyncCode)) return; // el código cambió mientras tanto
    const body = await encryptSyncPayload(message, ctx);
    await fetch(`${getSyncRelayUrl()}/${ctx.topic}`, { method: 'POST', body });
  } catch (e) {
    // Sin red o error puntual: se reenviará en la próxima acción
  }
}

// Mezcla de contadores: cada dispositivo mide su propio tiempo, así que nos quedamos
// con el valor más alto de cada contador (nunca se pierde ni se duplica tiempo medido).
function mergeUsageInto(localApp, incoming) {
  if (!localApp || !incoming) return false;
  let changed = false;
  const inUsed = toSafeSeconds(incoming.usedSeconds);
  if (inUsed > localApp.usedSeconds) { localApp.usedSeconds = inUsed; changed = true; }
  ['usedByDevice', 'usedByChild'].forEach(key => {
    const src = sanitizeUsageMap(incoming[key]);
    Object.entries(src).forEach(([name, sec]) => {
      if (sec > (localApp[key][name] || 0)) { localApp[key][name] = sec; changed = true; }
    });
  });
  return changed;
}

function setSyncStatus(text) {
  const el = document.getElementById('sync-status-msg');
  if (el && text) el.textContent = text;
}

let syncConnectionId = 0;
async function connectFamilyCloudSync() {
  const myId = ++syncConnectionId;
  if (syncEventSource) {
    syncEventSource.close();
    syncEventSource = null;
  }
  if (!state.familySyncCode || typeof EventSource === 'undefined') return;
  if (!isSyncCryptoAvailable()) {
    setSyncStatus('⚠️ La sincronización cifrada necesita abrir la app por https (o instalada como app). Por seguridad no se envía nada sin cifrar.');
    return;
  }
  try {
    const ctx = await getSyncCrypto();
    if (myId !== syncConnectionId) return; // se pidió otra conexión mientras derivábamos la clave
    syncEventSource = new EventSource(`${getSyncRelayUrl()}/${ctx.topic}/sse?since=12h`);
    syncEventSource.onmessage = (event) => { handleSyncEvent(event, ctx); };
  } catch (e) {
    console.warn('Error conectando sincronización familiar:', e);
  }
}

async function handleSyncEvent(event, ctx) {
  try {
    if (ctx.code !== normalizeSyncCode(state.familySyncCode)) return;
    const outer = JSON.parse(event.data);
    if (!outer || outer.event !== 'message') return;
    let envelope = outer.message;
    // Los mensajes grandes el servidor los entrega como archivo adjunto
    if (outer.attachment && outer.attachment.url && String(outer.attachment.url).startsWith(getSyncRelayUrl() + '/')) {
      const res = await fetch(outer.attachment.url);
      if (!res.ok) return;
      envelope = await res.text();
    }
    if (!envelope) return;
    const msg = await decryptSyncPayload(envelope, ctx); // falla si no se cifró con nuestro código
    applySyncMessage(msg);
  } catch (err) {
    // Mensaje ajeno, alterado o ilegible: se descarta en silencio
  }
}

function applySyncMessage(msg) {
  if (!msg || msg.senderFp === CURRENT_DEVICE_FP) return; // ignorar nuestros propios envíos
  if (msg.dateKey && msg.dateKey !== getLocalDateKey()) return; // mensajes de otro día

  if (msg.type === 'CONTROLPAREN_USAGE' && Array.isArray(msg.apps)) {
    let changed = false;
    msg.apps.forEach(inApp => {
      const localApp = state.apps.find(a => a.id === inApp.id);
      if (mergeUsageInto(localApp, inApp)) changed = true;
    });
    if (changed) {
      saveState(true, { fromTick: true });
      renderAll();
    }
    return;
  }

  if (msg.type !== 'CONTROLPAREN_SYNC' || !msg.payload) return;
  if (state.lastUpdatedAt && !(Number(msg.updatedAt) > state.lastUpdatedAt)) return;

  const incomingLic = revalidateLicense(msg.payload.license);
  if (!incomingLic || !incomingLic.isActivated) return; // licencia alterada o no válida: se ignora
  // La licencia recibida debe ser la misma que la nuestra (no se puede "cambiar" de titular por sync)
  if (state.license?.isActivated && incomingLic.licenseKey !== state.license.licenseKey) return;

  const regList = Array.isArray(incomingLic.registeredDeviceIds) ? [...incomingLic.registeredDeviceIds] : [];
  if (!regList.includes(CURRENT_DEVICE_FP)) {
    if (regList.length >= (incomingLic.maxDevices || 1)) {
      state.license.isActivated = false;
      safeStorageSet(STORAGE_KEY, JSON.stringify(state));
      renderLicenseGate();
      return;
    }
    regList.push(CURRENT_DEVICE_FP);
  }
  incomingLic.registeredDeviceIds = regList;

  const previous = state;
  const previouslyBlockedIds = new Set(previous.apps.filter(a => a.manuallyBlocked).map(a => a.id));
  const next = normalizeState(deepClone(msg.payload), { stopRunningOnNewDay: true });
  next.license = incomingLic;
  next.familySyncCode = previous.familySyncCode; // el código es local: nunca se acepta uno recibido
  next.syncRelayUrl = previous.syncRelayUrl;     // el servidor lo elige cada dispositivo
  next.isParentUnlocked = previous.isParentUnlocked;
  next.activeDevice = next.familyDevices.some(d => d.name === previous.activeDevice)
    ? previous.activeDevice
    : next.activeDevice;

  // Conservar el tiempo medido localmente y las sesiones que siguen en marcha en ESTE dispositivo
  next.apps.forEach(app => {
    const localApp = previous.apps.find(a => a.id === app.id);
    if (!localApp) return;
    mergeUsageInto(app, localApp);
    const runningHere = localApp.isRunning && localApp.runningDevice === previous.activeDevice;
    if (runningHere && !app.manuallyBlocked) {
      app.isRunning = true;
      app.runningDevice = localApp.runningDevice;
      app.runningChildId = localApp.runningChildId;
      app.runningChildName = localApp.runningChildName;
      app.lastTickTimestamp = localApp.lastTickTimestamp;
    } else if (app.manuallyBlocked) {
      app.isRunning = false;
      app.lastTickTimestamp = null;
    }
  });

  state = next;
  syncActiveChildLegacyFields();
  safeStorageSet(STORAGE_KEY, JSON.stringify(state));
  renderAll();
  const newlyBlockedApp = state.apps.find(a => a.manuallyBlocked && !previouslyBlockedIds.has(a.id));
  if (newlyBlockedApp) {
    showLiveCutOverlay(newlyBlockedApp);
  }
}

// Formateadores de tiempo
function formatHoursMinutes(totalSeconds) {
  const sec = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  if (hours > 0) {
    return `${hours}h ${String(mins).padStart(2, '0')}m`;
  }
  return `${mins} min`;
}

function formatCountdown(totalSeconds) {
  const sec = Math.max(0, Math.floor(totalSeconds));
  const hours = Math.floor(sec / 3600);
  const mins = Math.floor((sec % 3600) / 60);
  const secs = sec % 60;
  if (hours > 0) {
    return `${String(hours).padStart(2, '0')}:${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
  }
  return `${String(mins).padStart(2, '0')}:${String(secs).padStart(2, '0')}`;
}

function playAlarmSound() {
  try {
    const ctx = new (window.AudioContext || window.webkitAudioContext)();
    const notes = [523.25, 659.25, 783.99, 523.25];
    notes.forEach((freq, idx) => {
      const osc = ctx.createOscillator();
      const gain = ctx.createGain();
      osc.type = 'sine';
      osc.frequency.value = freq;
      gain.gain.setValueAtTime(0.18, ctx.currentTime + idx * 0.18);
      gain.gain.exponentialRampToValueAtTime(0.001, ctx.currentTime + (idx + 1) * 0.18);
      osc.connect(gain);
      gain.connect(ctx.destination);
      osc.start(ctx.currentTime + idx * 0.18);
      osc.stop(ctx.currentTime + (idx + 1) * 0.18);
    });
  } catch (err) {
    // Ignorar si el navegador bloquea audio sin interacción
  }
}

// Cálculo de tiempos globales, por todos los dispositivos, por cada hijo/a y por categoría
function getTotals() {
  let globalUsed = 0;
  const deviceTotals = {};
  const childTotals = {};

  state.familyDevices.forEach(d => {
    deviceTotals[d.name] = 0;
  });
  state.childrenList.forEach(c => {
    childTotals[c.name] = 0;
  });

  const catUsed = {
    'Juegos': 0,
    'Redes Sociales': 0,
    'Videos': 0,
    'Educación': 0
  };

  state.apps.forEach(app => {
    if (app.usedByDevice && typeof app.usedByDevice === 'object') {
      Object.entries(app.usedByDevice).forEach(([devName, sec]) => {
        deviceTotals[devName] = (deviceTotals[devName] || 0) + (sec || 0);
      });
    }
    if (app.usedByChild && typeof app.usedByChild === 'object') {
      Object.entries(app.usedByChild).forEach(([cName, sec]) => {
        childTotals[cName] = (childTotals[cName] || 0) + (sec || 0);
      });
    }

    if (!state.silentMode && !app.isControlled) return;
    globalUsed += app.usedSeconds;
    if (catUsed[app.category] !== undefined) {
      catUsed[app.category] += app.usedSeconds;
    } else {
      catUsed[app.category] = app.usedSeconds;
    }
  });

  return { globalUsed, deviceTotals, childTotals, catUsed };
}

function getEffectiveRemainingSeconds(app, totals) {
  if (!app.isControlled) return Infinity;
  const appRem = Math.max(0, app.dailyLimitSeconds - app.usedSeconds);
  const catLimit = state.categoryLimitsSeconds[app.category] || 0;
  const catRem = catLimit > 0 ? Math.max(0, catLimit - (totals.catUsed[app.category] || 0)) : Infinity;
  const globalRem = Math.max(0, state.globalDailyLimitSeconds - totals.globalUsed);

  return Math.min(appRem, catRem, globalRem);
}

function requireParentAccess(actionCallback) {
  if (state.isParentUnlocked) {
    actionCallback();
  } else {
    pendingProtectedAction = actionCallback;
    const modalPin = document.getElementById('modal-pin');
    const pinInput = document.getElementById('unlock-pin-input');
    const pinError = document.getElementById('pin-error-msg');
    pinInput.value = '';
    pinError.classList.add('hidden');
    modalPin.classList.remove('hidden');
    setTimeout(() => pinInput.focus(), 50);
  }
}

function addDeviceAndChildElapsed(app, seconds, customDevName = null, customChildName = null) {
  const devName = customDevName || app.runningDevice || state.activeDevice || state.familyDevices[0]?.name || 'Dispositivo';
  if (!app.usedByDevice || typeof app.usedByDevice !== 'object') {
    app.usedByDevice = {};
  }
  app.usedByDevice[devName] = (app.usedByDevice[devName] || 0) + seconds;

  const activeChild = getActiveChildObj();
  const childName = customChildName || app.runningChildName || activeChild?.name || state.childName || 'Hijo/a';
  if (!app.usedByChild || typeof app.usedByChild !== 'object') {
    app.usedByChild = {};
  }
  app.usedByChild[childName] = (app.usedByChild[childName] || 0) + seconds;
}

// ===== Motor de cronometraje exacto =====
// Se basa en marcas de tiempo (Date.now() - lastTickTimestamp), no en contar "ticks":
// - Si el navegador congela o ralentiza el setInterval (pantalla apagada, pestaña en segundo
//   plano, iOS suspendiendo la PWA), al volver se suma de golpe el tiempo real transcurrido.
// - Solo se suman segundos enteros y el resto de milisegundos se arrastra al siguiente ciclo,
//   así no hay deriva acumulada (antes cada ciclo redondeaba y sumaba como mínimo 1 s).
// - Si el reloj del sistema retrocede, no se resta ni se suma tiempo.
// - Al pasar la medianoche con una sesión abierta, se reinicia el día y solo cuenta lo de hoy.
function tickTimers() {
  if (!state.license || !state.license.isActivated) return;

  const now = Date.now();
  const dayChanged = checkDailyReset(now);
  let anyChanged = dayChanged;
  let cutHappened = false;
  const totals = getTotals();

  state.apps.forEach(app => {
    if (!app.isRunning) return;

    if (!app.lastTickTimestamp || app.lastTickTimestamp > now) {
      app.lastTickTimestamp = now; // sin referencia válida o reloj atrasado: empezar a medir desde ahora
      anyChanged = true;
      return;
    }

    const elapsed = Math.floor((now - app.lastTickTimestamp) / 1000);
    if (elapsed < 1) return;
    app.lastTickTimestamp += elapsed * 1000; // conservar la fracción de segundo sobrante

    const countsForTotals = state.silentMode || app.isControlled;
    const mustCutAtLimit = app.isControlled && (app.enforceCut === true || !state.silentMode);
    const remBefore = getEffectiveRemainingSeconds(app, totals);
    const step = mustCutAtLimit ? Math.min(elapsed, remBefore) : elapsed;

    if (step > 0) {
      app.usedSeconds += step;
      addDeviceAndChildElapsed(app, step);
      if (countsForTotals) {
        totals.globalUsed += step;
        totals.catUsed[app.category] = (totals.catUsed[app.category] || 0) + step;
      }
      anyChanged = true;
    }

    const remAfter = getEffectiveRemainingSeconds(app, totals);

    if (!mustCutAtLimit) {
      // Modo solo medir: aviso silencioso una única vez al superar el margen
      if (app.isControlled && remBefore > 0 && remAfter <= 0) {
        triggerAlarm(app, false);
      }
      return;
    }

    if (remAfter <= 0) {
      app.isRunning = false;
      app.lastTickTimestamp = null;
      app.manuallyBlocked = true;
      app.cutReason = `Corte automático alcanzado a los ${Math.round(app.dailyLimitSeconds / 60)} minutos (${app.runningChildName || state.childName})`;
      cutHappened = true;
      anyChanged = true;
      triggerAlarm(app, true);
      showLiveCutOverlay(app);
    }
  });

  if (!anyChanged) return;

  if (cutHappened || dayChanged) {
    saveState(); // cambio importante: se envía el estado completo a toda la familia
  } else {
    saveState(true, { fromTick: true });
    pushStateToCloud('usage'); // contadores, como mucho cada 15 s
  }
  renderTick();
}

// Refresco ligero durante el cronómetro (no reconstruye cabecera ni selectores)
function renderTick() {
  renderLicenseGate();
  renderSummary();
  renderAppsGrid();
}

// Al volver a primer plano (desbloquear el móvil, cambiar de pestaña o de app) se recalcula
// al instante, sin esperar al siguiente ciclo, y se guarda antes de pasar a segundo plano.
function handleVisibilityChange() {
  tickTimers();
  if (document.visibilityState === 'hidden') {
    safeStorageSet(STORAGE_KEY, JSON.stringify(state));
  }
}

function showLiveCutOverlay(app) {
  lastAlarmAppId = app.id;
  playAlarmSound();
  const overlay = document.getElementById('live-cut-overlay');
  if (!overlay) return;
  const who = app.runningChildName || state.childName;
  const where = app.runningDevice || state.activeDevice;
  document.getElementById('live-cut-title').textContent = `🛑 ¡Tiempo Cortado en ${app.name}!`;
  document.getElementById('live-cut-msg').textContent = `El tiempo de ${who} en ${app.name} (${where}) ha sido cortado.`;
  document.getElementById('live-cut-used').textContent = formatHoursMinutes(app.usedSeconds);
  document.getElementById('live-cut-reason').textContent = app.cutReason || `Margen finalizado (${formatHoursMinutes(app.dailyLimitSeconds)})`;
  document.getElementById('live-cut-pin-input').value = '';
  document.getElementById('live-cut-pin-error').classList.add('hidden');
  overlay.classList.remove('hidden');
}

function triggerAlarm(app, forceCut = false) {
  lastAlarmAppId = app.id;
  if (forceCut || !state.silentMode) {
    playAlarmSound();
  }
  const banner = document.getElementById('alarm-banner');
  const title = document.getElementById('alarm-title');
  const msg = document.getElementById('alarm-message');
  const who = app.runningChildName || state.childName;
  const where = app.runningDevice || state.activeDevice;

  const isCut = forceCut || !state.silentMode || app.enforceCut;
  title.textContent = isCut
    ? `🛑 ¡Tiempo cortado en ${app.name} (${who})!`
    : `📊 Aviso silencioso: ${who} superó el margen de referencia en ${app.name}`;
  msg.textContent = isCut
    ? `${app.cutReason || `Se alcanzó el margen de ${formatHoursMinutes(app.dailyLimitSeconds)}`}. La aplicación ha quedado cortada en ${where}.`
    : `${who} sigue usando ${app.name} en ${where}. Puedes cortarla cuando desees con el botón "🛑 Cortar Ahora".`;
  banner.classList.remove('hidden');
}

// Renderizado de la Pantalla de Licencia Personal e Intransferible
function renderLicenseGate() {
  const gate = document.getElementById('license-gate-overlay');
  const fpEl = document.getElementById('current-device-fingerprint');
  if (fpEl) fpEl.textContent = CURRENT_DEVICE_FP;

  const pill = document.getElementById('license-status-pill');
  if (state.license && state.license.isActivated) {
    gate.classList.add('hidden');
    if (pill) {
      const maxD = state.license.maxDevices || 9;
      const maxC = state.license.maxChildren || 5;
      pill.textContent = `🔐 ${state.license.holderName} · ${state.familyDevices.length}/${maxD} disp. · ${state.childrenList.length}/${maxC} hijos`;
      pill.title = 'Licencia personal e intransferible. Datos guardados 100% en tus dispositivos.';
    }
  } else {
    gate.classList.remove('hidden');
    if (pill) {
      pill.textContent = '🔒 Sin Licencia Activa';
    }
  }
}

// Renderizado Completo
function renderAll() {
  syncActiveChildLegacyFields();
  renderLicenseGate();
  renderHeader();
  renderSummary();
  renderCounts();
  renderAppsGrid();
}

function renderCounts() {
  const controlledCount = state.apps.filter(a => a.isControlled).length;
  const uncontrolledCount = state.apps.filter(a => !a.isControlled).length;
  const elControlled = document.getElementById('count-controlled');
  const elUncontrolled = document.getElementById('count-uncontrolled');
  if (elControlled) elControlled.textContent = controlledCount;
  if (elUncontrolled) elUncontrolled.textContent = uncontrolledCount;
}

// Reconstruye las opciones de un <select> solo si han cambiado (evita que el desplegable
// se cierre solo cuando el temporizador refresca la pantalla cada segundo).
function setSelectOptionsIfChanged(selectEl, optionsHtml, selectedValue) {
  if (!selectEl) return;
  if (selectEl.dataset.sig !== optionsHtml) {
    selectEl.innerHTML = optionsHtml;
    selectEl.dataset.sig = optionsHtml;
  }
  if (selectEl.value !== selectedValue) selectEl.value = selectedValue;
}

function renderHeader() {
  // Selector desplegable de Hijo/a activo (para detectar a qué hijo/a se le está dando el tiempo de juego)
  const childSelect = document.getElementById('active-child-select');
  if (childSelect) {
    const html = state.childrenList.map(c => {
      const label = c.age ? `${c.name} (${c.age})` : c.name;
      return `<option value="${escapeHtml(c.id)}">${c.avatar || '👦'} ${escapeHtml(label)}</option>`;
    }).join('');
    setSelectOptionsIfChanged(childSelect, html, state.activeChildId);
  }

  const childrenBadge = document.getElementById('children-count-badge');
  if (childrenBadge) {
    const maxC = state.license?.maxChildren || 5;
    childrenBadge.textContent = `${state.childrenList.length}/${maxC}`;
  }

  // Selector desplegable de todos los dispositivos de la familia
  const devSelect = document.getElementById('active-device-select');
  if (devSelect) {
    const html = state.familyDevices.map(d =>
      `<option value="${escapeHtml(d.name)}">${d.icon || '📲'} ${escapeHtml(d.name)}</option>`
    ).join('');
    setSelectOptionsIfChanged(devSelect, html, state.activeDevice);
  }

  const devCountBadge = document.getElementById('devices-count-badge');
  if (devCountBadge) {
    const maxD = state.license?.maxDevices || 9;
    devCountBadge.textContent = `${state.familyDevices.length}/${maxD}`;
  }

  const syncBadge = document.getElementById('sync-code-badge');
  if (syncBadge) {
    syncBadge.textContent = state.familySyncCode ? 'Conectada 🔒 (cifrada)' : 'Solo este dispositivo';
  }

  const silentBtn = document.getElementById('btn-silent-mode');
  const silentIcon = document.getElementById('silent-icon');
  const silentText = document.getElementById('silent-text');
  if (silentBtn) {
    silentBtn.classList.toggle('is-cut', !state.silentMode);
    silentBtn.setAttribute('aria-checked', String(!state.silentMode));
    if (state.silentMode) {
      silentIcon.textContent = '📊';
      silentText.textContent = 'Solo medir';
      silentBtn.title = 'Ahora: solo se mide el tiempo. Pulsa para cortar automáticamente al llegar al margen.';
    } else {
      silentIcon.textContent = '🛑';
      silentText.textContent = 'Corte automático';
      silentBtn.title = 'Ahora: las apps supervisadas se cortan al llegar al margen. Pulsa para solo medir.';
    }
  }

  const lockBtn = document.getElementById('btn-lock-mode');
  const lockIcon = document.getElementById('lock-icon');
  const lockText = document.getElementById('lock-text');

  if (state.isParentUnlocked) {
    lockBtn.classList.remove('locked');
    lockIcon.textContent = '🔓';
    lockText.textContent = 'Bloquear';
    lockBtn.title = 'Modo Padre activo. Pulsa para bloquear el panel con el PIN parental.';
  } else {
    lockBtn.classList.add('locked');
    lockIcon.textContent = '🔒';
    lockText.textContent = 'Desbloquear';
    lockBtn.title = 'Modo Hijo: el panel está bloqueado. Pulsa e introduce el PIN para desbloquear.';
  }
}

function renderSummary() {
  const totals = getTotals();
  const globalRem = Math.max(0, state.globalDailyLimitSeconds - totals.globalUsed);
  const pct = state.globalDailyLimitSeconds > 0
    ? Math.min(100, (totals.globalUsed / state.globalDailyLimitSeconds) * 100)
    : 0;

  document.getElementById('global-used-time').textContent = formatHoursMinutes(totals.globalUsed);
  document.getElementById('global-limit-time').textContent = formatHoursMinutes(state.globalDailyLimitSeconds);
  const elRem = document.getElementById('global-remaining-time');
  if (elRem) {
    elRem.textContent = globalRem > 0 ? `Quedan ${formatHoursMinutes(globalRem)}` : 'Margen agotado';
    elRem.className = 'remaining-chip' + (pct >= 100 ? ' danger' : pct >= 75 ? ' warn' : '');
  }

  // Desglose por Hijos/as y por Dispositivos
  const breakdownContainer = document.getElementById('global-devices-breakdown');
  if (breakdownContainer) {
    const childPills = state.childrenList.map(c => {
      const sec = totals.childTotals[c.name] || 0;
      return `<span class="dev-pill" style="background:#eef2ff; border-color:#c7d2fe; color:#1e1b4b;">${c.avatar || '👦'} ${escapeHtml(c.name)}: <strong>${formatHoursMinutes(sec)}</strong></span>`;
    }).join('');

    const usedDevices = state.familyDevices.filter(d => (totals.deviceTotals[d.name] || 0) > 0);
    const listToShow = usedDevices.length > 0 ? usedDevices : state.familyDevices.slice(0, 3);
    const devPills = listToShow.map(d => {
      const sec = totals.deviceTotals[d.name] || 0;
      return `<span class="dev-pill">${d.icon || '📲'} ${escapeHtml(d.name)}: <strong>${formatHoursMinutes(sec)}</strong></span>`;
    }).join('');

    breakdownContainer.innerHTML = childPills + devPills;
  }

  const bar = document.getElementById('global-progress-bar');
  bar.style.width = `${pct.toFixed(1)}%`;
  bar.className = 'progress-fill';
  if (pct >= 100) bar.classList.add('danger');
  else if (pct >= 75) bar.classList.add('warn');

  const activeApps = state.apps.filter(a => a.isRunning);
  const pill = document.getElementById('active-timers-indicator');
  if (activeApps.length > 0) {
    pill.className = 'status-pill running';
    pill.textContent = `🟢 En uso: ${activeApps.map(a => `${a.name} (${a.runningChildName || state.childName})`).join(', ')}`;
  } else {
    pill.className = 'status-pill';
    pill.textContent = 'Ninguna app en uso ahora';
  }

  const catContainer = document.getElementById('category-bars-container');
  const categories = [
    { key: 'Juegos', icon: '🎮' },
    { key: 'Redes Sociales', icon: '💬' },
    { key: 'Videos', icon: '📺' },
    { key: 'Educación', icon: '📚' }
  ];

  catContainer.innerHTML = categories.map(cat => {
    const used = totals.catUsed[cat.key] || 0;
    const limit = state.categoryLimitsSeconds[cat.key] || 0;
    const catPct = limit > 0 ? Math.min(100, (used / limit) * 100) : 0;
    let fillClass = 'progress-fill';
    if (catPct >= 100) fillClass += ' danger';
    else if (catPct >= 75) fillClass += ' warn';

    return `
      <div class="cat-row">
        <div class="cat-row-top">
          <strong>${cat.icon} ${cat.key}</strong>
          <span class="cat-row-time">${formatHoursMinutes(used)} / ${formatHoursMinutes(limit)}</span>
        </div>
        <div class="progress-track">
          <div class="${fillClass}" style="width: ${catPct.toFixed(1)}%"></div>
        </div>
      </div>
    `;
  }).join('');
}

// Tarjetas cuya sección "Más opciones" está desplegada (se conserva entre refrescos del temporizador)
const expandedCardIds = new Set();

function renderAppDeviceAndChildBreakdownHtml(app) {
  const childEntries = Object.entries(app.usedByChild || {}).filter(([, sec]) => sec > 0);
  const devEntries = Object.entries(app.usedByDevice || {}).filter(([, sec]) => sec > 0);

  if (childEntries.length === 0 && devEntries.length === 0) {
    return '<p class="card-breakdown-empty">Todavía no hay tiempo registrado hoy.</p>';
  }

  const chips = [
    ...childEntries.map(([cName, sec]) => `<span class="mini-chip child">👦 ${escapeHtml(cName)} <strong>${formatHoursMinutes(sec)}</strong></span>`),
    ...devEntries.map(([devName, sec]) => `<span class="mini-chip">📲 ${escapeHtml(devName)} <strong>${formatHoursMinutes(sec)}</strong></span>`)
  ].join('');

  return `<div class="card-breakdown">${chips}</div>`;
}

// Estado visual de una app: ok (verde), warn (ámbar ≥75%), over (margen superado sin corte),
// blocked (rojo, cortada) o free (uso libre).
function getAppVisualState(app, totals) {
  const effectiveRem = getEffectiveRemainingSeconds(app, totals);
  const mustCutAtLimit = app.isControlled && (app.enforceCut === true || !state.silentMode);
  const isExpired = app.manuallyBlocked || (mustCutAtLimit && effectiveRem <= 0);

  let pct = 0;
  if (mustCutAtLimit && Number.isFinite(effectiveRem)) {
    const effectiveLimit = app.usedSeconds + effectiveRem;
    pct = effectiveLimit > 0 ? (app.usedSeconds / effectiveLimit) * 100 : 100;
  } else if (app.dailyLimitSeconds > 0) {
    pct = (app.usedSeconds / app.dailyLimitSeconds) * 100;
  }
  pct = Math.max(0, Math.min(100, pct));

  let level = 'ok';
  if (isExpired) level = 'blocked';
  else if (!app.isControlled) level = 'free';
  else if (pct >= 100) level = 'over';
  else if (pct >= 75) level = 'warn';

  return { effectiveRem, mustCutAtLimit, isExpired, pct, level };
}

function renderAppsGrid() {
  const grid = document.getElementById('apps-grid');
  const totals = getTotals();
  const q = searchQuery.trim().toLowerCase();

  const filtered = state.apps.filter(app => {
    let matchCat = true;
    if (activeCategoryFilter === 'controlled') matchCat = app.isControlled === true;
    else if (activeCategoryFilter === 'uncontrolled') matchCat = app.isControlled === false;
    else if (activeCategoryFilter !== 'all') matchCat = app.category === activeCategoryFilter;

    const matchSearch = !q || app.name.toLowerCase().includes(q) || app.category.toLowerCase().includes(q);
    return matchCat && matchSearch;
  });

  if (filtered.length === 0) {
    grid.innerHTML = `
      <div class="empty-state">
        <p class="empty-icon">🔥</p>
        <h3>No hay aplicaciones en este filtro</h3>
        <p class="subtitle">Usa <strong>➕ Añadir app</strong> para activar juegos o aplicaciones del catálogo.</p>
      </div>
    `;
    return;
  }

  grid.innerHTML = filtered.map(app => renderAppCard(app, totals)).join('');
}

function renderAppCard(app, totals) {
  const vs = getAppVisualState(app, totals);
  const who = app.runningChildName || state.childName;
  const where = app.runningDevice || state.activeDevice;
  const limitMins = Math.round(app.dailyLimitSeconds / 60);

  // Insignia de estado (semáforo)
  let badge;
  if (app.manuallyBlocked) badge = '<span class="app-status-badge badge-blocked">🛑 Cortada</span>';
  else if (vs.isExpired) badge = '<span class="app-status-badge badge-blocked">⛔ Límite alcanzado</span>';
  else if (app.isRunning) badge = '<span class="app-status-badge badge-running">▶ En uso</span>';
  else if (vs.level === 'free') badge = '<span class="app-status-badge badge-free">🟢 Libre</span>';
  else if (vs.level === 'over') badge = '<span class="app-status-badge badge-blocked">⚠️ Margen superado</span>';
  else if (vs.level === 'warn') badge = '<span class="app-status-badge badge-warning">🟠 Queda poco</span>';
  else if (app.enforceCut) badge = `<span class="app-status-badge badge-warning">✂️ Corta a los ${limitMins}m</span>`;
  else badge = '<span class="app-status-badge badge-available">📊 Midiendo</span>';

  // Modo de la app (texto corto bajo el nombre)
  let modeText;
  if (!app.isControlled) modeText = 'Uso libre';
  else if (vs.mustCutAtLimit) modeText = `Corte a los ${formatHoursMinutes(app.dailyLimitSeconds)}`;
  else modeText = `Solo medir · margen ${formatHoursMinutes(app.dailyLimitSeconds)}`;

  // Contador principal
  let digits;
  let caption;
  if (app.manuallyBlocked) {
    digits = 'CORTADA';
    caption = `Usado hoy: <strong>${formatHoursMinutes(app.usedSeconds)}</strong>`;
  } else if (vs.mustCutAtLimit) {
    digits = formatCountdown(vs.effectiveRem);
    caption = `restante · usado <strong>${formatHoursMinutes(app.usedSeconds)}</strong>`;
  } else {
    digits = formatCountdown(app.usedSeconds);
    caption = app.isControlled
      ? `usado de <strong>${formatHoursMinutes(app.dailyLimitSeconds)}</strong>`
      : 'usado hoy';
  }

  const fillClass = 'progress-fill' + (vs.level === 'blocked' || vs.level === 'over' ? ' danger' : vs.level === 'warn' ? ' warn' : '');
  const barPct = app.isControlled ? vs.pct : 0;

  // Acciones principales (2 botones grandes, cómodos al tacto)
  let primary;
  if (app.manuallyBlocked || vs.isExpired) {
    primary = `
      <button class="btn card-btn card-btn-resume" data-action="${app.manuallyBlocked ? 'resume-cut' : 'bonus'}" data-id="${app.id}">🔓 Quitar corte (+15 min)</button>
      <button class="btn card-btn card-btn-ghost" data-action="open-cut-margin" data-id="${app.id}">✂️ Ajustar</button>
    `;
  } else if (app.isRunning) {
    primary = `
      <button class="btn card-btn card-btn-pause" data-action="toggle-timer" data-id="${app.id}" title="Terminar el turno de ${escapeHtml(who)} en ${escapeHtml(where)}">⏸️ Terminar turno</button>
      <button class="btn card-btn card-btn-cut" data-action="cut-now" data-id="${app.id}" title="Cortar esta app ahora mismo">🛑 Cortar</button>
    `;
  } else {
    primary = `
      <button class="btn card-btn card-btn-start" data-action="toggle-timer" data-id="${app.id}" title="Dar tiempo a ${escapeHtml(state.childName)} en ${escapeHtml(state.activeDevice)}">▶️ Dar tiempo</button>
      <button class="btn card-btn card-btn-cut" data-action="cut-now" data-id="${app.id}" title="Cortar esta app ahora mismo">🛑 Cortar</button>
    `;
  }

  const turnLine = app.isRunning
    ? `<div class="card-turn">🟢 <strong>${escapeHtml(who)}</strong> en ${escapeHtml(where)}</div>`
    : '';

  const isOpen = expandedCardIds.has(app.id);
  const modeButton = app.isControlled
    ? `<button class="opt-btn" data-action="toggle-controlled" data-id="${app.id}">🟢 Pasar a uso libre</button>`
    : `<button class="opt-btn" data-action="toggle-controlled" data-id="${app.id}">🛡️ Supervisar esta app</button>`;

  const classes = ['app-card', `state-${vs.level}`];
  if (app.isRunning) classes.push('is-running');

  return `
    <article class="${classes.join(' ')}" data-id="${app.id}">
      <div class="app-card-header">
        <div class="app-identity">
          <div class="app-icon-box" style="background: ${escapeHtml(app.color || '#4f46e5')}">${escapeHtml(app.icon || '🎮')}</div>
          <div class="app-title-group">
            <h3>${escapeHtml(app.name)}</h3>
            <span class="app-category-label">${escapeHtml(app.category)} · ${escapeHtml(modeText)}</span>
          </div>
        </div>
        ${badge}
      </div>

      <div class="app-meter">
        <div class="meter-top">
          <span class="timer-digits ${vs.level === 'blocked' ? 'expired' : ''}">${digits}</span>
          <span class="meter-caption">${caption}</span>
        </div>
        <div class="progress-track"><div class="${fillClass}" style="width: ${barPct.toFixed(1)}%"></div></div>
      </div>

      ${turnLine}

      <div class="card-primary-actions">${primary}</div>

      <details class="card-more" data-id="${app.id}" ${isOpen ? 'open' : ''}>
        <summary>Más opciones <span class="panel-chevron" aria-hidden="true">▾</span></summary>
        <div class="card-more-body">
          <div class="opt-grid">
            <button class="opt-btn" data-action="open-cut-margin" data-id="${app.id}">✂️ Cortar a los… (${limitMins}m)</button>
            <button class="opt-btn" data-action="bonus" data-id="${app.id}">⏱️ +15 min de margen</button>
            <button class="opt-btn" data-action="add-used-active" data-id="${app.id}" title="Anotar 15 min usados por ${escapeHtml(state.childName)} en ${escapeHtml(state.activeDevice)}">➕ Anotar 15 min usados</button>
            ${modeButton}
            <button class="opt-btn" data-action="edit" data-id="${app.id}">⚙️ Configurar</button>
            <button class="opt-btn danger" data-action="delete" data-id="${app.id}">🗑️ Quitar del panel</button>
          </div>
          <div class="card-more-section">
            <span class="card-more-label">Uso de hoy por hijo/a y dispositivo</span>
            ${renderAppDeviceAndChildBreakdownHtml(app)}
          </div>
          ${app.notes ? `<div class="app-notes">📌 ${escapeHtml(app.notes)}</div>` : ''}
        </div>
      </details>
    </article>
  `;
}

// Gestión de Dispositivos de la Familia (respetando el límite contratado en la licencia)
function renderDevicesModal() {
  const container = document.getElementById('devices-manager-list');
  if (!container) return;
  const totals = getTotals();
  const maxD = state.license?.maxDevices || 9;

  container.innerHTML = `
    <div style="background:#eef2ff; border:1px solid #c7d2fe; border-radius:10px; padding:0.6rem 0.85rem; margin-bottom:0.6rem; font-size:0.84rem; color:#1e1b4b;">
      📲 <strong>Dispositivos registrados en esta licencia:</strong> ${state.familyDevices.length} de <strong>${maxD}</strong> contratados por el cliente.
    </div>
  ` + state.familyDevices.map(dev => {
    const usedSec = totals.deviceTotals[dev.name] || 0;
    const isCurrent = dev.name === state.activeDevice;
    return `
      <div class="catalog-item ${isCurrent ? 'in-panel' : ''}">
        <div class="catalog-item-info">
          <div class="catalog-icon" style="background: ${dev.type === 'iPad' ? '#4f46e5' : '#0f172a'}">${dev.icon || '📲'}</div>
          <div>
            <strong class="catalog-name">${escapeHtml(dev.name)}</strong>
            <span class="catalog-cat">${escapeHtml(dev.type)} • Usado hoy: ${formatHoursMinutes(usedSec)}</span>
          </div>
        </div>
        <div class="catalog-actions">
          <button type="button" class="cat-choice-btn ${isCurrent ? 'active-controlled' : ''}" data-dev-action="select" data-dev-id="${dev.id}">
            ${isCurrent ? '✓ Activo' : 'Usar este'}
          </button>
          <button type="button" class="cat-choice-btn" data-dev-action="delete" data-dev-id="${dev.id}" title="Eliminar dispositivo">
            🗑️
          </button>
        </div>
      </div>
    `;
  }).join('');
}

// Gestión de Hijos/as Autorizados en la Licencia (1 o varios hijos en casa)
function renderChildrenModal() {
  const quotaBanner = document.getElementById('children-quota-banner');
  const listEl = document.getElementById('children-manager-list');
  const maxC = state.license?.maxChildren || 5;
  const totals = getTotals();

  if (quotaBanner) {
    quotaBanner.innerHTML = `
      🔐 <strong>Cupo de Hijos/as de esta Licencia:</strong> Tienes registrados <strong>${state.childrenList.length} de ${maxC}</strong> hijo(s)/a(s) autorizados.
      Cada vez que das tiempo a una aplicación, queda registrado a qué hijo/a y en qué dispositivo se le ha dejado jugar.
    `;
  }

  if (listEl) {
    listEl.innerHTML = state.childrenList.map(child => {
      const isCurrent = child.id === state.activeChildId;
      const usedSec = totals.childTotals[child.name] || 0;
      return `
        <div class="catalog-item ${isCurrent ? 'in-panel' : ''}">
          <div class="catalog-item-info">
            <div class="catalog-icon" style="background:#4f46e5;">${child.avatar || '👦'}</div>
            <div>
              <strong class="catalog-name">${escapeHtml(child.name)} ${child.age ? `(${escapeHtml(child.age)})` : ''}</strong>
              <span class="catalog-cat">Tiempo total usado hoy por ${escapeHtml(child.name)}: <strong>${formatHoursMinutes(usedSec)}</strong></span>
            </div>
          </div>
          <div class="catalog-actions">
            <button type="button" class="cat-choice-btn ${isCurrent ? 'active-controlled' : ''}" data-child-action="select" data-child-id="${child.id}">
              ${isCurrent ? '✓ En turno' : 'Seleccionar'}
            </button>
            <button type="button" class="cat-choice-btn" data-child-action="edit" data-child-id="${child.id}">
              ✏️ Editar
            </button>
            <button type="button" class="cat-choice-btn" data-child-action="delete" data-child-id="${child.id}" title="Quitar perfil">
              🗑️
            </button>
          </div>
        </div>
      `;
    }).join('');
  }
}

function loadChildIntoProfileForm(childObj) {
  if (!childObj) return;
  document.getElementById('profile-child-id-input').value = childObj.id;
  document.getElementById('profile-name-input').value = childObj.name || '';
  document.getElementById('profile-age-input').value = childObj.age || '';
  document.getElementById('profile-pin-input').value = state.parentPin || '1234';
  document.getElementById('form-profile-mode-title').textContent = `✏️ Editando perfil de: ${childObj.name}`;
  document.querySelectorAll('.avatar-opt').forEach(btn => {
    btn.classList.toggle('selected', btn.dataset.avatar === (childObj.avatar || '👦'));
  });
}

// Renderizar el Catálogo de Selección Rápida de Apps y Tendencias
function getAllKnownCatalogApps() {
  const combined = [...APP_CATALOG, ...(state.customCatalogApps || [])];
  state.apps.forEach(userApp => {
    const exists = combined.some(c => c.name.toLowerCase() === userApp.name.toLowerCase());
    if (!exists) {
      combined.push({
        name: userApp.name,
        category: userApp.category,
        icon: userApp.icon,
        color: userApp.color,
        defaultLimitMins: Math.round(userApp.dailyLimitSeconds / 60) || 60
      });
    }
  });
  return combined;
}

function renderCatalogModal() {
  const container = document.getElementById('catalog-list');
  const allKnownApps = getAllKnownCatalogApps();

  container.innerHTML = allKnownApps.map(item => {
    const existing = state.apps.find(a => a.name.toLowerCase() === item.name.toLowerCase());
    const status = !existing ? 'hidden' : (existing.isControlled ? 'controlled' : 'free');

    return `
      <div class="catalog-item ${existing ? 'in-panel' : ''}">
        <div class="catalog-item-info">
          <div class="catalog-icon" style="background: ${item.color || '#4f46e5'}">${item.icon || '🔥'}</div>
          <div>
            <strong class="catalog-name">${escapeHtml(item.name)}</strong>
            <span class="catalog-cat">${escapeHtml(item.category)}</span>
          </div>
        </div>
        <div class="catalog-actions">
          <button type="button"
            class="cat-choice-btn ${status === 'controlled' ? 'active-controlled' : ''}"
            data-cat-name="${escapeHtml(item.name)}"
            data-cat-mode="controlled">
            🛡️ Supervisar
          </button>
          <button type="button"
            class="cat-choice-btn ${status === 'free' ? 'active-free' : ''}"
            data-cat-name="${escapeHtml(item.name)}"
            data-cat-mode="free">
            🟢 Libre
          </button>
          <button type="button"
            class="cat-choice-btn ${status === 'hidden' ? 'active-hidden' : ''}"
            data-cat-name="${escapeHtml(item.name)}"
            data-cat-mode="remove">
            ✕ Ocultar
          </button>
        </div>
      </div>
    `;
  }).join('');
}

function setCatalogAppStatus(appName, mode) {
  requireParentAccess(() => {
    const existingIndex = state.apps.findIndex(a => a.name.toLowerCase() === appName.toLowerCase());
    const allKnown = getAllKnownCatalogApps();
    const catalogTemplate = allKnown.find(c => c.name.toLowerCase() === appName.toLowerCase()) || {
      name: appName,
      category: 'Juegos',
      icon: '🔥',
      color: '#4f46e5',
      defaultLimitMins: 60
    };

    if (mode === 'remove') {
      if (existingIndex !== -1) {
        state.apps.splice(existingIndex, 1);
      }
    } else {
      const wantControlled = mode === 'controlled';
      if (existingIndex !== -1) {
        state.apps[existingIndex].isControlled = wantControlled;
        if (!wantControlled) {
          state.apps[existingIndex].manuallyBlocked = false;
          state.apps[existingIndex].enforceCut = false;
        }
      } else {
        state.apps.push({
          id: 'app-' + Date.now() + '-' + Math.random().toString(36).slice(2, 6),
          name: catalogTemplate.name,
          category: catalogTemplate.category,
          icon: catalogTemplate.icon,
          color: catalogTemplate.color,
          isControlled: wantControlled,
          enforceCut: false,
          dailyLimitSeconds: (catalogTemplate.defaultLimitMins || 60) * 60,
          usedSeconds: 0,
          usedByDevice: {},
          usedByChild: {},
          runningDevice: state.activeDevice,
          runningChildId: state.activeChildId,
          runningChildName: state.childName,
          isRunning: false,
          lastTickTimestamp: null,
          manuallyBlocked: false,
          notes: wantControlled ? '' : 'Uso libre'
        });
      }
    }

    saveState();
    renderCatalogModal();
    renderAll();
  });
}

function toggleAppControlled(appId) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    app.isControlled = !app.isControlled;
    if (!app.isControlled) {
      app.manuallyBlocked = false;
      app.enforceCut = false;
    }
    saveState();
    renderAll();
  });
}

function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Acciones sobre Aplicaciones (registrando a qué Hijo/a y en qué Dispositivo se le da el tiempo)
function toggleTimer(appId, forcedDevice = null, forcedChildName = null) {
  const app = state.apps.find(a => a.id === appId);
  if (!app) return;

  if (app.isRunning) {
    app.isRunning = false;
    app.lastTickTimestamp = null;
  } else {
    const mustCutAtLimit = app.isControlled && (app.enforceCut === true || !state.silentMode);
    if (app.manuallyBlocked || (mustCutAtLimit && getEffectiveRemainingSeconds(app, getTotals()) <= 0)) {
      showLiveCutOverlay(app);
      return;
    }
    const activeChild = getActiveChildObj();
    app.runningDevice = forcedDevice || state.activeDevice;
    app.runningChildId = activeChild?.id || state.activeChildId;
    app.runningChildName = forcedChildName || activeChild?.name || state.childName;
    app.isRunning = true;
    app.lastTickTimestamp = Date.now();
  }
  saveState();
  renderAll();
}

function giveBonusTime(appId, minutes = 15) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    const bonusSec = minutes * 60;
    rememberBaseLimits(app); // la ampliación solo dura hasta mañana
    app.dailyLimitSeconds = Math.max(app.dailyLimitSeconds, app.usedSeconds) + bonusSec;
    app.manuallyBlocked = false;

    const totals = getTotals();
    if (state.globalDailyLimitSeconds - totals.globalUsed < bonusSec) {
      state.globalDailyLimitSeconds = totals.globalUsed + bonusSec;
    }
    const catLimit = state.categoryLimitsSeconds[app.category] || 0;
    const catUsed = totals.catUsed[app.category] || 0;
    if (catLimit > 0 && catLimit - catUsed < bonusSec) {
      state.categoryLimitsSeconds[app.category] = catUsed + bonusSec;
    }

    document.getElementById('alarm-banner').classList.add('hidden');
    document.getElementById('live-cut-overlay').classList.add('hidden');
    saveState();
    renderAll();
  });
}

function logUsedTime(appId, minutes = 15, targetDevice = null) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    const addSec = minutes * 60;
    app.usedSeconds += addSec;
    addDeviceAndChildElapsed(app, addSec, targetDevice || state.activeDevice, state.childName);

    const totals = getTotals();
    const mustCutAtLimit = app.isControlled && (app.enforceCut === true || !state.silentMode);
    if (mustCutAtLimit && getEffectiveRemainingSeconds(app, totals) <= 0) {
      app.isRunning = false;
      app.lastTickTimestamp = null;
      app.manuallyBlocked = true;
      app.cutReason = `Corte automático alcanzado a los ${Math.round(app.dailyLimitSeconds / 60)} minutos (${state.childName})`;
      showLiveCutOverlay(app);
    }
    saveState();
    renderAll();
  });
}

function cutAppImmediately(appId) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    const who = app.runningChildName || state.childName;
    app.isRunning = false;
    app.lastTickTimestamp = null;
    app.manuallyBlocked = true;
    app.enforceCut = true;
    const usedMins = Math.round(app.usedSeconds / 60);
    app.cutReason = `Cortado en vivo por Padre/Madre/Tutor a ${who} (${usedMins} min usados)`;
    document.getElementById('modal-cut-margin').classList.add('hidden');
    saveState();
    renderAll();
    showLiveCutOverlay(app);
  });
}

function resumeCutApp(appId) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    app.manuallyBlocked = false;
    if (app.usedSeconds >= app.dailyLimitSeconds) {
      rememberBaseLimits(app);
      app.dailyLimitSeconds = app.usedSeconds + 15 * 60;
    }
    document.getElementById('live-cut-overlay').classList.add('hidden');
    document.getElementById('alarm-banner').classList.add('hidden');
    saveState();
    renderAll();
  });
}

function openCutMarginModal(appId) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    document.getElementById('cut-margin-app-id').value = app.id;
    document.getElementById('cut-margin-title').textContent = `⏱️ Margen o Corte en Vivo — ${app.name}`;
    const usedMins = Math.floor(app.usedSeconds / 60);
    const currentLimitMins = Math.round(app.dailyLimitSeconds / 60);

    document.getElementById('cut-status-summary').innerHTML = `
      <div style="display:flex; justify-content:space-between; flex-wrap:wrap; gap:0.5rem; background:#f8fafc; border:1px solid #cbd5e1; padding:0.75rem 1rem; border-radius:10px; font-size:0.86rem;">
        <span>👦 Hijo/a en turno: <strong>${escapeHtml(app.runningChildName || state.childName)}</strong></span>
        <span>⏱️ Usado hoy: <strong>${formatHoursMinutes(app.usedSeconds)}</strong></span>
        <span>🎯 Margen actual: <strong>${formatHoursMinutes(app.dailyLimitSeconds)}</strong></span>
      </div>
    `;
    document.getElementById('cut-at-minute-input').value = currentLimitMins;
    document.getElementById('cut-enforce-checkbox').checked = true;
    document.getElementById('modal-cut-margin').dataset.usedMins = usedMins;
    document.getElementById('modal-cut-margin').classList.remove('hidden');
  });
}

function deleteApp(appId) {
  requireParentAccess(() => {
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;
    if (confirm(`¿Quitar "${app.name}" del panel? (Podrás volver a activarla cuando quieras desde "Catálogo y Tendencias")`)) {
      state.apps = state.apps.filter(a => a.id !== appId);
      saveState();
      renderAll();
    }
  });
}

function syncControlModeRadioUI() {
  const isControlled = document.getElementById('mode-controlled-yes').checked;
  const limitWrapper = document.getElementById('limit-field-wrapper');
  if (isControlled) {
    limitWrapper.classList.remove('hidden');
  } else {
    limitWrapper.classList.add('hidden');
  }
}

function openAppModal(appId = null) {
  requireParentAccess(() => {
    const modal = document.getElementById('modal-app');
    const title = document.getElementById('modal-app-title');
    const presetsSection = document.getElementById('quick-presets-section');

    if (appId) {
      const app = state.apps.find(a => a.id === appId);
      if (!app) return;
      title.textContent = `Configurar ${app.name}`;
      presetsSection.classList.add('hidden');
      document.getElementById('app-id-input').value = app.id;
      document.getElementById('app-name-input').value = app.name;
      document.getElementById('app-icon-input').value = app.icon || '🔥';
      document.getElementById('app-category-input').value = app.category;
      document.getElementById('app-color-input').value = app.color || '#4f46e5';
      document.getElementById('app-limit-input').value = Math.round(app.dailyLimitSeconds / 60);
      document.getElementById('app-notes-input').value = app.notes || '';
      document.getElementById('mode-controlled-yes').checked = app.isControlled !== false;
      document.getElementById('mode-controlled-no').checked = app.isControlled === false;
    } else {
      title.textContent = 'Añadir Aplicación o Nueva Tendencia';
      presetsSection.classList.remove('hidden');
      document.getElementById('app-id-input').value = '';
      document.getElementById('app-name-input').value = '';
      document.getElementById('app-icon-input').value = '🔥';
      document.getElementById('app-category-input').value = 'Juegos';
      document.getElementById('app-color-input').value = '#4f46e5';
      document.getElementById('app-limit-input').value = 60;
      document.getElementById('app-notes-input').value = '';
      document.getElementById('mode-controlled-yes').checked = true;
      document.getElementById('mode-controlled-no').checked = false;
    }

    syncControlModeRadioUI();
    modal.classList.remove('hidden');
  });
}

function updateShortcutUrlsUI() {
  const appSelect = document.getElementById('shortcut-app-select');
  const devSelect = document.getElementById('shortcut-device-select');
  const startInput = document.getElementById('shortcut-url-start');
  const stopInput = document.getElementById('shortcut-url-stop');
  if (!appSelect || !devSelect || !startInput || !stopInput) return;

  const appName = appSelect.value || 'Roblox';
  const devName = devSelect.value || state.activeDevice || 'iPad 1';
  const childParam = `&child=${encodeURIComponent(state.childName)}`;
  const baseUrl = window.location.href.split('?')[0];
  // El código familiar ya NO va en los enlaces (quedaría a la vista en el historial y en los Atajos):
  // cada dispositivo lo guarda una sola vez al conectarse en "Sincronizar familia".
  const codeParam = '';

  startInput.value = `${baseUrl}?auto=start&app=${encodeURIComponent(appName)}&device=${encodeURIComponent(devName)}${childParam}${codeParam}`;
  stopInput.value = `${baseUrl}?auto=stop&app=${encodeURIComponent(appName)}&device=${encodeURIComponent(devName)}${childParam}${codeParam}`;
}

function handleUrlAutomationParams() {
  try {
    const params = new URLSearchParams(window.location.search);
    // Por seguridad se ignora cualquier código familiar recibido por URL (parámetro "code")

    const autoAction = params.get('auto');
    const appName = params.get('app');
    const device = params.get('device') || state.activeDevice;
    const childFromUrl = params.get('child') || state.childName;

    if (autoAction && appName) {
      const maxD = state.license?.maxDevices || 9;
      if (!state.familyDevices.some(d => d.name.toLowerCase() === device.toLowerCase()) && state.familyDevices.length < maxD) {
        state.familyDevices.push({
          id: 'dev-' + Date.now(),
          name: device,
          type: device.toLowerCase().includes('ipad') ? 'iPad' : 'iPhone',
          icon: device.toLowerCase().includes('ipad') ? '📲' : '📱'
        });
      }
      state.activeDevice = device;

      let targetApp = state.apps.find(a => a.name.toLowerCase() === appName.trim().toLowerCase());
      if (!targetApp) {
        const allKnown = getAllKnownCatalogApps();
        const tmpl = allKnown.find(c => c.name.toLowerCase() === appName.trim().toLowerCase()) || {
          name: appName.trim(),
          category: 'Juegos',
          icon: '🔥',
          color: '#4f46e5',
          defaultLimitMins: 60
        };
        targetApp = {
          id: 'app-' + Date.now(),
          name: tmpl.name,
          category: tmpl.category,
          icon: tmpl.icon,
          color: tmpl.color,
          isControlled: true,
          enforceCut: false,
          dailyLimitSeconds: (tmpl.defaultLimitMins || 60) * 60,
          usedSeconds: 0,
          usedByDevice: {},
          usedByChild: {},
          runningDevice: device,
          runningChildName: childFromUrl,
          isRunning: false,
          lastTickTimestamp: null,
          manuallyBlocked: false,
          notes: 'Detectada automáticamente'
        };
        state.apps.push(targetApp);
      }

      if (autoAction === 'start') {
        if (!targetApp.manuallyBlocked) {
          targetApp.runningDevice = device;
          targetApp.runningChildName = childFromUrl;
          targetApp.isRunning = true;
          targetApp.lastTickTimestamp = Date.now();
        } else {
          showLiveCutOverlay(targetApp);
        }
      } else if (autoAction === 'stop') {
        targetApp.isRunning = false;
        targetApp.lastTickTimestamp = null;
      }
      saveState();
      window.history.replaceState({}, document.title, window.location.pathname);
    }
  } catch (e) {
    console.warn('Error procesando parámetros:', e);
  }
}

function renderDevLicenseStatusSummary() {
  const box = document.getElementById('current-license-summary-box');
  if (!box) return;
  const lic = state.license || {};
  box.innerHTML = `
    <div><strong>Estado:</strong> ${lic.isActivated ? '✅ Activada y Verificada' : '🔒 Bloqueada (Pendiente de activación)'}</div>
    <div><strong>Titular:</strong> ${escapeHtml(lic.holderName || 'Ninguno')}</div>
    <div><strong>Clave activa:</strong> <code style="word-break: break-all;">${escapeHtml(lic.licenseKey || 'Ninguna')}</code></div>
    <div><strong>Firma digital:</strong> ${lic.isActivated ? '✅ ECDSA P-256 verificada con la clave pública del programador' : '—'}</div>
    <div><strong>Cupo de Dispositivos:</strong> ${state.familyDevices.length} en lista / ${(lic.registeredDeviceIds || []).length} aparatos físicos vinculados de <strong>${lic.maxDevices || 9} autorizados</strong></div>
    <div><strong>Cupo de Hijos/as:</strong> ${state.childrenList.length} registrados de <strong>${lic.maxChildren || 5} autorizados</strong> (${state.childrenList.map(c => escapeHtml(c.name)).join(', ')})</div>
    <div><strong>Almacenamiento de datos:</strong> <span style="color:#047857; font-weight:700;">100% Local en los dispositivos del cliente (0 bytes ocupados al programador)</span></div>
  `;
}

// Inicialización de Eventos
document.addEventListener('DOMContentLoaded', () => {
  handleUrlAutomationParams();
  if (state.familySyncCode) {
    connectFamilyCloudSync();
  }
  renderAll();
  setInterval(tickTimers, 1000);
  document.addEventListener('visibilitychange', handleVisibilityChange);
  window.addEventListener('pageshow', () => tickTimers()); // vuelta desde la caché del navegador (iOS)
  window.addEventListener('focus', () => tickTimers());
  window.addEventListener('pagehide', () => safeStorageSet(STORAGE_KEY, JSON.stringify(state)));
  window.addEventListener('online', () => {
    if (state.familySyncCode) {
      connectFamilyCloudSync();
      pushStateToCloud('full');
    }
  });
  // Si la app está abierta en otra pestaña del mismo navegador, mantener ambas coherentes
  window.addEventListener('storage', e => {
    if (e.key === STORAGE_KEY && e.newValue) {
      state = loadState();
      renderAll();
    }
  });

  // Cambio rápido de Hijo/a activo en el selector superior
  const activeChildSelect = document.getElementById('active-child-select');
  if (activeChildSelect) {
    activeChildSelect.addEventListener('change', e => {
      state.activeChildId = e.target.value;
      syncActiveChildLegacyFields();
      saveState();
      renderAll();
    });
  }

  // Cambio de dispositivo activo en el desplegable superior
  const activeDevSelect = document.getElementById('active-device-select');
  if (activeDevSelect) {
    activeDevSelect.addEventListener('change', e => {
      state.activeDevice = e.target.value;
      saveState();
      renderAll();
    });
  }

  // Abrir gestor de todos los dispositivos de la casa
  const openDevicesManager = () => {
    requireParentAccess(() => {
      renderDevicesModal();
      document.getElementById('modal-devices').classList.remove('hidden');
    });
  };

  document.getElementById('btn-manage-devices')?.addEventListener('click', openDevicesManager);
  document.getElementById('btn-quick-add-device')?.addEventListener('click', openDevicesManager);

  // Añadir un nuevo dispositivo (verificando que no supere el número de dispositivos contratados en la licencia)
  document.getElementById('form-add-device')?.addEventListener('submit', e => {
    e.preventDefault();
    const maxD = state.license?.maxDevices || 9;
    if (state.familyDevices.length >= maxD) {
      alert(`⛔ Límite de Licencia Alcanzado: Tu licencia actual está contratada para un máximo de ${maxD} dispositivo(s). Si necesitas añadir más dispositivos, solicita una ampliación al programador.`);
      return;
    }

    const nameInput = document.getElementById('new-device-name');
    const typeSelect = document.getElementById('new-device-type');
    const name = nameInput.value.trim();
    const type = typeSelect.value;
    if (!name) return;

    let icon = '📲';
    if (type === 'iPhone') icon = '📱';
    else if (type === 'Móvil Android') icon = '🤖';
    else if (type === 'Tablet Android') icon = '📲';
    else if (type === 'PC') icon = '💻';
    state.familyDevices.push({
      id: 'dev-' + Date.now(),
      name,
      type,
      icon
    });
    state.activeDevice = name;
    nameInput.value = '';
    saveState();
    renderDevicesModal();
    renderAll();
  });

  // Botón cargar plantilla rápida de 3 iPhones y 6 iPads (ajustada al límite de la licencia)
  document.getElementById('btn-preset-3iphone-6ipad')?.addEventListener('click', () => {
    const maxD = state.license?.maxDevices || 9;
    state.familyDevices = deepClone(DEFAULT_DEVICES).slice(0, maxD);
    state.activeDevice = state.familyDevices[Math.min(2, state.familyDevices.length - 1)].name;
    saveState();
    renderDevicesModal();
    renderAll();
  });

  // Acciones en la lista de dispositivos (seleccionar o borrar)
  document.getElementById('devices-manager-list')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-dev-action]');
    if (!btn) return;
    const action = btn.dataset.devAction;
    const devId = btn.dataset.devId;
    const dev = state.familyDevices.find(d => d.id === devId);
    if (!dev) return;

    if (action === 'select') {
      state.activeDevice = dev.name;
      saveState();
      renderDevicesModal();
      renderAll();
    } else if (action === 'delete') {
      if (state.familyDevices.length <= 1) {
        alert('Debe existir al menos un dispositivo en la lista.');
        return;
      }
      state.familyDevices = state.familyDevices.filter(d => d.id !== devId);
      if (state.activeDevice === dev.name) {
        state.activeDevice = state.familyDevices[0].name;
      }
      saveState();
      renderDevicesModal();
      renderAll();
    }
  });

  // Formulario rápido para añadir una Nueva App en Tendencia desde el Catálogo
  document.getElementById('form-quick-trend-app')?.addEventListener('submit', e => {
    e.preventDefault();
    const name = document.getElementById('trend-app-name').value.trim();
    const icon = document.getElementById('trend-app-icon').value.trim() || '🔥';
    const category = document.getElementById('trend-app-cat').value;
    const limitMins = Math.max(5, parseInt(document.getElementById('trend-app-limit').value, 10) || 60);
    if (!name) return;

    if (!state.customCatalogApps.some(c => c.name.toLowerCase() === name.toLowerCase())) {
      state.customCatalogApps.push({
        name,
        category,
        icon,
        color: '#4f46e5',
        defaultLimitMins: limitMins
      });
    }

    const existing = state.apps.find(a => a.name.toLowerCase() === name.toLowerCase());
    if (!existing) {
      state.apps.unshift({
        id: 'app-' + Date.now(),
        name,
        category,
        icon,
        color: '#4f46e5',
        isControlled: true,
        enforceCut: false,
        dailyLimitSeconds: limitMins * 60,
        usedSeconds: 0,
        usedByDevice: {},
        usedByChild: {},
        runningDevice: state.activeDevice,
        runningChildId: state.activeChildId,
        runningChildName: state.childName,
        isRunning: false,
        lastTickTimestamp: null,
        manuallyBlocked: false,
        notes: '🔥 App en tendencia añadida'
      });
    }

    document.getElementById('trend-app-name').value = '';
    saveState();
    renderCatalogModal();
    renderAll();
  });

  // Modal Sincronización Familiar Multi-Dispositivo
  document.getElementById('btn-family-sync')?.addEventListener('click', () => {
    const codeInput = document.getElementById('family-sync-code-input');
    if (codeInput) codeInput.value = state.familySyncCode || '';
    const appSelect = document.getElementById('shortcut-app-select');
    if (appSelect) {
      appSelect.innerHTML = state.apps.map(a => `<option value="${escapeHtml(a.name)}">${escapeHtml(a.icon)} ${escapeHtml(a.name)}</option>`).join('');
    }
    const devSelect = document.getElementById('shortcut-device-select');
    if (devSelect) {
      devSelect.innerHTML = state.familyDevices.map(d => `<option value="${escapeHtml(d.name)}">${d.icon || '📲'} ${escapeHtml(d.name)}</option>`).join('');
    }
    updateShortcutUrlsUI();
    document.getElementById('modal-family-sync').classList.remove('hidden');
  });

  // Indicador de fortaleza del código familiar
  const syncCodeInput = document.getElementById('family-sync-code-input');
  const renderSyncCodeStrength = () => {
    const box = document.getElementById('sync-code-strength');
    if (!box || !syncCodeInput) return;
    const ev = evaluateSyncCode(syncCodeInput.value);
    box.textContent = ev.text;
    box.className = 'sync-strength ' + ev.level;
  };
  syncCodeInput?.addEventListener('input', renderSyncCodeStrength);
  document.getElementById('btn-family-sync')?.addEventListener('click', () => {
    renderSyncCodeStrength();
    if (!isSyncCryptoAvailable()) {
      setSyncStatus('⚠️ Este navegador no permite la sincronización cifrada aquí. Abre la app por https o instálala en la pantalla de inicio.');
    }
  });

  document.getElementById('btn-generate-sync-code')?.addEventListener('click', () => {
    if (!isSyncCryptoAvailable()) return;
    syncCodeInput.value = generateSecureSyncCode();
    renderSyncCodeStrength();
  });

  document.getElementById('btn-copy-sync-code')?.addEventListener('click', () => {
    const val = normalizeSyncCode(syncCodeInput?.value);
    if (!val) return;
    navigator.clipboard?.writeText(val).then(
      () => setSyncStatus('📋 Código copiado. Escríbelo igual en cada dispositivo de la familia y pulsa "Conectar".'),
      () => {}
    );
  });

  document.getElementById('btn-save-sync-code')?.addEventListener('click', () => {
    requireParentAccess(() => {
      const val = normalizeSyncCode(syncCodeInput?.value);
      const ev = evaluateSyncCode(val);
      if (!isSyncCryptoAvailable()) {
        setSyncStatus('⚠️ No se puede conectar: este navegador no ofrece cifrado seguro aquí (abre la app por https).');
        return;
      }
      if (!ev.ok) {
        renderSyncCodeStrength();
        setSyncStatus('⛔ Elige un código más seguro antes de conectar (pulsa 🎲).');
        return;
      }
      state.familySyncCode = val;
      saveState();
      connectFamilyCloudSync();
      renderAll();
      setSyncStatus('✅ Conectado. Los datos viajan cifrados y solo los dispositivos con este código pueden leerlos.');
    });
  });

  document.getElementById('btn-disconnect-sync')?.addEventListener('click', () => {
    requireParentAccess(() => {
      state.familySyncCode = '';
      if (syncEventSource) { syncEventSource.close(); syncEventSource = null; }
      saveState(true);
      if (syncCodeInput) syncCodeInput.value = '';
      renderSyncCodeStrength();
      renderAll();
      setSyncStatus('⏏️ Desconectado. Este dispositivo funciona en modo local.');
    });
  });

  document.getElementById('btn-sync-now')?.addEventListener('click', () => {
    if (!state.familySyncCode) {
      setSyncStatus('Primero crea o escribe el código familiar y pulsa "Conectar este dispositivo".');
      return;
    }
    pushStateToCloud('full');
    connectFamilyCloudSync();
    setSyncStatus('🔄 Estado enviado (cifrado) a los dispositivos de la familia.');
  });

  document.getElementById('shortcut-app-select')?.addEventListener('change', updateShortcutUrlsUI);
  document.getElementById('shortcut-device-select')?.addEventListener('change', updateShortcutUrlsUI);

  // LICENCIAS PERSONALES E INTRANSFERIBLES — Activación y Panel del Programador
  // (Las claves se generan FUERA de la app, con PROGRAMADOR-PRIVADO/GENERADOR-LICENCIAS.html)
  document.getElementById('form-activate-license')?.addEventListener('submit', e => {
    e.preventDefault();
    const holder = document.getElementById('license-holder-input').value;
    const key = document.getElementById('license-key-input').value;
    const errEl = document.getElementById('license-error-msg');

    const res = verifyLicenseKey(holder, key);
    if (!res.valid) {
      errEl.textContent = res.reason;
      errEl.classList.remove('hidden');
      return;
    }

    state.license = {
      isActivated: true,
      holderName: res.holder,
      licenseKey: res.key,
      maxDevices: res.maxDevices,
      maxChildren: res.maxChildren,
      authorizedChildNames: [],
      registeredDeviceIds: [CURRENT_DEVICE_FP]
    };

    // Ajustar lista de dispositivos e hijos si exceden el cupo de la nueva licencia
    if (state.familyDevices.length > state.license.maxDevices) {
      state.familyDevices = state.familyDevices.slice(0, state.license.maxDevices);
      state.activeDevice = state.familyDevices[0].name;
    }
    if (state.childrenList.length > state.license.maxChildren) {
      state.childrenList = state.childrenList.slice(0, state.license.maxChildren);
      state.activeChildId = state.childrenList[0].id;
      syncActiveChildLegacyFields();
    }

    // Ya no se usa el nombre del titular como código familiar (era fácil de adivinar):
    // la familia crea su propio código seguro en "Sincronizar familia".
    errEl.classList.add('hidden');
    document.getElementById('license-key-input').value = '';
    saveState();
    renderAll();
  });

  const openDevLicenseModal = () => {
    renderDevLicenseStatusSummary();
    document.getElementById('modal-dev-licenses').classList.remove('hidden');
  };

  document.getElementById('btn-dev-license-panel')?.addEventListener('click', openDevLicenseModal);
  document.getElementById('btn-open-dev-from-gate')?.addEventListener('click', openDevLicenseModal);

  document.getElementById('btn-unlock-dev-panel')?.addEventListener('click', () => {
    const pass = document.getElementById('dev-master-password-input').value.trim();
    const err = document.getElementById('dev-auth-error');
    if (verifyMasterPassword(pass)) {
      err.classList.add('hidden');
      document.getElementById('dev-generator-section').classList.remove('hidden');
      renderDevLicenseStatusSummary();
    } else {
      err.classList.remove('hidden');
    }
  });

  document.getElementById('btn-lock-license-test')?.addEventListener('click', () => {
    state.license.isActivated = false;
    saveState();
    document.getElementById('modal-dev-licenses').classList.add('hidden');
    renderAll();
  });

  // Botón Modo Solo Medir / Cortar Automático
  document.getElementById('btn-silent-mode')?.addEventListener('click', () => {
    requireParentAccess(() => {
      state.silentMode = !state.silentMode;
      saveState();
      renderAll();
    });
  });

  // Botón abrir Catálogo y Tendencias
  document.getElementById('btn-catalog')?.addEventListener('click', () => {
    requireParentAccess(() => {
      renderCatalogModal();
      document.getElementById('modal-catalog').classList.remove('hidden');
    });
  });

  document.getElementById('catalog-list')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-cat-mode]');
    if (!btn) return;
    setCatalogAppStatus(btn.dataset.catName, btn.dataset.catMode);
  });

  document.getElementById('btn-catalog-custom')?.addEventListener('click', () => {
    document.getElementById('modal-catalog').classList.add('hidden');
    openAppModal(null);
  });

  document.getElementById('btn-add-app')?.addEventListener('click', () => openAppModal(null));

  document.querySelectorAll('input[name="app-controlled-mode"]').forEach(radio => {
    radio.addEventListener('change', syncControlModeRadioUI);
  });

  document.getElementById('preset-chips')?.addEventListener('click', e => {
    const chip = e.target.closest('.chip');
    if (!chip) return;
    document.getElementById('app-name-input').value = chip.dataset.name;
    document.getElementById('app-category-input').value = chip.dataset.cat;
    document.getElementById('app-icon-input').value = chip.dataset.icon;
    document.getElementById('app-color-input').value = chip.dataset.color;
  });

  document.querySelectorAll('.btn-pill[data-mins]').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('app-limit-input').value = btn.dataset.mins;
    });
  });

  // Guardar App (Nueva o Editada)
  document.getElementById('form-app')?.addEventListener('submit', e => {
    e.preventDefault();
    const id = document.getElementById('app-id-input').value;
    const name = document.getElementById('app-name-input').value.trim();
    const icon = document.getElementById('app-icon-input').value.trim() || '🔥';
    const category = document.getElementById('app-category-input').value;
    const color = document.getElementById('app-color-input').value;
    const isControlled = document.getElementById('mode-controlled-yes').checked;
    const limitMins = Math.max(1, parseInt(document.getElementById('app-limit-input').value, 10) || 60);
    const notes = document.getElementById('app-notes-input').value.trim();

    if (!name) return;

    if (!state.customCatalogApps.some(c => c.name.toLowerCase() === name.toLowerCase()) &&
        !APP_CATALOG.some(c => c.name.toLowerCase() === name.toLowerCase())) {
      state.customCatalogApps.push({
        name,
        category,
        icon,
        color,
        defaultLimitMins: limitMins
      });
    }

    if (id) {
      const existing = state.apps.find(a => a.id === id);
      if (existing) {
        existing.name = name;
        existing.icon = icon;
        existing.category = category;
        existing.color = color;
        existing.isControlled = isControlled;
        existing.dailyLimitSeconds = limitMins * 60;
        existing.baseLimitSeconds = null;
        existing.notes = notes;
        if (!isControlled) {
          existing.manuallyBlocked = false;
          existing.enforceCut = false;
        }
      }
    } else {
      state.apps.push({
        id: 'app-' + Date.now(),
        name,
        category,
        icon,
        color,
        isControlled,
        enforceCut: false,
        dailyLimitSeconds: limitMins * 60,
        usedSeconds: 0,
        usedByDevice: {},
        usedByChild: {},
        runningDevice: state.activeDevice,
        runningChildId: state.activeChildId,
        runningChildName: state.childName,
        isRunning: false,
        lastTickTimestamp: null,
        manuallyBlocked: false,
        notes
      });
    }

    document.getElementById('modal-app').classList.add('hidden');
    saveState();
    renderAll();
  });

  // Delegación de eventos en la cuadrícula de aplicaciones
  document.getElementById('apps-grid')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-action]');
    if (!btn) return;
    const action = btn.dataset.action;
    const appId = btn.dataset.id;

    if (action === 'toggle-timer') toggleTimer(appId);
    else if (action === 'toggle-controlled') toggleAppControlled(appId);
    else if (action === 'open-cut-margin') openCutMarginModal(appId);
    else if (action === 'cut-now') cutAppImmediately(appId);
    else if (action === 'resume-cut') resumeCutApp(appId);
    else if (action === 'bonus') giveBonusTime(appId, 15);
    else if (action === 'add-used-active') logUsedTime(appId, 15, state.activeDevice);
    else if (action === 'edit') openAppModal(appId);
    else if (action === 'delete') deleteApp(appId);
  });

  // Eventos del Modal de Recortar Margen / Cortar a los X minutos
  document.querySelectorAll('.cut-preset-btn').forEach(btn => {
    btn.addEventListener('click', () => {
      document.getElementById('cut-at-minute-input').value = btn.dataset.cutmins;
    });
  });

  document.getElementById('btn-cut-in-5m')?.addEventListener('click', () => {
    const appId = document.getElementById('cut-margin-app-id').value;
    const app = state.apps.find(a => a.id === appId);
    const usedMins = app ? Math.floor(app.usedSeconds / 60) : 0;
    document.getElementById('cut-at-minute-input').value = Math.max(1, usedMins + 5);
  });

  document.getElementById('btn-cut-immediately')?.addEventListener('click', () => {
    const appId = document.getElementById('cut-margin-app-id').value;
    if (appId) cutAppImmediately(appId);
  });

  document.getElementById('form-cut-margin')?.addEventListener('submit', e => {
    e.preventDefault();
    const appId = document.getElementById('cut-margin-app-id').value;
    const app = state.apps.find(a => a.id === appId);
    if (!app) return;

    const newCutMins = Math.max(1, parseInt(document.getElementById('cut-at-minute-input').value, 10) || 40);
    const enforce = document.getElementById('cut-enforce-checkbox').checked;

    app.dailyLimitSeconds = newCutMins * 60;
    app.baseLimitSeconds = null; // margen fijado expresamente por el padre/madre
    app.isControlled = true;
    app.enforceCut = enforce;

    if (enforce && app.usedSeconds >= app.dailyLimitSeconds) {
      app.isRunning = false;
      app.lastTickTimestamp = null;
      app.manuallyBlocked = true;
      app.cutReason = `Corte aplicado a los ${newCutMins} minutos (${app.runningChildName || state.childName})`;
      document.getElementById('modal-cut-margin').classList.add('hidden');
      saveState();
      renderAll();
      showLiveCutOverlay(app);
      return;
    } else {
      app.manuallyBlocked = false;
      app.cutReason = enforce ? `Se cortará automáticamente a los ${newCutMins} minutos` : '';
    }

    document.getElementById('modal-cut-margin').classList.add('hidden');
    saveState();
    renderAll();
  });

  // Eventos de la pantalla roja de Corte en Vivo (#live-cut-overlay)
  document.getElementById('btn-live-cut-unlock')?.addEventListener('click', () => {
    const pinVal = document.getElementById('live-cut-pin-input').value;
    if (pinVal === state.parentPin) {
      document.getElementById('live-cut-overlay').classList.add('hidden');
      if (lastAlarmAppId) {
        const app = state.apps.find(a => a.id === lastAlarmAppId);
        if (app) {
          app.manuallyBlocked = false;
          rememberBaseLimits(app);
          app.dailyLimitSeconds = Math.max(app.dailyLimitSeconds, app.usedSeconds) + 15 * 60;
          saveState();
          renderAll();
        }
      }
    } else {
      document.getElementById('live-cut-pin-error').classList.remove('hidden');
    }
  });

  document.getElementById('btn-live-cut-close-parent')?.addEventListener('click', () => {
    if (state.isParentUnlocked) {
      document.getElementById('live-cut-overlay').classList.add('hidden');
    } else {
      const pinVal = document.getElementById('live-cut-pin-input').value;
      if (pinVal === state.parentPin) {
        document.getElementById('live-cut-overlay').classList.add('hidden');
      } else {
        document.getElementById('live-cut-pin-error').classList.remove('hidden');
      }
    }
  });

  // Filtros de categoría
  document.getElementById('category-tabs')?.addEventListener('click', e => {
    const tab = e.target.closest('.tab-btn');
    if (!tab) return;
    document.querySelectorAll('.tab-btn').forEach(b => b.classList.remove('active'));
    tab.classList.add('active');
    activeCategoryFilter = tab.dataset.category;
    renderAppsGrid();
  });

  // Búsqueda
  document.getElementById('search-input')?.addEventListener('input', e => {
    searchQuery = e.target.value;
    renderAppsGrid();
  });

  // Reiniciar día
  document.getElementById('btn-reset-day')?.addEventListener('click', () => {
    requireParentAccess(() => {
      if (confirm('¿Reiniciar a cero el tiempo usado hoy por todos los hijos y en todos los dispositivos?')) {
        state.apps.forEach(app => {
          app.usedSeconds = 0;
          app.usedByDevice = {};
          app.usedByChild = {};
          app.isRunning = false;
          app.lastTickTimestamp = null;
          app.manuallyBlocked = false;
        });
        document.getElementById('alarm-banner').classList.add('hidden');
        document.getElementById('live-cut-overlay').classList.add('hidden');
        saveState();
        renderAll();
      }
    });
  });

  // Configurar Márgenes Globales y por Categoría
  const openLimitsModal = () => {
    requireParentAccess(() => {
      document.getElementById('global-limit-input').value = Math.round(state.globalDailyLimitSeconds / 60);
      document.getElementById('cat-limit-juegos').value = Math.round((state.categoryLimitsSeconds['Juegos'] || 0) / 60);
      document.getElementById('cat-limit-redes').value = Math.round((state.categoryLimitsSeconds['Redes Sociales'] || 0) / 60);
      document.getElementById('cat-limit-videos').value = Math.round((state.categoryLimitsSeconds['Videos'] || 0) / 60);
      document.getElementById('cat-limit-educacion').value = Math.round((state.categoryLimitsSeconds['Educación'] || 0) / 60);
      document.getElementById('modal-limits').classList.remove('hidden');
    });
  };

  document.getElementById('btn-edit-global-limit')?.addEventListener('click', openLimitsModal);
  document.getElementById('btn-edit-categories')?.addEventListener('click', openLimitsModal);

  document.getElementById('form-limits')?.addEventListener('submit', e => {
    e.preventDefault();
    state.globalDailyLimitSeconds = (parseInt(document.getElementById('global-limit-input').value, 10) || 180) * 60;
    state.categoryLimitsSeconds['Juegos'] = (parseInt(document.getElementById('cat-limit-juegos').value, 10) || 0) * 60;
    state.categoryLimitsSeconds['Redes Sociales'] = (parseInt(document.getElementById('cat-limit-redes').value, 10) || 0) * 60;
    state.categoryLimitsSeconds['Videos'] = (parseInt(document.getElementById('cat-limit-videos').value, 10) || 0) * 60;
    state.categoryLimitsSeconds['Educación'] = (parseInt(document.getElementById('cat-limit-educacion').value, 10) || 0) * 60;
    state.baseLimits = null; // márgenes fijados expresamente: pasan a ser los nuevos valores base

    document.getElementById('modal-limits').classList.add('hidden');
    saveState();
    renderAll();
  });

  // Modal Gestor de Hijos/as Autorizados en la Licencia y PIN Parental
  const openChildrenManager = () => {
    requireParentAccess(() => {
      renderChildrenModal();
      loadChildIntoProfileForm(getActiveChildObj());
      document.getElementById('modal-profile').classList.remove('hidden');
    });
  };
  document.getElementById('child-profile-btn')?.addEventListener('click', openChildrenManager);
  document.getElementById('btn-quick-manage-children')?.addEventListener('click', openChildrenManager);

  document.getElementById('btn-new-child-profile')?.addEventListener('click', () => {
    const maxC = state.license?.maxChildren || 5;
    if (state.childrenList.length >= maxC) {
      alert(`⛔ Cupo de Hijos/as Alcanzado: Tu licencia actual está contratada para un máximo de ${maxC} hijo(s)/a(s). No se pueden añadir más perfiles sin ampliar la licencia con el programador.`);
      return;
    }
    document.getElementById('profile-child-id-input').value = '';
    document.getElementById('profile-name-input').value = '';
    document.getElementById('profile-age-input').value = '';
    document.getElementById('form-profile-mode-title').textContent = `➕ Añadir Nuevo Hijo/a (${state.childrenList.length + 1} de ${maxC} autorizados):`;
    document.getElementById('profile-name-input').focus();
  });

  document.getElementById('children-manager-list')?.addEventListener('click', e => {
    const btn = e.target.closest('[data-child-action]');
    if (!btn) return;
    const action = btn.dataset.childAction;
    const childId = btn.dataset.childId;
    const childObj = state.childrenList.find(c => c.id === childId);
    if (!childObj) return;

    if (action === 'select') {
      state.activeChildId = childObj.id;
      syncActiveChildLegacyFields();
      saveState();
      renderChildrenModal();
      loadChildIntoProfileForm(childObj);
      renderAll();
    } else if (action === 'edit') {
      loadChildIntoProfileForm(childObj);
      document.getElementById('profile-name-input').focus();
    } else if (action === 'delete') {
      if (state.childrenList.length <= 1) {
        alert('Debe haber al menos 1 hijo o hija registrado.');
        return;
      }
      state.childrenList = state.childrenList.filter(c => c.id !== childId);
      if (state.activeChildId === childId) {
        state.activeChildId = state.childrenList[0].id;
      }
      syncActiveChildLegacyFields();
      saveState();
      renderChildrenModal();
      loadChildIntoProfileForm(getActiveChildObj());
      renderAll();
    }
  });

  document.getElementById('avatar-picker')?.addEventListener('click', e => {
    const btn = e.target.closest('.avatar-opt');
    if (!btn) return;
    document.querySelectorAll('.avatar-opt').forEach(b => b.classList.remove('selected'));
    btn.classList.add('selected');
  });

  document.getElementById('form-profile')?.addEventListener('submit', e => {
    e.preventDefault();
    const editingId = document.getElementById('profile-child-id-input').value.trim();
    const name = document.getElementById('profile-name-input').value.trim();
    const age = document.getElementById('profile-age-input').value.trim();
    const pin = document.getElementById('profile-pin-input').value.trim();
    const selectedAvatar = document.querySelector('.avatar-opt.selected');
    const avatar = selectedAvatar ? selectedAvatar.dataset.avatar : '👦';

    if (!name) return;
    if (/^\d{4}$/.test(pin)) state.parentPin = pin;

    if (editingId) {
      const target = state.childrenList.find(c => c.id === editingId);
      if (target) {
        target.name = name;
        target.age = age;
        target.avatar = avatar;
        state.activeChildId = target.id;
      }
    } else {
      const maxC = state.license?.maxChildren || 5;
      if (state.childrenList.length >= maxC) {
        alert(`⛔ Cupo de Hijos/as Alcanzado: Tu licencia actual permite hasta ${maxC} hijo(s)/a(s).`);
        return;
      }
      const newChild = {
        id: 'child-' + Date.now(),
        name,
        age,
        avatar
      };
      state.childrenList.push(newChild);
      state.activeChildId = newChild.id;
    }

    syncActiveChildLegacyFields();
    saveState();
    renderChildrenModal();
    loadChildIntoProfileForm(getActiveChildObj());
    renderAll();
  });

  // Bloqueo / Desbloqueo Modo Padre con PIN
  document.getElementById('btn-lock-mode')?.addEventListener('click', () => {
    if (state.isParentUnlocked) {
      state.isParentUnlocked = false;
      saveState();
      renderAll();
    } else {
      requireParentAccess(() => {
        state.isParentUnlocked = true;
        saveState();
        renderAll();
      });
    }
  });

  document.getElementById('form-pin')?.addEventListener('submit', e => {
    e.preventDefault();
    const entered = document.getElementById('unlock-pin-input').value;
    if (entered === state.parentPin) {
      state.isParentUnlocked = true;
      document.getElementById('modal-pin').classList.add('hidden');
      saveState();
      renderAll();
      if (typeof pendingProtectedAction === 'function') {
        const fn = pendingProtectedAction;
        pendingProtectedAction = null;
        fn();
      }
    } else {
      document.getElementById('pin-error-msg').classList.remove('hidden');
    }
  });

  // Botones de la barra de alarma
  document.getElementById('btn-alarm-dismiss')?.addEventListener('click', () => {
    document.getElementById('alarm-banner').classList.add('hidden');
  });

  document.getElementById('btn-alarm-bonus')?.addEventListener('click', () => {
    if (lastAlarmAppId) {
      giveBonusTime(lastAlarmAppId, 15);
    }
  });

  // Cerrar modales
  document.querySelectorAll('[data-close]').forEach(btn => {
    btn.addEventListener('click', () => {
      const targetId = btn.dataset.close;
      document.getElementById(targetId).classList.add('hidden');
    });
  });

  // Cerrar un modal pulsando fuera de la tarjeta (no aplica a las pantallas de licencia ni de corte)
  const NON_DISMISSIBLE = new Set(['license-gate-overlay', 'live-cut-overlay']);
  document.querySelectorAll('.modal-backdrop').forEach(backdrop => {
    backdrop.addEventListener('click', e => {
      if (e.target === backdrop && !NON_DISMISSIBLE.has(backdrop.id)) {
        backdrop.classList.add('hidden');
      }
    });
  });

  // Menús desplegables de la cabecera
  initDropdowns();

  // Privacidad y datos
  document.getElementById('btn-privacy')?.addEventListener('click', () => {
    setPrivacyStatus('');
    document.getElementById('modal-privacy').classList.remove('hidden');
  });
  document.getElementById('btn-export-data')?.addEventListener('click', () => requireParentAccess(exportUserData));
  document.getElementById('input-import-data')?.addEventListener('change', e => {
    const file = e.target.files && e.target.files[0];
    e.target.value = '';
    if (file) requireParentAccess(() => importUserData(file));
  });
  document.getElementById('btn-wipe-data')?.addEventListener('click', () => requireParentAccess(wipeUserData));

  // Servidor de retransmisión elegido por la familia
  const relayInput = document.getElementById('sync-relay-input');
  document.getElementById('btn-family-sync')?.addEventListener('click', () => {
    if (relayInput) relayInput.value = state.syncRelayUrl || '';
  });
  document.getElementById('btn-save-relay')?.addEventListener('click', () => {
    requireParentAccess(() => {
      const raw = relayInput ? relayInput.value : '';
      const norm = normalizeRelayUrl(raw);
      if (norm === null) {
        setSyncStatus('⛔ Dirección no válida: debe empezar por https:// (sin usuario ni contraseña).');
        return;
      }
      state.syncRelayUrl = norm;
      if (relayInput) relayInput.value = norm;
      saveState(true);
      if (state.familySyncCode) connectFamilyCloudSync();
      setSyncStatus(norm ? `✅ Servidor guardado: ${norm}. Usad el mismo en todos los dispositivos.` : '✅ Se usará el servidor público por defecto (ntfy.sh).');
    });
  });

  // Recordar qué tarjetas tienen "Más opciones" desplegado (el evento toggle no burbujea: usamos captura)
  document.getElementById('apps-grid')?.addEventListener('toggle', e => {
    const det = e.target;
    if (!(det instanceof HTMLDetailsElement) || !det.classList.contains('card-more')) return;
    if (det.open) expandedCardIds.add(det.dataset.id);
    else expandedCardIds.delete(det.dataset.id);
  }, true);

  // Recordar si el panel de resumen está plegado o desplegado
  const summaryPanel = document.getElementById('summary-panel');
  if (summaryPanel) {
    if (safeStorageGet(UI_PREFS_KEY + ':summaryOpen') === '0') summaryPanel.open = false;
    summaryPanel.addEventListener('toggle', () => {
      safeStorageSet(UI_PREFS_KEY + ':summaryOpen', summaryPanel.open ? '1' : '0');
    });
  }

  // Tecla Escape: cierra menús y el modal superior que se pueda cerrar
  document.addEventListener('keydown', e => {
    if (e.key !== 'Escape') return;
    if (closeAllDropdowns()) return;
    const openModals = [...document.querySelectorAll('.modal-backdrop:not(.hidden)')]
      .filter(m => !NON_DISMISSIBLE.has(m.id));
    if (openModals.length) openModals[openModals.length - 1].classList.add('hidden');
  });
});

// ===== Privacidad y datos del usuario (todo es suyo y vive en su dispositivo) =====
function setPrivacyStatus(text) {
  const el = document.getElementById('privacy-status');
  if (el) el.textContent = text;
}

function exportUserData() {
  const backup = {
    app: 'ControlParen',
    tipo: 'copia-de-seguridad',
    version: 3,
    exportadoEl: new Date().toISOString(),
    state: { ...state, isParentUnlocked: false }
  };
  const blob = new Blob([JSON.stringify(backup, null, 2)], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `controlparen-copia-${getLocalDateKey()}.json`;
  document.body.appendChild(a);
  a.click();
  a.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);
  setPrivacyStatus('💾 Copia descargada. Guárdala en un lugar seguro: contiene el PIN parental y la licencia.');
}

async function importUserData(file) {
  try {
    const text = await file.text();
    const parsed = JSON.parse(text);
    const incoming = parsed && parsed.app === 'ControlParen' ? parsed.state : null;
    if (!incoming || typeof incoming !== 'object' || !Array.isArray(incoming.apps)) {
      throw new Error('El archivo no es una copia de ControlParen');
    }
    if (!confirm('¿Sustituir todos los datos de este dispositivo por los de la copia?')) return;
    const keepUnlocked = state.isParentUnlocked;
    const next = normalizeState(deepClone(incoming), { stopRunningOnNewDay: true });
    next.isParentUnlocked = keepUnlocked;
    // La licencia de la copia se vuelve a verificar (normalizeState) y este aparato se registra en ella
    if (next.license && next.license.isActivated) {
      const reg = Array.isArray(next.license.registeredDeviceIds) ? next.license.registeredDeviceIds : [];
      if (!reg.includes(CURRENT_DEVICE_FP)) {
        if (reg.length >= (next.license.maxDevices || 1)) next.license.isActivated = false;
        else reg.push(CURRENT_DEVICE_FP);
      }
      next.license.registeredDeviceIds = reg;
    }
    state = next;
    saveState(true);
    if (state.familySyncCode) connectFamilyCloudSync();
    renderAll();
    setPrivacyStatus('✅ Copia restaurada correctamente.');
  } catch (e) {
    setPrivacyStatus('⛔ No se pudo restaurar: ' + e.message);
  }
}

function wipeUserData() {
  if (!confirm('¿Borrar TODOS los datos de ControlParen de este dispositivo? No se puede deshacer (nadie más tiene una copia).')) return;
  if (!confirm('Última confirmación: se borrarán perfiles, tiempos, configuración y licencia de este dispositivo.')) return;
  if (syncEventSource) { syncEventSource.close(); syncEventSource = null; }
  try {
    [STORAGE_KEY, STORAGE_KEY + '_corrupt_backup', UI_PREFS_KEY + ':summaryOpen'].forEach(k => window.localStorage.removeItem(k));
  } catch (e) { /* almacenamiento no disponible */ }
  state = deepClone(DEFAULT_STATE);
  safeStorageSet(STORAGE_KEY, JSON.stringify(state));
  document.getElementById('modal-privacy')?.classList.add('hidden');
  renderAll();
}

// Service worker: guarda la app en el dispositivo para que funcione sin conexión y
// no dependa de la web donde se publicó una vez instalada.
function registerOfflineSupport() {
  if (!('serviceWorker' in navigator)) return;
  const isLocalhost = ['localhost', '127.0.0.1'].includes(location.hostname);
  if (location.protocol !== 'https:' && !isLocalhost) return;
  window.addEventListener('load', () => {
    navigator.serviceWorker.register('sw.js').catch(err => console.warn('Service worker no registrado:', err));
  });
}
registerOfflineSupport();

// ===== Menús desplegables (accesibles con teclado y táctiles) =====
function closeAllDropdowns() {
  let closedAny = false;
  document.querySelectorAll('.dropdown.open').forEach(dd => {
    dd.classList.remove('open');
    dd.querySelector('.dropdown-toggle')?.setAttribute('aria-expanded', 'false');
    closedAny = true;
  });
  return closedAny;
}

function initDropdowns() {
  document.querySelectorAll('.dropdown').forEach(dd => {
    const toggle = dd.querySelector('.dropdown-toggle');
    const menu = dd.querySelector('.dropdown-menu');
    if (!toggle || !menu) return;
    toggle.addEventListener('click', e => {
      e.stopPropagation();
      const willOpen = !dd.classList.contains('open');
      closeAllDropdowns();
      if (willOpen) {
        dd.classList.add('open');
        toggle.setAttribute('aria-expanded', 'true');
        menu.querySelector('.dropdown-item')?.focus({ preventScroll: true });
      }
    });
    // Al elegir una opción, el menú se cierra
    menu.addEventListener('click', e => {
      if (e.target.closest('.dropdown-item')) closeAllDropdowns();
    });
  });
  document.addEventListener('click', e => {
    if (!e.target.closest('.dropdown-menu, .dropdown-toggle')) closeAllDropdowns();
  });
}

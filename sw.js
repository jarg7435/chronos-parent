// Chronos Parent — Service worker
// Guarda una copia de la app en el propio dispositivo para que funcione sin conexión
// y no dependa de la web donde se publicó. No recoge, no envía y no guarda ningún
// dato del usuario: solo los archivos de la aplicación (HTML, CSS, JS y guías).
const CACHE_NAME = 'chronosparent-app-v4';
const APP_FILES = [
  './',
  './index.html',
  './styles.css',
  './app.js',
  './manifest.json',
  './GUIA-IPHONE-IPAD-PASO-A-PASO.html',
  './GUIA-ANDROID-MOVILES-Y-TABLETS.html',
  './GUIA-INSTALACION-PADRES.html',
  './icons/favicon.ico',
  './icons/favicon-32.png',
  './icons/icon-192.png',
  './icons/icon-512.png',
  './icons/apple-touch-icon.png',
  './icons/logo-chronos-parent.png'
];

self.addEventListener('install', event => {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(cache => cache.addAll(APP_FILES))
      .then(() => self.skipWaiting())
  );
});

self.addEventListener('activate', event => {
  event.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => (k.startsWith('controlparen-') || k.startsWith('chronosparent-')) && k !== CACHE_NAME).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

// Primero la copia local (arranque instantáneo y sin conexión); en segundo plano se
// descarga la versión publicada más reciente para la próxima apertura.
self.addEventListener('fetch', event => {
  const req = event.request;
  if (req.method !== 'GET') return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return; // la sincronización cifrada nunca pasa por aquí

  event.respondWith((async () => {
    const cache = await caches.open(CACHE_NAME);
    const cached = await cache.match(req, { ignoreSearch: req.mode === 'navigate' });
    const network = fetch(req)
      .then(res => {
        if (res && res.ok && res.type === 'basic') cache.put(req, res.clone());
        return res;
      })
      .catch(() => null);

    if (cached) {
      event.waitUntil(network);
      return cached;
    }
    const fresh = await network;
    if (fresh) return fresh;
    if (req.mode === 'navigate') {
      const shell = await cache.match('./index.html');
      if (shell) return shell;
    }
    return new Response('Sin conexión', { status: 503, headers: { 'Content-Type': 'text/plain; charset=utf-8' } });
  })());
});

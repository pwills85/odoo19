
const CACHE_NAME = 'financial-reports-v1';
const urlsToCache = [
  '/account_financial_report/static/src/css/financial_dashboard.css',
  '/account_financial_report/static/src/js/financial_dashboard.js',
  '/account_financial_report/static/src/scss/mobile_optimizations.scss',
  '/account_financial_report/static/manifest.json'
];

self.addEventListener('install', function(event) {
  event.waitUntil(
    caches.open(CACHE_NAME)
      .then(function(cache) {
        return cache.addAll(urlsToCache);
      })
  );
});

self.addEventListener('fetch', function(event) {
  event.respondWith(
    caches.match(event.request)
      .then(function(response) {
        // Return cached version or fetch from network
        return response || fetch(event.request);
      }
    )
  );
});

// Background sync for offline data
self.addEventListener('sync', function(event) {
  if (event.tag === 'background-sync') {
    event.waitUntil(syncOfflineData());
  }
});

function syncOfflineData() {
  // Sync offline changes when connection is restored
  return new Promise((resolve) => {
    // Implementation for syncing offline data
    resolve();
  });
}

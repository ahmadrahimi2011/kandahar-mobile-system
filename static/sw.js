// Service Worker for Kandahar Mobile System
const CACHE_NAME = 'kandahar-v1';

// Files jo offline bhi kaam karein (icons aur basic files)
const urlsToCache = [
    '/',
    '/static/icon-192.png',
    '/static/icon-512.png'
];

// Install event - cache store karein
self.addEventListener('install', event => {
    event.waitUntil(
        caches.open(CACHE_NAME)
            .then(cache => cache.addAll(urlsToCache))
    );
});

// Fetch event - pehle cache dekhein, agar nahi toh internet se laayein
self.addEventListener('fetch', event => {
    event.respondWith(
        caches.match(event.request)
            .then(response => {
                if (response) {
                    return response; // Cache se mil gaya
                }
                return fetch(event.request).then(
                    function(response) {
                        // Naye files ko cache mein store karein
                        if(!response || response.status !== 200 || response.type !== 'basic') {
                            return response;
                        }
                        var responseToCache = response.clone();
                        caches.open(CACHE_NAME)
                            .then(function(cache) {
                                cache.put(event.request, responseToCache);
                            });
                        return response;
                    }
                );
            })
    );
});
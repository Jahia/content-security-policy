/*
 * MIT License
 *
 * Copyright (c) 2002 - 2025 Jahia Solutions Group. All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
package org.jahia.modules.csp.actions;

import java.util.Iterator;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

/**
 * Minimal fixed-window, in-memory rate limiter used to throttle the unauthenticated CSP report endpoint.
 * <p>
 * Keys are typically client IP addresses ({@code request.getRemoteAddr()}); behind a reverse proxy this is
 * the proxy address unless the container is configured to resolve {@code X-Forwarded-For}, so the limit
 * should stay generous. The tracked-key set is bounded by {@code maxTrackedKeys}: when the bound is reached,
 * expired windows are evicted first, then the oldest live windows — never a full reset, so a key-spoofing
 * flood cannot hand every throttled client a fresh budget. This limiter is per-JVM-node, not cluster-wide
 * (a cluster of N nodes effectively multiplies the limit by N) — it is a noise/abuse mitigation, not a
 * substitute for an edge/WAF rate limit.
 */
final class SimpleRateLimiter {

    private final int maxRequests;
    private final long windowMillis;
    private final int maxTrackedKeys;
    private final ConcurrentHashMap<String, Window> windows = new ConcurrentHashMap<>();

    SimpleRateLimiter(int maxRequests, long windowMillis, int maxTrackedKeys) {
        this.maxRequests = maxRequests;
        this.windowMillis = windowMillis;
        this.maxTrackedKeys = maxTrackedKeys;
    }

    /**
     * Records a hit for the given key at the given instant and reports whether it is within the allowed rate.
     *
     * @param key the client identifier (a {@code null} key is bucketed under {@code "unknown"})
     * @param nowMillis the current time in epoch milliseconds (passed explicitly for testability)
     * @return {@code true} when the request is allowed, {@code false} when the rate is exceeded
     */
    boolean allow(String key, long nowMillis) {
        final String bucketKey = key == null ? "unknown" : key;
        evictIfNeeded(nowMillis);
        final Window window = windows.compute(bucketKey, (k, current) -> {
            if (current == null || nowMillis - current.start >= windowMillis) {
                return new Window(nowMillis, 1);
            }
            return new Window(current.start, current.count + 1);
        });
        return window.count <= maxRequests;
    }

    private void evictIfNeeded(long nowMillis) {
        if (windows.size() < maxTrackedKeys) {
            return;
        }
        for (Iterator<Map.Entry<String, Window>> it = windows.entrySet().iterator(); it.hasNext(); ) {
            if (nowMillis - it.next().getValue().start >= windowMillis) {
                it.remove();
            }
        }
        // Still full (a flood of live keys): evict the oldest windows one by one instead of clearing the
        // map — a full reset would gift every throttled client a fresh budget, defeating the limiter.
        while (windows.size() >= maxTrackedKeys) {
            String oldestKey = null;
            long oldestStart = Long.MAX_VALUE;
            for (Map.Entry<String, Window> entry : windows.entrySet()) {
                if (entry.getValue().start < oldestStart) {
                    oldestStart = entry.getValue().start;
                    oldestKey = entry.getKey();
                }
            }
            if (oldestKey == null) {
                return;
            }
            windows.remove(oldestKey);
        }
    }

    /** Immutable per-key counting window. */
    private static final class Window {
        private final long start;
        private final int count;

        private Window(long start, int count) {
            this.start = start;
            this.count = count;
        }
    }
}

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

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link SimpleRateLimiter}. The clock is passed explicitly, so every scenario is
 * deterministic.
 */
@DisplayName("SimpleRateLimiter")
class SimpleRateLimiterTest {

    private static final long WINDOW = 60_000L;
    private static final long T0 = 1_000_000L;

    @Test
    @DisplayName("allows up to the limit within one window and denies the request after it")
    void allow_overLimitInWindow_isDenied() {
        // Arrange
        SimpleRateLimiter limiter = new SimpleRateLimiter(3, WINDOW, 100);

        // Act / Assert
        assertThat(limiter.allow("ip-1", T0)).isTrue();
        assertThat(limiter.allow("ip-1", T0 + 1)).isTrue();
        assertThat(limiter.allow("ip-1", T0 + 2)).isTrue();
        assertThat(limiter.allow("ip-1", T0 + 3)).isFalse();
    }

    @Test
    @DisplayName("resets the counter once the window has elapsed")
    void allow_afterWindowElapsed_isAllowedAgain() {
        // Arrange
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, WINDOW, 100);
        limiter.allow("ip-1", T0);
        assertThat(limiter.allow("ip-1", T0 + 1)).isFalse();

        // Act / Assert — a new window starts
        assertThat(limiter.allow("ip-1", T0 + WINDOW)).isTrue();
    }

    @Test
    @DisplayName("tracks each key independently")
    void allow_distinctKeys_areIndependent() {
        // Arrange
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, WINDOW, 100);
        limiter.allow("ip-1", T0);

        // Act / Assert — exhausting ip-1 does not affect ip-2
        assertThat(limiter.allow("ip-1", T0 + 1)).isFalse();
        assertThat(limiter.allow("ip-2", T0 + 1)).isTrue();
    }

    @Test
    @DisplayName("buckets a null key under a shared key instead of failing")
    void allow_nullKey_isBucketed() {
        // Arrange
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, WINDOW, 100);

        // Act / Assert
        assertThat(limiter.allow(null, T0)).isTrue();
        assertThat(limiter.allow(null, T0 + 1)).isFalse();
    }

    @Test
    @DisplayName("evicts expired windows when the tracked-key bound is reached and keeps working")
    void allow_keyBoundReached_evictsExpiredAndKeepsWorking() {
        // Arrange — bound of 2 keys, both expired by the time the third arrives
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, WINDOW, 2);
        limiter.allow("ip-1", T0);
        limiter.allow("ip-2", T0);

        // Act / Assert — at T0 + WINDOW both stored windows are stale and are evicted
        assertThat(limiter.allow("ip-3", T0 + WINDOW)).isTrue();
        assertThat(limiter.allow("ip-3", T0 + WINDOW + 1)).isFalse();
    }

    @Test
    @DisplayName("evicts only the oldest live window at the bound — a throttled client is never reset by the flood")
    void allow_keyBoundReachedWithLiveKeys_evictsOldestOnly() {
        // Arrange — bound of 3 keys, all live; ip-3 (the newest) gets throttled
        SimpleRateLimiter limiter = new SimpleRateLimiter(1, WINDOW, 3);
        assertThat(limiter.allow("ip-1", T0)).isTrue();
        assertThat(limiter.allow("ip-2", T0 + 10)).isTrue();
        assertThat(limiter.allow("ip-3", T0 + 20)).isTrue();

        // Act / Assert — at the bound, each call evicts only the OLDEST window (ip-1, then ip-2):
        // ip-3 keeps its counter across the churn and stays throttled. The previous clear-all
        // backstop would have reset it to a fresh budget here.
        assertThat(limiter.allow("ip-3", T0 + 21)).isFalse();
        assertThat(limiter.allow("ip-4", T0 + 30)).isTrue();
        assertThat(limiter.allow("ip-3", T0 + 31)).isFalse();
    }
}

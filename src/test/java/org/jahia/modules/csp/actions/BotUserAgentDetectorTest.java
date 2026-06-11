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

import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.regex.Pattern;
import org.json.JSONArray;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

/**
 * Tests for {@link BotUserAgentDetector}: detection against the vendored crawler-user-agents list
 * (real bot and real browser user agents), and robustness of the pattern loading helpers.
 */
@DisplayName("BotUserAgentDetector")
class BotUserAgentDetectorTest {

    @Nested
    @DisplayName("isBot with the vendored pattern list")
    class IsBot {

        @ParameterizedTest(name = "flags a self-declared bot: {0}")
        @ValueSource(strings = {
                "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
                "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
                "Mozilla/5.0 (compatible; UptimeRobot/2.0; http://www.uptimerobot.com/)",
                "Mozilla/5.0 (compatible; AhrefsBot/7.0; +http://ahrefs.com/robot/)",
                // The exact shape seen in production (JAHIACOM-1582)
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36"})
        void isBot_botUserAgent_returnsTrue(String userAgent) {
            assertThat(BotUserAgentDetector.isBot(userAgent)).isTrue();
        }

        @ParameterizedTest(name = "does not flag a real browser: {0}")
        @ValueSource(strings = {
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
                "Mozilla/5.0 (X11; Linux x86_64; rv:126.0) Gecko/20100101 Firefox/126.0",
                "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1"})
        void isBot_realBrowserUserAgent_returnsFalse(String userAgent) {
            assertThat(BotUserAgentDetector.isBot(userAgent)).isFalse();
        }

        @Test
        @DisplayName("does not flag a missing user agent")
        void isBot_nullUserAgent_returnsFalse() {
            assertThat(BotUserAgentDetector.isBot(null)).isFalse();
        }

        @Test
        @DisplayName("does not flag the 'unknown user agent' log placeholder")
        void isBot_unknownPlaceholder_returnsFalse() {
            assertThat(BotUserAgentDetector.isBot("unknown user agent")).isFalse();
        }
    }

    @Nested
    @DisplayName("combinePatterns")
    class CombinePatterns {

        @Test
        @DisplayName("skips patterns that are not valid Java regexes but keeps the valid ones")
        void combinePatterns_invalidEntry_skippedNotFatal() {
            // Arrange — "[broken" does not compile; "Googlebot" does
            final List<String> patterns = Arrays.asList("[broken", "Googlebot");

            // Act
            final Pattern combined = BotUserAgentDetector.combinePatterns(patterns);

            // Assert
            assertThat(combined).isNotNull();
            assertThat(combined.matcher("Mozilla/5.0 (compatible; Googlebot/2.1)").find()).isTrue();
            assertThat(combined.matcher("Mozilla/5.0 [broken").find()).isFalse();
        }

        @Test
        @DisplayName("returns null when no pattern is usable, disabling detection")
        void combinePatterns_noUsablePattern_returnsNull() {
            assertThat(BotUserAgentDetector.combinePatterns(Collections.singletonList("[broken"))).isNull();
            assertThat(BotUserAgentDetector.combinePatterns(Collections.emptyList())).isNull();
        }

        @Test
        @DisplayName("isolates alternation between patterns with non-capturing groups")
        void combinePatterns_alternationDoesNotBleedAcrossPatterns() {
            // Arrange — anchors must stay scoped to their own pattern when joined with "|"
            final Pattern combined = BotUserAgentDetector.combinePatterns(Arrays.asList("^crawler", "spider$"));

            // Act / Assert
            assertThat(combined.matcher("crawler something").find()).isTrue();
            assertThat(combined.matcher("something spider").find()).isTrue();
            assertThat(combined.matcher("something crawler something").find()).isFalse();
        }
    }

    @Nested
    @DisplayName("extractPatterns")
    class ExtractPatterns {

        @Test
        @DisplayName("collects the pattern field of every entry, skipping entries without one")
        void extractPatterns_mixedEntries_skipsBlankAndMissing() {
            // Arrange — upstream entries carry pattern/url/instances; only pattern matters here
            final JSONArray entries = new JSONArray(
                    "[{\"pattern\":\"Googlebot\",\"url\":\"http://www.google.com/bot.html\"},"
                            + "{\"pattern\":\"\"},"
                            + "{\"url\":\"https://no-pattern.example\"},"
                            + "{\"pattern\":\"bingbot\"}]");

            // Act / Assert
            assertThat(BotUserAgentDetector.extractPatterns(entries)).containsExactly("Googlebot", "bingbot");
        }
    }
}

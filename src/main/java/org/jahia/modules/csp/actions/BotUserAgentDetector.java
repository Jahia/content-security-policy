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

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.StringJoiner;
import java.util.regex.Pattern;
import java.util.regex.PatternSyntaxException;
import org.json.JSONArray;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Identifies self-declared bots and crawlers from the {@code User-Agent} request header, using the
 * community-maintained <a href="https://github.com/monperrus/crawler-user-agents">crawler-user-agents</a>
 * pattern list (MIT licensed) vendored at {@value #PATTERNS_RESOURCE}. To refresh the list, replace that
 * file with the latest {@code crawler-user-agents.json} from the upstream repository — no code change needed.
 * <p>
 * The User-Agent header is client-controlled, so this is a <strong>log-noise filter, not a security
 * control</strong>: callers must keep accepting (and rate-limit counting) the reports, and only demote
 * their log level. Patterns are matched case-sensitively, as upstream designs them.
 * <p>
 * If the vendored list is missing or unreadable, detection is disabled (everything reported as non-bot):
 * the endpoint then fails open to a noisier warning log rather than silently dropping report visibility.
 */
final class BotUserAgentDetector {

    private static final Logger LOGGER = LoggerFactory.getLogger(BotUserAgentDetector.class);
    /** Vendored copy of crawler-user-agents.json; refresh by replacing the file with the upstream version. */
    static final String PATTERNS_RESOURCE = "/META-INF/crawler-user-agents.json";
    private static final String KEY_PATTERN = "pattern";

    /** Single alternation over all valid patterns, compiled once; {@code null} when detection is disabled. */
    private static final Pattern BOT_PATTERN = loadBotPattern();

    private BotUserAgentDetector() {
        // static utility
    }

    /**
     * @param userAgent the raw {@code User-Agent} header value (may be {@code null})
     * @return {@code true} when the user agent declares itself as a known bot, crawler or monitoring tool
     */
    static boolean isBot(String userAgent) {
        return BOT_PATTERN != null && userAgent != null && BOT_PATTERN.matcher(userAgent).find();
    }

    private static Pattern loadBotPattern() {
        try (InputStream input = BotUserAgentDetector.class.getResourceAsStream(PATTERNS_RESOURCE)) {
            if (input == null) {
                LOGGER.warn("Bot pattern list {} not found on the classpath, bot report filtering is disabled", PATTERNS_RESOURCE);
                return null;
            }
            final String json = new String(input.readAllBytes(), StandardCharsets.UTF_8);
            return combinePatterns(extractPatterns(new JSONArray(json)));
        } catch (IOException | RuntimeException ex) {
            // Never let a bad data file break the report endpoint: disable the filter instead.
            LOGGER.warn("Could not load bot pattern list {}, bot report filtering is disabled", PATTERNS_RESOURCE, ex);
            return null;
        }
    }

    /** Pulls the {@code pattern} field of every entry of the upstream JSON array, skipping blank ones. */
    static List<String> extractPatterns(JSONArray entries) {
        final List<String> patterns = new ArrayList<>(entries.length());
        for (int i = 0; i < entries.length(); i++) {
            final String pattern = entries.getJSONObject(i).optString(KEY_PATTERN, "");
            if (!pattern.isEmpty()) {
                patterns.add(pattern);
            }
        }
        return patterns;
    }

    /**
     * Joins the individually-validated patterns into one non-capturing alternation so a user agent is
     * checked with a single regex evaluation. Patterns that do not compile (upstream targets several regex
     * dialects) are skipped and counted rather than failing the whole list.
     *
     * @return the combined pattern, or {@code null} when no pattern is usable
     */
    static Pattern combinePatterns(List<String> patterns) {
        final StringJoiner alternation = new StringJoiner("|");
        int invalid = 0;
        for (String pattern : patterns) {
            if (isValidRegex(pattern)) {
                alternation.add("(?:" + pattern + ")");
            } else {
                invalid++;
            }
        }
        if (invalid > 0) {
            LOGGER.warn("Skipped {} bot user-agent patterns that are not valid Java regular expressions", invalid);
        }
        return alternation.length() == 0 ? null : Pattern.compile(alternation.toString());
    }

    private static boolean isValidRegex(String pattern) {
        try {
            Pattern.compile(pattern);
            return true;
        } catch (PatternSyntaxException ex) {
            LOGGER.debug("Invalid bot user-agent pattern skipped: {}", CspViolation.sanitizeForLog(pattern), ex);
            return false;
        }
    }
}

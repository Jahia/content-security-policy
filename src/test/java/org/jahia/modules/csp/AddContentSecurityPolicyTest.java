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
package org.jahia.modules.csp;

import static org.assertj.core.api.Assertions.assertThat;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for the pure policy- and nonce-building helpers of {@link AddContentSecurityPolicy}.
 */
@DisplayName("AddContentSecurityPolicy helpers")
class AddContentSecurityPolicyTest {

    @Nested
    @DisplayName("buildPolicyValue")
    class BuildPolicyValue {

        @Test
        @DisplayName("appends report-uri and report-to when the author declared neither")
        void appendsReportingDirectivesWhenAbsent() {
            String result = AddContentSecurityPolicy.buildPolicyValue("default-src 'self'", "ABC", "/r.do");

            assertThat(result).isEqualTo("default-src 'self'; report-uri /r.do; report-to csp-endpoint");
        }

        @Test
        @DisplayName("substitutes the nonce into the nonce- placeholder")
        void substitutesNoncePlaceholder() {
            String result = AddContentSecurityPolicy.buildPolicyValue("script-src 'nonce-'", "ABC", "/r.do");

            assertThat(result).startsWith("script-src 'nonce-ABC'");
        }

        @Test
        @DisplayName("does not duplicate report-uri when the author already declared one")
        void doesNotDuplicateReportUri() {
            String result = AddContentSecurityPolicy.buildPolicyValue(
                    "default-src 'self'; report-uri /custom", "ABC", "/default.do");

            // report-to is still appended since the author did not declare it
            assertThat(result)
                    .contains("report-uri /custom")
                    .doesNotContain("/default.do")
                    .contains("report-to csp-endpoint");
        }

        @Test
        @DisplayName("normalises a trailing separator instead of emitting a double semicolon")
        void normalisesTrailingSeparator() {
            String result = AddContentSecurityPolicy.buildPolicyValue("default-src 'self';", "ABC", "/r.do");

            assertThat(result)
                    .isEqualTo("default-src 'self'; report-uri /r.do; report-to csp-endpoint")
                    .doesNotContain(";;");
        }
    }

    @Nested
    @DisplayName("containsDirective")
    class ContainsDirective {

        @Test
        @DisplayName("detects an existing directive with a value")
        void detectsExistingDirective() {
            assertThat(AddContentSecurityPolicy.containsDirective(
                    "default-src 'self'; report-uri /r", "report-uri")).isTrue();
        }

        @Test
        @DisplayName("is case-insensitive")
        void isCaseInsensitive() {
            assertThat(AddContentSecurityPolicy.containsDirective(
                    "REPORT-URI /r", "report-uri")).isTrue();
        }

        @Test
        @DisplayName("returns false when the directive is absent")
        void returnsFalseWhenAbsent() {
            assertThat(AddContentSecurityPolicy.containsDirective(
                    "default-src 'self'", "report-uri")).isFalse();
        }

        @Test
        @DisplayName("does not match a directive name that is only a substring of a token")
        void doesNotMatchSubstring() {
            assertThat(AddContentSecurityPolicy.containsDirective(
                    "default-src 'self'", "src")).isFalse();
        }
    }

    @Nested
    @DisplayName("applyNonce")
    class ApplyNonce {

        @Test
        @DisplayName("injects the nonce into a script tag")
        void injectsNonceIntoScript() {
            String result = AddContentSecurityPolicy.applyNonce("<script src='a.js'></script>", "script", "N");

            assertThat(result).contains("<script nonce=\"N\" src='a.js'>");
        }

        @Test
        @DisplayName("injects the nonce into a style tag")
        void injectsNonceIntoStyle() {
            String result = AddContentSecurityPolicy.applyNonce("<style>.a{}</style>", "style", "N");

            assertThat(result).contains("<style nonce=\"N\">");
        }

        @Test
        @DisplayName("injects the nonce into a stylesheet link tag")
        void injectsNonceIntoLink() {
            String result = AddContentSecurityPolicy.applyNonce(
                    "<link rel=\"stylesheet\" href=\"a.css\">", "link", "N");

            assertThat(result).contains("<link nonce=\"N\" rel=\"stylesheet\"");
        }

        @Test
        @DisplayName("replaces a pre-existing nonce rather than adding a second one")
        void replacesExistingNonce() {
            String result = AddContentSecurityPolicy.applyNonce(
                    "<script nonce=\"OLD\" src='a.js'>", "script", "N");

            assertThat(result)
                    .contains("nonce=\"N\"")
                    .doesNotContain("OLD");
        }

        @Test
        @DisplayName("matches tags case-insensitively")
        void matchesCaseInsensitively() {
            String result = AddContentSecurityPolicy.applyNonce("<SCRIPT>", "script", "N");

            assertThat(result).contains("nonce=\"N\"");
        }

        @Test
        @DisplayName("handles a long attribute list without a nonce (regex backtracking regression guard)")
        void handlesLongAttributesWithoutNonce() {
            // Arrange — a tag with a very long attribute string and no nonce: the old .*? pattern
            // degraded quadratically on this shape. A backtracking regression would hang this test
            // into the surefire timeout, which is signal enough — no wall-clock assertion needed.
            String longAttributes = "data-config=\"" + "x".repeat(10_000) + "\"";
            String html = "<script " + longAttributes + " src='a.js'></script>";

            // Act
            String result = AddContentSecurityPolicy.applyNonce(html, "script", "N");

            // Assert
            assertThat(result).contains("<script nonce=\"N\" " + longAttributes);
        }

        @Test
        @DisplayName("injects the nonce into a self-closing link tag")
        void injectsNonceIntoSelfClosingLink() {
            String result = AddContentSecurityPolicy.applyNonce(
                    "<link rel=\"stylesheet\" href=\"a.css\"/>", "link", "N");

            assertThat(result).isEqualTo("<link nonce=\"N\" rel=\"stylesheet\" href=\"a.css\"/>");
        }

        @Test
        @DisplayName("injects the nonce into a bare script tag with no attributes")
        void injectsNonceIntoBareScriptTag() {
            String result = AddContentSecurityPolicy.applyNonce(
                    "<script>alert(1)</script>", "script", "N");

            assertThat(result).isEqualTo("<script nonce=\"N\">alert(1)</script>");
        }
    }

    @Nested
    @DisplayName("isValidReportUrl")
    class IsValidReportUrl {

        @Test
        @DisplayName("accepts absolute http and https URLs")
        void acceptsHttpAndHttps() {
            assertThat(AddContentSecurityPolicy.isValidReportUrl("https://reports.example.com/csp")).isTrue();
            assertThat(AddContentSecurityPolicy.isValidReportUrl("http://reports.example.com/csp")).isTrue();
        }

        @Test
        @DisplayName("rejects non-http(s) schemes that java.net.URL would accept")
        void rejectsDangerousSchemes() {
            assertThat(AddContentSecurityPolicy.isValidReportUrl("file:///etc/passwd")).isFalse();
            assertThat(AddContentSecurityPolicy.isValidReportUrl("ftp://internal.host/r")).isFalse();
        }

        @Test
        @DisplayName("rejects URLs containing control characters (header injection)")
        void rejectsControlCharacters() {
            assertThat(AddContentSecurityPolicy.isValidReportUrl("https://ok.example.com/\r\nX-Injected: evil")).isFalse();
            assertThat(AddContentSecurityPolicy.isValidReportUrl("https://ok.example.com/ ")).isFalse();
        }

        @Test
        @DisplayName("rejects malformed, empty and null values")
        void rejectsMalformedValues() {
            assertThat(AddContentSecurityPolicy.isValidReportUrl("not a url")).isFalse();
            assertThat(AddContentSecurityPolicy.isValidReportUrl("")).isFalse();
            assertThat(AddContentSecurityPolicy.isValidReportUrl(null)).isFalse();
        }
    }

    @Nested
    @DisplayName("sanitizeHeaderValue")
    class SanitizeHeaderValue {

        @Test
        @DisplayName("collapses CR/LF to a space (response splitting defence)")
        void collapsesCrlf() {
            assertThat(AddContentSecurityPolicy.sanitizeHeaderValue("default-src 'self';\r\nscript-src 'self'"))
                    .isEqualTo("default-src 'self'; script-src 'self'");
        }

        @Test
        @DisplayName("leaves a clean single-line value untouched")
        void leavesCleanValueUntouched() {
            assertThat(AddContentSecurityPolicy.sanitizeHeaderValue("default-src 'self'"))
                    .isEqualTo("default-src 'self'");
        }

        @Test
        @DisplayName("buildPolicyValue turns a multi-line textarea policy into a valid single-line header")
        void buildPolicyValueAcceptsMultilinePolicy() {
            // Arrange — the multi-line layout our README examples encourage
            String multiline = "default-src 'self';\nscript-src 'nonce-';\nobject-src 'none'";

            // Act
            String result = AddContentSecurityPolicy.buildPolicyValue(multiline, "ABC", "/r.do");

            // Assert
            assertThat(result)
                    .doesNotContain("\n")
                    .doesNotContain("\r")
                    .startsWith("default-src 'self'; script-src 'nonce-ABC'; object-src 'none'")
                    .contains("report-uri /r.do");
        }
    }
}

/*
 * MIT License
 *
 * Copyright (c) 2002 - 2022 Jahia Solutions Group. All rights reserved.
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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import org.json.JSONException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ReportOnlyAction#parseCspReport(String)}, the pure CSP-violation-report parser.
 * <p>
 * The triple returned by the parser is ordered {@code [document-url, effective-directive, blocked-url]} —
 * matching the order in which {@code doExecute} formats its {@code LOGGER.warn} message.
 */
@DisplayName("ReportOnlyAction.parseCspReport")
class ReportOnlyActionTest {

    private static final int DOCUMENT_URL = 0;
    private static final int EFFECTIVE_DIRECTIVE = 1;
    private static final int BLOCKED_URL = 2;

    @Test
    @DisplayName("parses the legacy Firefox application/csp-report object")
    void parseCspReport_firefoxObject_returnsViolationTriple() {
        // Arrange — Firefox kebab-case keys nested under "csp-report"
        String report = "{\"csp-report\":{"
                + "\"document-uri\":\"https://example.com/page\","
                + "\"effective-directive\":\"script-src\","
                + "\"blocked-uri\":\"https://evil.com/x.js\"}}";

        // Act
        String[] violation = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violation).isNotNull();
        assertThat(violation[DOCUMENT_URL]).isEqualTo("https://example.com/page");
        assertThat(violation[EFFECTIVE_DIRECTIVE]).isEqualTo("script-src");
        assertThat(violation[BLOCKED_URL]).isEqualTo("https://evil.com/x.js");
    }

    @Test
    @DisplayName("parses the Chrome Reporting API array (application/reports+json)")
    void parseCspReport_chromeArray_returnsViolationTriple() {
        // Arrange — Chrome camelCase keys nested under "body", wrapped in an array
        String report = "[{\"type\":\"csp-violation\",\"body\":{"
                + "\"documentURL\":\"https://example.com/page\","
                + "\"effectiveDirective\":\"script-src-elem\","
                + "\"blockedURL\":\"https://evil.com/x.js\"}}]";

        // Act
        String[] violation = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violation).isNotNull();
        assertThat(violation[DOCUMENT_URL]).isEqualTo("https://example.com/page");
        assertThat(violation[EFFECTIVE_DIRECTIVE]).isEqualTo("script-src-elem");
        assertThat(violation[BLOCKED_URL]).isEqualTo("https://evil.com/x.js");
    }

    @Test
    @DisplayName("parses a Chrome Reporting API report delivered as a bare object (regression: previously dropped)")
    void parseCspReport_chromeBareObject_returnsViolationTriple() {
        // Arrange — a "body" report NOT wrapped in an array; the old code re-parsed the
        // payload as a JSONArray here and threw, silently dropping the report.
        String report = "{\"type\":\"csp-violation\",\"body\":{"
                + "\"documentURL\":\"https://example.com/page\","
                + "\"effectiveDirective\":\"img-src\","
                + "\"blockedURL\":\"https://evil.com/i.png\"}}";

        // Act
        String[] violation = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violation).isNotNull();
        assertThat(violation[DOCUMENT_URL]).isEqualTo("https://example.com/page");
        assertThat(violation[EFFECTIVE_DIRECTIVE]).isEqualTo("img-src");
        assertThat(violation[BLOCKED_URL]).isEqualTo("https://evil.com/i.png");
    }

    @Test
    @DisplayName("falls back to 'unknown' placeholders for missing body fields")
    void parseCspReport_missingFields_returnsUnknownPlaceholders() {
        // Arrange — body present but every detail field absent
        String report = "{\"csp-report\":{}}";

        // Act
        String[] violation = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violation).isNotNull();
        assertThat(violation[DOCUMENT_URL]).isEqualTo("unknown document url");
        assertThat(violation[EFFECTIVE_DIRECTIVE]).isEqualTo("unknown effective directive");
        assertThat(violation[BLOCKED_URL]).isEqualTo("unknown url");
    }

    @Test
    @DisplayName("returns all-unknown placeholders when neither csp-report nor body key is present")
    void parseCspReport_unrecognisedShape_returnsUnknownPlaceholders() {
        // Arrange — valid JSON object but not a CSP report we understand
        String report = "{\"something\":\"else\"}";

        // Act
        String[] violation = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violation)
                .containsExactly("unknown document url", "unknown effective directive", "unknown url");
    }

    @Test
    @DisplayName("returns null for a payload that is neither a JSON object nor array")
    void parseCspReport_nonJsonPayload_returnsNull() {
        // Arrange — plain text the caller must answer with BAD_REQUEST
        String report = "this is not json";

        // Act
        String[] violation = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violation).isNull();
    }

    @Test
    @DisplayName("throws JSONException for a malformed JSON object")
    void parseCspReport_malformedObject_throwsJsonException() {
        // Arrange — starts like an object but is truncated
        String report = "{\"csp-report\":";

        // Act / Assert
        assertThatThrownBy(() -> ReportOnlyAction.parseCspReport(report))
                .isInstanceOf(JSONException.class);
    }

    @Test
    @DisplayName("throws JSONException for an empty JSON array")
    void parseCspReport_emptyArray_throwsJsonException() {
        // Arrange — getJSONObject(0) on an empty array has no first element
        String report = "[]";

        // Act / Assert
        assertThatThrownBy(() -> ReportOnlyAction.parseCspReport(report))
                .isInstanceOf(JSONException.class);
    }
}

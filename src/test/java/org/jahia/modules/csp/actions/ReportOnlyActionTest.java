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
import static org.assertj.core.api.Assertions.assertThatThrownBy;

import java.util.List;
import org.json.JSONException;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * Unit tests for {@link ReportOnlyAction#parseCspReport(String)} — the pure CSP-violation-report parser —
 * and for the {@link CspViolation} log formatting it produces.
 */
@DisplayName("ReportOnlyAction.parseCspReport")
class ReportOnlyActionTest {

    @Test
    @DisplayName("parses the legacy Firefox application/csp-report object")
    void parseCspReport_firefoxObject_returnsSingleViolation() {
        // Arrange — Firefox kebab-case keys nested under "csp-report"
        String report = "{\"csp-report\":{"
                + "\"document-uri\":\"https://example.com/page\","
                + "\"effective-directive\":\"script-src\","
                + "\"blocked-uri\":\"https://evil.com/x.js\"}}";

        // Act
        List<CspViolation> violations = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violations).hasSize(1);
        CspViolation violation = violations.get(0);
        assertThat(violation.getDocumentUrl()).isEqualTo("https://example.com/page");
        assertThat(violation.getEffectiveDirective()).isEqualTo("script-src");
        assertThat(violation.getBlockedUrl()).isEqualTo("https://evil.com/x.js");
    }

    @Test
    @DisplayName("parses the Chrome Reporting API array (application/reports+json)")
    void parseCspReport_chromeArray_returnsSingleViolation() {
        // Arrange — Chrome camelCase keys nested under "body", wrapped in an array
        String report = "[{\"type\":\"csp-violation\",\"body\":{"
                + "\"documentURL\":\"https://example.com/page\","
                + "\"effectiveDirective\":\"script-src-elem\","
                + "\"blockedURL\":\"https://evil.com/x.js\"}}]";

        // Act
        List<CspViolation> violations = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).getEffectiveDirective()).isEqualTo("script-src-elem");
        assertThat(violations.get(0).getBlockedUrl()).isEqualTo("https://evil.com/x.js");
    }

    @Test
    @DisplayName("parses a Chrome report delivered as a bare object (regression: previously dropped)")
    void parseCspReport_chromeBareObject_returnsSingleViolation() {
        // Arrange — a "body" report NOT wrapped in an array
        String report = "{\"type\":\"csp-violation\",\"body\":{"
                + "\"documentURL\":\"https://example.com/page\","
                + "\"effectiveDirective\":\"img-src\","
                + "\"blockedURL\":\"https://evil.com/i.png\"}}";

        // Act
        List<CspViolation> violations = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).getEffectiveDirective()).isEqualTo("img-src");
        assertThat(violations.get(0).getBlockedUrl()).isEqualTo("https://evil.com/i.png");
    }

    @Test
    @DisplayName("parses every report in a batched Reporting API array")
    void parseCspReport_batchedArray_returnsOneViolationPerEntry() {
        // Arrange — the Reporting API batches multiple violations in one POST
        String report = "[{\"body\":{\"documentURL\":\"https://example.com/a\","
                + "\"effectiveDirective\":\"script-src\",\"blockedURL\":\"https://evil.com/a.js\"}},"
                + "{\"body\":{\"documentURL\":\"https://example.com/b\","
                + "\"effectiveDirective\":\"style-src\",\"blockedURL\":\"https://evil.com/b.css\"}}]";

        // Act
        List<CspViolation> violations = ReportOnlyAction.parseCspReport(report);

        // Assert — both entries are captured, not just the first
        assertThat(violations).hasSize(2);
        assertThat(violations).extracting(CspViolation::getBlockedUrl)
                .containsExactly("https://evil.com/a.js", "https://evil.com/b.css");
    }

    @Test
    @DisplayName("falls back to violated-directive when effective-directive is absent (CSP2 / older Firefox)")
    void parseCspReport_violatedDirectiveFallback_usesViolatedDirective() {
        // Arrange — only the CSP2 "violated-directive" field is present
        String report = "{\"csp-report\":{"
                + "\"document-uri\":\"https://example.com/page\","
                + "\"violated-directive\":\"script-src https://example.com\","
                + "\"blocked-uri\":\"https://evil.com/x.js\"}}";

        // Act
        List<CspViolation> violations = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violations.get(0).getEffectiveDirective()).isEqualTo("script-src https://example.com");
    }

    @Test
    @DisplayName("captures the source location and sample when the browser provides them")
    void parseCspReport_withSourceLocation_capturesAllFields() {
        // Arrange
        String report = "{\"csp-report\":{"
                + "\"document-uri\":\"https://example.com/page\","
                + "\"effective-directive\":\"script-src\","
                + "\"blocked-uri\":\"https://evil.com/x.js\","
                + "\"source-file\":\"https://example.com/app.js\","
                + "\"line-number\":42,\"column-number\":7,"
                + "\"script-sample\":\"eval(danger)\"}}";

        // Act
        CspViolation violation = ReportOnlyAction.parseCspReport(report).get(0);

        // Assert — source location and sample surface in the log message for triage
        assertThat(violation.getSourceFile()).isEqualTo("https://example.com/app.js");
        assertThat(violation.getLineNumber()).isEqualTo("42");
        assertThat(violation.getColumnNumber()).isEqualTo("7");
        assertThat(violation.toLogMessage("UA"))
                .isEqualTo("https://evil.com/x.js blocked for script-src on https://example.com/page"
                        + " at https://example.com/app.js:42:7 (sample: eval(danger)) with user-agent \"UA\"");
    }

    @Test
    @DisplayName("omits the optional source location from the log message when absent")
    void toLogMessage_withoutSourceLocation_omitsLocationSegment() {
        // Arrange
        String report = "{\"csp-report\":{\"document-uri\":\"https://example.com/page\","
                + "\"effective-directive\":\"script-src\",\"blocked-uri\":\"https://evil.com/x.js\"}}";

        // Act
        String message = ReportOnlyAction.parseCspReport(report).get(0).toLogMessage("UA");

        // Assert
        assertThat(message)
                .isEqualTo("https://evil.com/x.js blocked for script-src on https://example.com/page"
                        + " with user-agent \"UA\"")
                .doesNotContain(" at ")
                .doesNotContain("sample:");
    }

    @Test
    @DisplayName("falls back to 'unknown' placeholders for missing body fields")
    void parseCspReport_missingFields_returnsUnknownPlaceholders() {
        // Arrange — body present but every detail field absent
        String report = "{\"csp-report\":{}}";

        // Act
        CspViolation violation = ReportOnlyAction.parseCspReport(report).get(0);

        // Assert
        assertThat(violation.getDocumentUrl()).isEqualTo("unknown document url");
        assertThat(violation.getEffectiveDirective()).isEqualTo("unknown effective directive");
        assertThat(violation.getBlockedUrl()).isEqualTo("unknown url");
        assertThat(violation.getSourceFile()).isNull();
    }

    @Test
    @DisplayName("returns an unknown violation when neither csp-report nor body key is present")
    void parseCspReport_unrecognisedShape_returnsUnknownViolation() {
        // Arrange — valid JSON object but not a CSP report we understand
        String report = "{\"something\":\"else\"}";

        // Act
        List<CspViolation> violations = ReportOnlyAction.parseCspReport(report);

        // Assert
        assertThat(violations).hasSize(1);
        assertThat(violations.get(0).getEffectiveDirective()).isEqualTo("unknown effective directive");
    }

    @Test
    @DisplayName("returns null for a payload that is neither a JSON object nor array")
    void parseCspReport_nonJsonPayload_returnsNull() {
        // Arrange — plain text the caller must answer with BAD_REQUEST
        String report = "this is not json";

        // Act / Assert
        assertThat(ReportOnlyAction.parseCspReport(report)).isNull();
    }

    @Test
    @DisplayName("returns an empty list for an empty JSON array")
    void parseCspReport_emptyArray_returnsEmptyList() {
        // Arrange — a batch with no entries
        String report = "[]";

        // Act / Assert
        assertThat(ReportOnlyAction.parseCspReport(report)).isEmpty();
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
}

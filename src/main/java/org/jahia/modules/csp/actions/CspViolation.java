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

/**
 * Immutable description of a single CSP violation, normalised from either the legacy
 * {@code application/csp-report} payload or the Reporting API {@code application/reports+json} payload.
 * <p>
 * The mandatory fields (document URL, effective directive, blocked URL) always carry a value — falling
 * back to the {@code UNKNOWN_*} placeholders. The source-location and sample fields are optional and are
 * {@code null} when the browser did not provide them.
 */
final class CspViolation {

    static final String UNKNOWN_DOCUMENT_URL = "unknown document url";
    static final String UNKNOWN_EFFECTIVE_DIRECTIVE = "unknown effective directive";
    static final String UNKNOWN_URL = "unknown url";

    private final String documentUrl;
    private final String effectiveDirective;
    private final String blockedUrl;
    private final String sourceFile;
    private final String lineNumber;
    private final String columnNumber;
    private final String sample;

    CspViolation(String documentUrl, String effectiveDirective, String blockedUrl,
                 String sourceFile, String lineNumber, String columnNumber, String sample) {
        this.documentUrl = documentUrl;
        this.effectiveDirective = effectiveDirective;
        this.blockedUrl = blockedUrl;
        this.sourceFile = sourceFile;
        this.lineNumber = lineNumber;
        this.columnNumber = columnNumber;
        this.sample = sample;
    }

    /** A violation whose every field is unknown — used when a report shape cannot be recognised. */
    static CspViolation unknown() {
        return new CspViolation(UNKNOWN_DOCUMENT_URL, UNKNOWN_EFFECTIVE_DIRECTIVE, UNKNOWN_URL,
                null, null, null, null);
    }

    String getDocumentUrl() {
        return documentUrl;
    }

    String getEffectiveDirective() {
        return effectiveDirective;
    }

    String getBlockedUrl() {
        return blockedUrl;
    }

    String getSourceFile() {
        return sourceFile;
    }

    String getLineNumber() {
        return lineNumber;
    }

    String getColumnNumber() {
        return columnNumber;
    }

    String getSample() {
        return sample;
    }

    /**
     * Builds the single-line, human-readable description logged for this violation. The optional source
     * location ({@code at file:line:column}) and script sample are appended only when present.
     *
     * @param userAgent the reporting browser's user agent (already defaulted by the caller)
     * @return the formatted log message, without the leading {@code "Content Security Policy:"} marker
     */
    String toLogMessage(String userAgent) {
        final StringBuilder message = new StringBuilder()
                .append(blockedUrl).append(" blocked for ").append(effectiveDirective)
                .append(" on ").append(documentUrl);
        if (isPresent(sourceFile)) {
            message.append(" at ").append(sourceFile);
            if (isPresent(lineNumber)) {
                message.append(':').append(lineNumber);
                if (isPresent(columnNumber)) {
                    message.append(':').append(columnNumber);
                }
            }
        }
        if (isPresent(sample)) {
            message.append(" (sample: ").append(sample).append(')');
        }
        return message.append(" with user-agent \"").append(userAgent).append('"').toString();
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isEmpty();
    }
}

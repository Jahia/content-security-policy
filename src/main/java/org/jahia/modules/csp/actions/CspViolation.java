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

    /** Maximum stored length per field; real CSP report fields are far shorter. */
    private static final int MAX_FIELD_LENGTH = 1024;

    /**
     * URI scheme prefixes browsers use for content injected by installed extensions. Violations whose
     * blocked URL or source file uses one of these schemes are caused by an extension, not by the site,
     * and are treated as noise.
     */
    private static final String[] BROWSER_EXTENSION_URI_PREFIXES = {
        "chrome-extension:",      // Chrome, Edge, Brave and other Chromium browsers
        "moz-extension:",         // Firefox
        "safari-extension:",      // Safari (legacy extensions)
        "safari-web-extension:",  // Safari (web extensions)
        "webkit-masked-url:"      // Safari masks extension resource URLs behind this scheme
    };

    private final String documentUrl;
    private final String effectiveDirective;
    private final String blockedUrl;
    private final String sourceFile;
    private final String lineNumber;
    private final String columnNumber;
    private final String sample;

    CspViolation(String documentUrl, String effectiveDirective, String blockedUrl,
                 String sourceFile, String lineNumber, String columnNumber, String sample) {
        // All fields are attacker-controlled (anonymous POST): sanitize once here so every
        // current and future log call is safe from CRLF log forging and field flooding.
        this.documentUrl = sanitizeForLog(documentUrl);
        this.effectiveDirective = sanitizeForLog(effectiveDirective);
        this.blockedUrl = sanitizeForLog(blockedUrl);
        this.sourceFile = sanitizeForLog(sourceFile);
        this.lineNumber = sanitizeForLog(lineNumber);
        this.columnNumber = sanitizeForLog(columnNumber);
        this.sample = sanitizeForLog(sample);
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
     * Whether this violation was caused by content injected by a browser extension (identified by the
     * blocked URL or source file using a {@code *-extension:} / {@code webkit-masked-url:} scheme), rather
     * than by the site itself. Such reports are noise and should not be logged as site violations.
     */
    boolean isFromBrowserExtension() {
        return usesExtensionScheme(blockedUrl) || usesExtensionScheme(sourceFile);
    }

    /**
     * Whether this violation carries enough information to act on. Reports where both the blocked URL and
     * the directive are unknown (typically gutted reports from headless crawlers navigating away mid-load,
     * or hand-crafted probe payloads) say nothing about what was blocked or why — there is nothing to
     * triage, so they should not reach the warning log.
     */
    boolean isActionable() {
        return !(UNKNOWN_URL.equals(blockedUrl) && UNKNOWN_EFFECTIVE_DIRECTIVE.equals(effectiveDirective));
    }

    private static boolean usesExtensionScheme(String uri) {
        if (uri == null) {
            return false;
        }
        final String normalised = uri.trim().toLowerCase();
        for (String prefix : BROWSER_EXTENSION_URI_PREFIXES) {
            if (normalised.startsWith(prefix)) {
                return true;
            }
        }
        return false;
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
        // The user agent is a raw request header: sanitize it at the last point before logging.
        return message.append(" with user-agent \"").append(sanitizeForLog(userAgent)).append('"').toString();
    }

    /**
     * Makes an attacker-controlled value safe to write to the log: CR/LF and other control characters
     * (which would allow forging extra log lines) are collapsed to a single space, and the value is
     * truncated to {@value #MAX_FIELD_LENGTH} characters so a single report cannot flood the log.
     */
    static String sanitizeForLog(String value) {
        if (value == null) {
            return null;
        }
        String sanitized = value.replaceAll("[\\x00-\\x1F\\x7F]+", " ");
        if (sanitized.length() > MAX_FIELD_LENGTH) {
            sanitized = sanitized.substring(0, MAX_FIELD_LENGTH) + "...";
        }
        return sanitized;
    }

    private static boolean isPresent(String value) {
        return value != null && !value.isEmpty();
    }
}

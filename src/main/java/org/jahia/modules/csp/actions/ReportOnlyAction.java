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

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletRequest;
import org.jahia.bin.Action;
import org.jahia.bin.ActionResult;
import org.jahia.modules.csp.CspConstants;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.URLResolver;
import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Unauthenticated, CSRF-whitelisted endpoint ({@code *.contentSecurityPolicyReportOnly.do}) receiving the
 * CSP violation reports browsers POST when a policy managed by this module is violated. Both the legacy
 * {@code application/csp-report} format and the Reporting API {@code application/reports+json} format are
 * accepted. Because the endpoint is anonymous by nature, it is defended by a per-client rate limit, a body
 * size cap and a batch cap; every logged field is sanitized against log forging.
 */
@Component(service = Action.class)
public final class ReportOnlyAction extends Action {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReportOnlyAction.class);
    private static final String CONTENT_TYPE_CSP_REPORT = "application/csp-report";
    private static final String CONTENT_TYPE_REPORTS_JSON = "application/reports+json";
    private static final String KEY_BODY = "body";
    private static final String KEY_CSP_REPORT = "csp-report";
    private static final String LOG_MSG_BEGIN = "Content Security Policy:";
    private static final String MSG_UNKNOWN_USER_AGENT = "unknown user agent";
    private static final String HEADER_USER_AGENT = "User-Agent";

    /** Hard cap on the request body size; a real CSP report is typically under 2 KB. */
    static final int MAX_REPORT_BODY_BYTES = 64 * 1024;
    /** Hard cap on the number of violations processed from a single Reporting API batch. */
    static final int MAX_REPORTS_PER_BATCH = 20;
    /** HTTP 429; not defined as a constant in javax.servlet's HttpServletResponse. */
    private static final int SC_TOO_MANY_REQUESTS = 429;
    /** Per-client-IP throttle for this unauthenticated endpoint; generous for real browsers, which batch reports. */
    private static final SimpleRateLimiter RATE_LIMITER = new SimpleRateLimiter(30, 60_000L, 10_000);

    /** Field names for the legacy {@code application/csp-report} payload (Firefox, kebab-case). */
    private static final ReportKeys FIREFOX_KEYS = new ReportKeys(
            "document-uri", "effective-directive", "violated-directive", "blocked-uri",
            new SourceKeys("source-file", "line-number", "column-number", "script-sample"));
    /** Field names for the Reporting API {@code application/reports+json} payload (Chrome, camelCase). */
    private static final ReportKeys CHROME_KEYS = new ReportKeys(
            "documentURL", "effectiveDirective", null, "blockedURL",
            new SourceKeys("sourceFile", "lineNumber", "columnNumber", "sample"));

    @Activate
    public void activate() {
        setName(CspConstants.REPORT_ACTION_NAME);
        setRequireAuthenticatedUser(false);
    }

    @Override
    public ActionResult doExecute(HttpServletRequest req, RenderContext renderContext, Resource resource, JCRSessionWrapper session, Map<String, List<String>> parameters, URLResolver urlResolver) throws Exception {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{} request content-type: {}", LOG_MSG_BEGIN, CspViolation.sanitizeForLog(req.getContentType()));
        }
        if (!isCspReportContentType(req.getContentType()) || !acceptsReports(renderContext.getSite(), resource)) {
            return ActionResult.BAD_REQUEST;
        }
        // Unauthenticated endpoint: throttle per client before reading the body.
        if (!RATE_LIMITER.allow(req.getRemoteAddr(), System.currentTimeMillis())) {
            return new ActionResult(SC_TOO_MANY_REQUESTS);
        }
        return processReport(req);
    }

    /**
     * A site accepts violation reports when the legacy report-only toggle is set, when the custom report URL
     * routes back to this action, or when any policy (enforced or report-only, at site or page level) is
     * configured — in which case the render filter auto-appends a {@code report-uri} pointing here, so the
     * resulting reports must not be rejected.
     */
    private static boolean acceptsReports(JCRSiteNode site, Resource resource) throws RepositoryException {
        if (site.hasProperty(CspConstants.PROP_CSP_REPORT_ONLY) && site.getProperty(CspConstants.PROP_CSP_REPORT_ONLY).getBoolean()) {
            return true;
        }
        if (site.hasProperty(CspConstants.PROP_CSP_REPORT_URL)
                && site.getPropertyAsString(CspConstants.PROP_CSP_REPORT_URL).endsWith(CspConstants.REPORT_ACTION_SUFFIX)) {
            return true;
        }
        return hasAnyPolicy(site) || hasAnyPolicy(resource.getNode());
    }

    private static boolean hasAnyPolicy(JCRNodeWrapper node) throws RepositoryException {
        return hasNonEmptyProperty(node, CspConstants.PROP_POLICY)
                || hasNonEmptyProperty(node, CspConstants.PROP_POLICY_REPORT_ONLY);
    }

    private static boolean hasNonEmptyProperty(JCRNodeWrapper node, String property) throws RepositoryException {
        return node.hasProperty(property) && !node.getProperty(property).getString().isEmpty();
    }

    private ActionResult processReport(HttpServletRequest req) throws IOException {
        final String report = readBoundedBody(req.getInputStream(), MAX_REPORT_BODY_BYTES);
        if (report == null) {
            // Oversized body: a real CSP report is orders of magnitude below the cap.
            LOGGER.debug("{} request body exceeds {} bytes, rejected", LOG_MSG_BEGIN, MAX_REPORT_BODY_BYTES);
            return ActionResult.BAD_REQUEST;
        }
        if (report.isBlank()) {
            return ActionResult.BAD_REQUEST;
        }
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{} request content: {}", LOG_MSG_BEGIN, CspViolation.sanitizeForLog(report));
        }
        try {
            final List<CspViolation> violations = parseCspReport(report);
            if (violations == null || violations.isEmpty()) {
                return ActionResult.BAD_REQUEST;
            }
            logViolations(violations, userAgent(req));
            return ActionResult.OK;
        } catch (JSONException ex) {
            // Malformed JSON from an anonymous client: log at debug and answer BAD_REQUEST.
            LOGGER.debug("{} error with json content", LOG_MSG_BEGIN, ex);
            return ActionResult.BAD_REQUEST;
        }
    }

    private static void logViolations(List<CspViolation> violations, String userAgent) {
        // One regex evaluation per request, not per violation.
        final boolean fromBot = BotUserAgentDetector.isBot(userAgent);
        for (CspViolation violation : violations) {
            if (fromBot) {
                // Self-declared bot or crawler: what it trips is noise, not a user-facing breakage.
                debugIgnored("bot", violation, userAgent);
            } else if (violation.isFromBrowserExtension()) {
                // Caused by a browser extension, not the site: keep it out of the warning log.
                debugIgnored("browser-extension", violation, userAgent);
            } else if (!violation.isActionable()) {
                // Neither a blocked URL nor a directive: nothing to triage (typically gutted reports
                // from headless crawlers or probe payloads) — keep it out of the warning log.
                debugIgnored("unactionable", violation, userAgent);
            } else if (LOGGER.isWarnEnabled()) {
                LOGGER.warn("{} {}", LOG_MSG_BEGIN, violation.toLogMessage(userAgent));
            }
        }
    }

    private static void debugIgnored(String reason, CspViolation violation, String userAgent) {
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("{} ignoring {} report: {}", LOG_MSG_BEGIN, reason, violation.toLogMessage(userAgent));
        }
    }

    private static String userAgent(HttpServletRequest req) {
        final String userAgent = req.getHeader(HEADER_USER_AGENT);
        return userAgent == null ? MSG_UNKNOWN_USER_AGENT : userAgent;
    }

    /**
     * Parses a raw CSP violation report into one {@link CspViolation} per reported violation.
     * <p>
     * Supports both the legacy {@code application/csp-report} shape (Firefox, top-level {@code csp-report}
     * key) and the Reporting API {@code application/reports+json} shape (Chrome, {@code body} key). A single
     * object ({@code {...}}) yields one violation; an array ({@code [{...},{...}]}) — which the Reporting API
     * uses to batch several violations into one POST — yields one violation per element, capped at
     * {@value #MAX_REPORTS_PER_BATCH} entries.
     *
     * @param report the raw request body
     * @return one entry per reported violation (an unrecognised shape maps to {@link CspViolation#unknown()});
     *         an empty list for an empty JSON array; or {@code null} when the payload is neither a JSON object
     *         nor a JSON array (the caller should answer {@code BAD_REQUEST})
     * @throws JSONException when the payload starts like JSON but is malformed
     */
    static List<CspViolation> parseCspReport(String report) throws JSONException {
        final List<CspViolation> violations = new ArrayList<>();
        if (report.startsWith("{")) {
            violations.add(parseSingleReport(new JSONObject(report)));
        } else if (report.startsWith("[")) {
            final JSONArray reports = new JSONArray(report);
            // Cap the batch: an attacker can pack hundreds of minimal entries into one body,
            // turning each into a WARN line (log flooding) — no real browser batches that many.
            final int total = reports.length();
            final int count = Math.min(total, MAX_REPORTS_PER_BATCH);
            if (total > count) {
                LOGGER.debug("{} batch of {} reports truncated to {}", LOG_MSG_BEGIN, total, count);
            }
            for (int i = 0; i < count; i++) {
                violations.add(parseSingleReport(reports.getJSONObject(i)));
            }
        } else {
            return null;
        }
        return violations;
    }

    /**
     * Matches the base MIME type, ignoring parameters: some browsers send
     * {@code application/csp-report; charset=UTF-8}, which an exact comparison would silently drop.
     */
    static boolean isCspReportContentType(String contentType) {
        if (contentType == null) {
            return false;
        }
        final int separator = contentType.indexOf(';');
        final String baseType = (separator >= 0 ? contentType.substring(0, separator) : contentType).trim();
        return CONTENT_TYPE_CSP_REPORT.equals(baseType) || CONTENT_TYPE_REPORTS_JSON.equals(baseType);
    }

    /**
     * Reads the request body up to {@code maxBytes}. Returns {@code null} when the stream holds more —
     * an unauthenticated client must not be able to make the server buffer an arbitrarily large body
     * (chunked encoding bypasses any Content-Length based check).
     */
    static String readBoundedBody(InputStream input, int maxBytes) throws IOException {
        final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        final byte[] chunk = new byte[8192];
        int read;
        while ((read = input.read(chunk)) != -1) {
            if (buffer.size() + read > maxBytes) {
                return null;
            }
            buffer.write(chunk, 0, read);
        }
        return new String(buffer.toByteArray(), StandardCharsets.UTF_8);
    }

    private static CspViolation parseSingleReport(JSONObject report) throws JSONException {
        if (report.has(KEY_CSP_REPORT)) {
            return parseBody(report.getJSONObject(KEY_CSP_REPORT), FIREFOX_KEYS);
        } else if (report.has(KEY_BODY)) {
            return parseBody(report.getJSONObject(KEY_BODY), CHROME_KEYS);
        }
        return CspViolation.unknown();
    }

    private static CspViolation parseBody(JSONObject body, ReportKeys keys) {
        return new CspViolation(
                body.optString(keys.documentUrl, CspViolation.UNKNOWN_DOCUMENT_URL),
                resolveDirective(body, keys),
                body.optString(keys.blockedUrl, CspViolation.UNKNOWN_URL),
                nullIfBlank(body.optString(keys.sourceKeys.sourceFile, null)),
                nullIfBlank(body.optString(keys.sourceKeys.lineNumber, null)),
                nullIfBlank(body.optString(keys.sourceKeys.columnNumber, null)),
                nullIfBlank(body.optString(keys.sourceKeys.sample, null)));
    }

    /**
     * Resolves the directive name, preferring {@code effective-directive} (CSP3) and falling back to
     * {@code violated-directive} (CSP2 / older Firefox) so reports from either era are not lost.
     */
    private static String resolveDirective(JSONObject body, ReportKeys keys) {
        final String effective = body.optString(keys.effectiveDirective, null);
        if (effective != null && !effective.isEmpty()) {
            return effective;
        }
        if (keys.violatedDirective != null) {
            final String violated = body.optString(keys.violatedDirective, null);
            if (violated != null && !violated.isEmpty()) {
                return violated;
            }
        }
        return CspViolation.UNKNOWN_EFFECTIVE_DIRECTIVE;
    }

    private static String nullIfBlank(String value) {
        return (value == null || value.isEmpty()) ? null : value;
    }

    /** Maps the generic violation fields to the concrete JSON key names used by a browser dialect. */
    private static final class ReportKeys {
        private final String documentUrl;
        private final String effectiveDirective;
        private final String violatedDirective;
        private final String blockedUrl;
        private final SourceKeys sourceKeys;

        private ReportKeys(String documentUrl, String effectiveDirective, String violatedDirective, String blockedUrl,
                           SourceKeys sourceKeys) {
            this.documentUrl = documentUrl;
            this.effectiveDirective = effectiveDirective;
            this.violatedDirective = violatedDirective;
            this.blockedUrl = blockedUrl;
            this.sourceKeys = sourceKeys;
        }
    }

    /** JSON key names of the optional source-location fields of a violation report. */
    private static final class SourceKeys {
        private final String sourceFile;
        private final String lineNumber;
        private final String columnNumber;
        private final String sample;

        private SourceKeys(String sourceFile, String lineNumber, String columnNumber, String sample) {
            this.sourceFile = sourceFile;
            this.lineNumber = lineNumber;
            this.columnNumber = columnNumber;
            this.sample = sample;
        }
    }
}

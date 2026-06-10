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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.IOUtils;
import org.jahia.bin.Action;
import org.jahia.bin.ActionResult;
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

@Component(service = Action.class)
public final class ReportOnlyAction extends Action {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReportOnlyAction.class);
    private static final String ACTION_NAME = "contentSecurityPolicyReportOnly";
    private static final String CONTENT_TYPE_CSP_REPORT = "application/csp-report";
    private static final String CONTENT_TYPE_REPORTS_JSON = "application/reports+json";
    private static final String KEY_BODY = "body";
    private static final String KEY_CSP_REPORT = "csp-report";
    private static final String LOG_MSG_BEGIN = "Content Security Policy:";
    private static final String MSG_UNKNOWN_USER_AGENT = "unknown user agent";
    private static final String HEADER_USER_AGENT = "User-Agent";
    public static final String PROP_CSP_REPORT_ONLY = "cspReportOnly";
    public static final String PROP_CSP_REPORT_URL = "cspReportUrl";

    /** Field names for the legacy {@code application/csp-report} payload (Firefox, kebab-case). */
    private static final ReportKeys FIREFOX_KEYS = new ReportKeys(
            "document-uri", "effective-directive", "violated-directive", "blocked-uri",
            "source-file", "line-number", "column-number", "script-sample");
    /** Field names for the Reporting API {@code application/reports+json} payload (Chrome, camelCase). */
    private static final ReportKeys CHROME_KEYS = new ReportKeys(
            "documentURL", "effectiveDirective", null, "blockedURL",
            "sourceFile", "lineNumber", "columnNumber", "sample");

    @Activate
    public void activate() {
        setName(ACTION_NAME);
        setRequireAuthenticatedUser(false);
    }

    @Override
    public ActionResult doExecute(HttpServletRequest req, RenderContext renderContext, Resource resource, JCRSessionWrapper session, Map<String, List<String>> parameters, URLResolver urlResolver) throws Exception {
        LOGGER.debug(String.format("%s request content-type: %s", LOG_MSG_BEGIN, req.getContentType()));
        if (CONTENT_TYPE_CSP_REPORT.equals(req.getContentType()) || CONTENT_TYPE_REPORTS_JSON.equals(req.getContentType())) {
            final JCRSiteNode site = renderContext.getSite();
            if ((site.hasProperty(PROP_CSP_REPORT_ONLY) && site.getProperty(PROP_CSP_REPORT_ONLY).getBoolean())
                    || (site.hasProperty(PROP_CSP_REPORT_URL) && site.getPropertyAsString(PROP_CSP_REPORT_URL).endsWith(ACTION_NAME + ".do"))) {
                final String report = IOUtils.toString(req.getInputStream(), StandardCharsets.UTF_8);
                if (report != null && !report.isBlank()) {
                    final String userAgent = req.getHeader(HEADER_USER_AGENT) == null ? MSG_UNKNOWN_USER_AGENT : req.getHeader(HEADER_USER_AGENT);
                    LOGGER.debug(String.format("%s request content: %s", LOG_MSG_BEGIN, report));
                    try {
                        final List<CspViolation> violations = parseCspReport(report);
                        if (violations == null || violations.isEmpty()) {
                            return ActionResult.BAD_REQUEST;
                        }
                        for (CspViolation violation : violations) {
                            LOGGER.warn(String.format("%s %s", LOG_MSG_BEGIN, violation.toLogMessage(userAgent)));
                        }
                        return ActionResult.OK;
                    } catch (JSONException ex) {
                        //ignore exception only if we want to debug anything
                        LOGGER.debug(String.format("%s error with json content", LOG_MSG_BEGIN), ex);
                    }
                }
            }
        }
        return ActionResult.BAD_REQUEST;
    }

    /**
     * Parses a raw CSP violation report into one {@link CspViolation} per reported violation.
     * <p>
     * Supports both the legacy {@code application/csp-report} shape (Firefox, top-level {@code csp-report}
     * key) and the Reporting API {@code application/reports+json} shape (Chrome, {@code body} key). A single
     * object ({@code {...}}) yields one violation; an array ({@code [{...},{...}]}) — which the Reporting API
     * uses to batch several violations into one POST — yields one violation per element.
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
            for (int i = 0; i < reports.length(); i++) {
                violations.add(parseSingleReport(reports.getJSONObject(i)));
            }
        } else {
            return null;
        }
        return violations;
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
                nullIfBlank(body.optString(keys.sourceFile, null)),
                nullIfBlank(body.optString(keys.lineNumber, null)),
                nullIfBlank(body.optString(keys.columnNumber, null)),
                nullIfBlank(body.optString(keys.sample, null)));
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
        private final String sourceFile;
        private final String lineNumber;
        private final String columnNumber;
        private final String sample;

        private ReportKeys(String documentUrl, String effectiveDirective, String violatedDirective, String blockedUrl,
                           String sourceFile, String lineNumber, String columnNumber, String sample) {
            this.documentUrl = documentUrl;
            this.effectiveDirective = effectiveDirective;
            this.violatedDirective = violatedDirective;
            this.blockedUrl = blockedUrl;
            this.sourceFile = sourceFile;
            this.lineNumber = lineNumber;
            this.columnNumber = columnNumber;
            this.sample = sample;
        }
    }
}

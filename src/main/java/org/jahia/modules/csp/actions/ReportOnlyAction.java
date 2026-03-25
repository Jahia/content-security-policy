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
    private static final String KEY_BLOCKED_URI = "blocked-uri";
    private static final String KEY_BLOCKED_URL = "blockedURL";
    private static final String KEY_BODY = "body";
    private static final String KEY_CSP_REPORT = "csp-report";
    private static final String KEY_DOCUMENT_URI = "document-uri";
    private static final String KEY_DOCUMENT_URL = "documentURL";
    private static final String KEY_EFF_DIR_CHROME = "effectiveDirective";
    private static final String KEY_EFF_DIR_FIREFOX = "effective-directive";
    private static final String LOG_MSG_BEGIN = "Content Security Policy:";
    private static final String MSG_UNKNOWN_DOCUMENT_URL = "unknown document url";
    private static final String MSG_UNKNOWN_EFFECTIVE_DIRECTIVE = "unknown effective directive";
    private static final String MSG_UNKNOWN_URL = "unknown url";
    private static final String HEADER_USER_AGENT = "User-Agent";
    public static final String PROP_CSP_REPORT_ONLY = "cspReportOnly";
    public static final String PROP_CSP_REPORT_URL = "cspReportUrl";

    @Activate
    public void activate() {
        setName(ACTION_NAME);
        setRequireAuthenticatedUser(false);
    }

    @Override
    public ActionResult doExecute(HttpServletRequest req, RenderContext renderContext, Resource resource, JCRSessionWrapper session, Map<String, List<String>> parameters, URLResolver urlResolver) throws Exception {
        LOGGER.debug(String.format("%s request content-type: %s", LOG_MSG_BEGIN, req.getContentType()));
        if ("application/csp-report".equals(req.getContentType()) || "application/reports+json".equals(req.getContentType())) {
            final JCRSiteNode site = renderContext.getSite();
            if ((site.hasProperty(PROP_CSP_REPORT_ONLY) && site.getProperty(PROP_CSP_REPORT_ONLY).getBoolean())
                    || (site.hasProperty(PROP_CSP_REPORT_URL) && site.getPropertyAsString(PROP_CSP_REPORT_URL).endsWith(ACTION_NAME + ".do"))) {
                final String report = IOUtils.toString(req.getInputStream(), StandardCharsets.UTF_8);
                if (report != null && !report.isBlank()) {
                    final String userAgent = req.getHeader(HEADER_USER_AGENT) == null ? "unknown user agent" : req.getHeader(HEADER_USER_AGENT);
                    LOGGER.debug(String.format("%s request content: %s", LOG_MSG_BEGIN, report));
                    try {
                        String[] violation = new String[]{MSG_UNKNOWN_DOCUMENT_URL, MSG_UNKNOWN_EFFECTIVE_DIRECTIVE, MSG_UNKNOWN_URL};
                        // CSP report from Firefox as of 2026/03/05
                        final JSONObject cspData;
                        if (report.startsWith("{")) {
                            cspData = new JSONObject(report);
                        } else if (report.startsWith("[")) {
                            cspData = new JSONArray(report).getJSONObject(0);
                        } else {
                            return ActionResult.BAD_REQUEST;
                        }
                        if (cspData.has(KEY_CSP_REPORT)) {
                            violation = parseReport(cspData, KEY_CSP_REPORT, KEY_DOCUMENT_URI, KEY_EFF_DIR_FIREFOX, KEY_BLOCKED_URI);
                        } else if (cspData.has(KEY_BODY)) {
                            violation = parseReport(new JSONArray(report).getJSONObject(0), KEY_BODY, KEY_DOCUMENT_URL, KEY_EFF_DIR_CHROME, KEY_BLOCKED_URL);
                        }
                        LOGGER.warn(String.format("%s %s blocked for %s on %s with user-agent \"%s\"", LOG_MSG_BEGIN, violation[2], violation[1], violation[0], userAgent));
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

    private String[] parseReport(JSONObject jsonReport, String bodyKey, String documentUrlKey, String effectiveDirectiveKey, String blockedUrlKey) throws JSONException {
        if (jsonReport.has(bodyKey)) {
            final JSONObject jsonBody = jsonReport.getJSONObject(bodyKey);
            return new String[]{
                jsonBody.optString(documentUrlKey, MSG_UNKNOWN_DOCUMENT_URL),
                jsonBody.optString(effectiveDirectiveKey, MSG_UNKNOWN_EFFECTIVE_DIRECTIVE),
                jsonBody.optString(blockedUrlKey, MSG_UNKNOWN_URL)
            };
        }
        return new String[]{MSG_UNKNOWN_DOCUMENT_URL, MSG_UNKNOWN_EFFECTIVE_DIRECTIVE, MSG_UNKNOWN_URL};
    }
}

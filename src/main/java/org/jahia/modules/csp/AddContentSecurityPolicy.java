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

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.csp.actions.ReportOnlyAction;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.filter.AbstractFilter;
import org.jahia.services.render.filter.RenderChain;
import org.jahia.services.render.filter.RenderFilter;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import javax.servlet.http.HttpServletResponse;
import java.net.MalformedURLException;
import java.net.URL;
import java.nio.ByteBuffer;
import java.util.Base64;
import java.util.Base64.Encoder;
import java.util.UUID;

@Component(service = RenderFilter.class)
public final class AddContentSecurityPolicy extends AbstractFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AddContentSecurityPolicy.class);
    private static final String CSP_SEPARATOR = ";";
    private static final String CSP_PROPERTY = "policy";
    private static final String CSP_PROPERTY_REPORT_ONLY = "policyReportOnly";
    private static final String CSP_HEADER = "Content-Security-Policy";
    private static final String CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";
    private static final String REPORTING_ENDPOINTS_HEADER = "Reporting-Endpoints";
    private static final String CSP_WEB_NONCE_PLACEHOLDER = "nonce-";
    private static final String CSP_ENDPOINT_NAME = "csp-endpoint";
    private static final String REPORT_URI_DIRECTIVE = "report-uri";
    private static final String REPORT_TO_DIRECTIVE = "report-to";
    private static final String DEFAULT_REPORT_ACTION_SUFFIX = ".contentSecurityPolicyReportOnly.do";
    private static final String[] NONCEABLE_TAGS = {"script", "style", "link"};
    private final Encoder encoder;

    public AddContentSecurityPolicy() {
        this.encoder = Base64.getUrlEncoder();
    }

    @Activate
    public void activate() {
        setPriority(-999);
        setApplyOnEditMode(false);
        setSkipOnAjaxRequest(true);
        setApplyOnModes("live,preview");
        setApplyOnConfigurations("page");
        setSkipOnConfigurations("include,wrapper");
        setApplyOnTemplateTypes("html,html-*");
    }

    @Override
    public String execute(String previousOut, RenderContext renderContext, Resource resource, RenderChain chain) throws Exception {
        final HttpServletResponse response = renderContext.getResponse();
        final JCRSiteNode site = renderContext.getSite();
        final JCRNodeWrapper page = renderContext.getMainResource().getNode();

        // page-level policies take precedence over the site-level ones
        final String enforcedPolicy = resolvePolicy(page, site, CSP_PROPERTY);
        final String reportOnlyPolicy = resolvePolicy(page, site, CSP_PROPERTY_REPORT_ONLY);
        final boolean hasEnforcedPolicy = StringUtils.isNotEmpty(enforcedPolicy);
        final boolean hasReportOnlyPolicy = StringUtils.isNotEmpty(reportOnlyPolicy);

        final String nonce = getNonceValue();

        if (hasEnforcedPolicy || hasReportOnlyPolicy) {
            final String reportEndpoint = resolveReportEndpoint(renderContext, resource, site);
            response.setHeader(REPORTING_ENDPOINTS_HEADER, CSP_ENDPOINT_NAME + "=\"" + reportEndpoint + "\"");

            if (hasEnforcedPolicy) {
                // Backward-compatible toggle: when cspReportOnly is set, the main policy is delivered as
                // report-only (no enforcement), matching the historical single-policy behaviour.
                final boolean asReportOnly = site.hasProperty(ReportOnlyAction.PROP_CSP_REPORT_ONLY)
                        && site.getProperty(ReportOnlyAction.PROP_CSP_REPORT_ONLY).getBoolean();
                response.addHeader(asReportOnly ? CSP_REPORT_ONLY_HEADER : CSP_HEADER,
                        buildPolicyValue(enforcedPolicy, nonce, reportEndpoint));
            }
            if (hasReportOnlyPolicy) {
                // The dedicated report-only policy is delivered alongside the enforced one, so a stricter
                // candidate can be trialled in report-only mode (per the CSP spec) without dropping enforcement.
                response.addHeader(CSP_REPORT_ONLY_HEADER,
                        buildPolicyValue(reportOnlyPolicy, nonce, reportEndpoint));
            }
        }

        if (site.getInstalledModules().contains("content-security-policy")) {
            String out = previousOut;
            // Nonce-source applies to scripts AND stylesheets, so tag every <script>, <style> and <link>.
            for (String tag : NONCEABLE_TAGS) {
                out = applyNonce(out, tag, nonce);
            }
            return out;
        }

        return previousOut;
    }

    private static String resolvePolicy(JCRNodeWrapper page, JCRSiteNode site, String property) throws RepositoryException {
        if (page.hasProperty(property)) {
            return page.getProperty(property).getString();
        }
        return site.hasProperty(property) ? site.getProperty(property).getString() : null;
    }

    private String resolveReportEndpoint(RenderContext renderContext, Resource resource, JCRSiteNode site) throws RepositoryException {
        String reportEndpoint = renderContext.getRequest().getContextPath() + resource.getNodePath() + DEFAULT_REPORT_ACTION_SUFFIX;
        if (site.hasProperty(ReportOnlyAction.PROP_CSP_REPORT_URL) && !site.getProperty(ReportOnlyAction.PROP_CSP_REPORT_URL).getString().isEmpty()) {
            try {
                reportEndpoint = new URL(site.getProperty(ReportOnlyAction.PROP_CSP_REPORT_URL).getString()).toString();
            } catch (MalformedURLException e) {
                LOGGER.warn("The provided CSP report URL is not valid, using the default one.", e);
            }
        }
        return reportEndpoint;
    }

    /**
     * Substitutes the per-response nonce into the {@code nonce-} placeholder and appends the reporting
     * directives. {@code report-uri}/{@code report-to} are only added when the author has not already
     * declared them, so the module never produces a duplicate (ignored) directive.
     */
    static String buildPolicyValue(String policyDirectives, String nonce, String reportEndpoint) {
        final String withNonce = policyDirectives.replace(CSP_WEB_NONCE_PLACEHOLDER, CSP_WEB_NONCE_PLACEHOLDER + nonce);
        final StringBuilder policy = new StringBuilder(stripTrailingSeparators(withNonce));
        if (!containsDirective(withNonce, REPORT_URI_DIRECTIVE)) {
            policy.append(CSP_SEPARATOR).append(' ').append(REPORT_URI_DIRECTIVE).append(' ').append(reportEndpoint);
        }
        if (!containsDirective(withNonce, REPORT_TO_DIRECTIVE)) {
            policy.append(CSP_SEPARATOR).append(' ').append(REPORT_TO_DIRECTIVE).append(' ').append(CSP_ENDPOINT_NAME);
        }
        return policy.toString();
    }

    /** Returns whether the policy already declares the given directive (case-insensitive). */
    static boolean containsDirective(String policy, String directiveName) {
        final String needle = directiveName.toLowerCase();
        for (String directive : policy.split(CSP_SEPARATOR)) {
            final String token = directive.trim().toLowerCase();
            if (token.equals(needle) || token.startsWith(needle + " ")) {
                return true;
            }
        }
        return false;
    }

    private static String stripTrailingSeparators(String policy) {
        String trimmed = policy.trim();
        while (trimmed.endsWith(CSP_SEPARATOR)) {
            trimmed = trimmed.substring(0, trimmed.length() - CSP_SEPARATOR.length()).trim();
        }
        return trimmed;
    }

    /**
     * Strips any pre-existing nonce attribute from the given tag and injects the per-response nonce, so the
     * attribute in the body always matches the one in the header. {@code tagName} is a controlled literal,
     * never user input.
     */
    static String applyNonce(String html, String tagName, String nonce) {
        final String stripped = html.replaceAll(
                "(?i)<" + tagName + "([^>]*?)\\snonce\\s*=\\s*(['\"]).*?\\2", "<" + tagName + "$1");
        return stripped.replaceAll(
                "(?i)<" + tagName + "([\\s>])", "<" + tagName + " nonce=\"" + nonce + "\"$1");
    }

    private String getNonceValue() {
        final UUID uuid = UUID.randomUUID();
        final byte[] src = ByteBuffer.wrap(new byte[16]).putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits()).array();
        return encoder.encodeToString(src).substring(0, 22);
    }
}

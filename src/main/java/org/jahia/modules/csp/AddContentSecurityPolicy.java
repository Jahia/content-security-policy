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
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;
import java.util.regex.Pattern;

/**
 * Render filter emitting the Content-Security-Policy headers configured on the site or page (via the
 * {@code jmix:siteContentSecurityPolicy} / {@code jmix:pageContentSecurityPolicy} mixins) and injecting the
 * per-request nonce into the rendered HTML. It runs late in the render chain (priority -999) so the full
 * page markup is available, in live and preview modes only, and rewrites the body on every request — which
 * keeps header and body nonces consistent even when fragments are served from Jahia's HTML cache.
 */
@Component(service = RenderFilter.class)
public final class AddContentSecurityPolicy extends AbstractFilter {

    private static final Logger LOGGER = LoggerFactory.getLogger(AddContentSecurityPolicy.class);
    private static final String CSP_SEPARATOR = ";";
    private static final String CSP_HEADER = "Content-Security-Policy";
    private static final String CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";
    private static final String REPORTING_ENDPOINTS_HEADER = "Reporting-Endpoints";
    private static final String CACHE_CONTROL_HEADER = "Cache-Control";
    private static final String CACHE_CONTROL_NO_STORE = "no-store";
    private static final String CSP_WEB_NONCE_PLACEHOLDER = "nonce-";
    private static final String REPORT_URI_DIRECTIVE = "report-uri";
    private static final String REPORT_TO_DIRECTIVE = "report-to";
    private static final String[] NONCEABLE_TAGS = {"script", "style", "link"};
    // Patterns are compiled once per tag at class load: String.replaceAll would recompile them on
    // every page render. The nonce-value part uses [^'"]* (not .*?) to rule out regex backtracking
    // blow-ups on adversarial markup.
    private static final Map<String, Pattern> STRIP_NONCE_PATTERNS =
            compileNoncePatterns("(?i)<%s([^>]*?)\\snonce\\s*=\\s*(['\"])[^'\"]*\\2");
    private static final Map<String, Pattern> INJECT_NONCE_PATTERNS =
            compileNoncePatterns("(?i)<%s([\\s>])");
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
        final String enforcedPolicy = resolvePolicy(page, site, CspConstants.PROP_POLICY);
        final String reportOnlyPolicy = resolvePolicy(page, site, CspConstants.PROP_POLICY_REPORT_ONLY);
        final boolean hasEnforcedPolicy = StringUtils.isNotEmpty(enforcedPolicy);
        final boolean hasReportOnlyPolicy = StringUtils.isNotEmpty(reportOnlyPolicy);

        if (!hasEnforcedPolicy && !hasReportOnlyPolicy) {
            // No policy configured: no headers, and no point paying the nonce-injection rewrite.
            return previousOut;
        }

        final String nonce = getNonceValue();
        final String reportEndpoint = resolveReportEndpoint(renderContext, resource, site);
        response.setHeader(REPORTING_ENDPOINTS_HEADER,
                sanitizeHeaderValue(CspConstants.CSP_ENDPOINT_NAME + "=\"" + reportEndpoint + "\""));

        final boolean usesNonce = (hasEnforcedPolicy && enforcedPolicy.contains(CSP_WEB_NONCE_PLACEHOLDER))
                || (hasReportOnlyPolicy && reportOnlyPolicy.contains(CSP_WEB_NONCE_PLACEHOLDER));
        if (usesNonce) {
            // A per-request nonce is incompatible with any full-response cache (edge/CDN): a cached header
            // nonce can never match a freshly generated one. Forbid response caching for nonce-based policies.
            response.setHeader(CACHE_CONTROL_HEADER, CACHE_CONTROL_NO_STORE);
        }

        if (hasEnforcedPolicy) {
            // Backward-compatible toggle: when cspReportOnly is set, the main policy is delivered as
            // report-only (no enforcement), matching the historical single-policy behaviour.
            final boolean asReportOnly = site.hasProperty(CspConstants.PROP_CSP_REPORT_ONLY)
                    && site.getProperty(CspConstants.PROP_CSP_REPORT_ONLY).getBoolean();
            response.addHeader(asReportOnly ? CSP_REPORT_ONLY_HEADER : CSP_HEADER,
                    buildPolicyValue(enforcedPolicy, nonce, reportEndpoint));
        }
        if (hasReportOnlyPolicy) {
            // The dedicated report-only policy is delivered alongside the enforced one, so a stricter
            // candidate can be trialled in report-only mode (per the CSP spec) without dropping enforcement.
            response.addHeader(CSP_REPORT_ONLY_HEADER,
                    buildPolicyValue(reportOnlyPolicy, nonce, reportEndpoint));
        }

        // Nonce-source applies to scripts AND stylesheets, so tag every <script>, <style> and <link>.
        // Rewriting on every request (replacing any pre-existing nonce) keeps the body consistent with
        // the freshly generated header nonce even when fragments come out of Jahia's HTML cache.
        String out = previousOut;
        for (String tag : NONCEABLE_TAGS) {
            out = applyNonce(out, tag, nonce);
        }
        return out;
    }

    private static String resolvePolicy(JCRNodeWrapper page, JCRSiteNode site, String property) throws RepositoryException {
        if (page.hasProperty(property)) {
            return page.getProperty(property).getString();
        }
        return site.hasProperty(property) ? site.getProperty(property).getString() : null;
    }

    private String resolveReportEndpoint(RenderContext renderContext, Resource resource, JCRSiteNode site) throws RepositoryException {
        if (site.hasProperty(CspConstants.PROP_CSP_REPORT_URL) && !site.getProperty(CspConstants.PROP_CSP_REPORT_URL).getString().isEmpty()) {
            final String customUrl = site.getProperty(CspConstants.PROP_CSP_REPORT_URL).getString().trim();
            if (isValidReportUrl(customUrl)) {
                return customUrl;
            }
            LOGGER.warn("The provided CSP report URL is not valid, using the default one.");
        }
        return renderContext.getRequest().getContextPath() + resource.getNodePath() + CspConstants.REPORT_ACTION_SUFFIX;
    }

    /**
     * Accepts only absolute http(s) URLs free of control characters. {@code new URL(...)} alone is not a
     * security validator: it accepts {@code file:}, {@code ftp:} or {@code jar:} schemes and tolerates raw
     * control characters, which would end up inside response headers (header injection on unpatched
     * containers, request failure on patched ones).
     */
    static boolean isValidReportUrl(String url) {
        if (url == null || url.isEmpty()) {
            return false;
        }
        for (int i = 0; i < url.length(); i++) {
            final char c = url.charAt(i);
            // Control characters enable header injection; a raw space is illegal in a URL (RFC 3986)
            // and would split the space-delimited report-uri directive value.
            if (c <= 0x20 || c == 0x7F) {
                return false;
            }
        }
        try {
            final String protocol = new URL(url).getProtocol();
            return "http".equals(protocol) || "https".equals(protocol);
        } catch (MalformedURLException e) {
            return false;
        }
    }

    /**
     * Makes a value safe to use as an HTTP header: CR/LF and other control characters are collapsed to a
     * single space. This is defence-in-depth against response splitting via JCR-stored values, and it also
     * turns the multi-line policies admins paste into the textarea into a valid single-line header.
     */
    static String sanitizeHeaderValue(String value) {
        return value.replaceAll("[\\x00-\\x1F\\x7F]+", " ").trim();
    }

    /**
     * Substitutes the per-response nonce into the {@code nonce-} placeholder and appends the reporting
     * directives. {@code report-uri}/{@code report-to} are only added when the author has not already
     * declared them, so the module never produces a duplicate (ignored) directive.
     */
    static String buildPolicyValue(String policyDirectives, String nonce, String reportEndpoint) {
        // Sanitizing here both blocks response splitting through the JCR-stored policy and lets
        // admins keep the multi-line layout the textarea (and our README examples) encourage.
        final String withNonce = sanitizeHeaderValue(policyDirectives)
                .replace(CSP_WEB_NONCE_PLACEHOLDER, CSP_WEB_NONCE_PLACEHOLDER + nonce);
        final StringBuilder policy = new StringBuilder(stripTrailingSeparators(withNonce));
        if (!containsDirective(withNonce, REPORT_URI_DIRECTIVE)) {
            policy.append(CSP_SEPARATOR).append(' ').append(REPORT_URI_DIRECTIVE).append(' ').append(reportEndpoint);
        }
        if (!containsDirective(withNonce, REPORT_TO_DIRECTIVE)) {
            policy.append(CSP_SEPARATOR).append(' ').append(REPORT_TO_DIRECTIVE).append(' ').append(CspConstants.CSP_ENDPOINT_NAME);
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
     * attribute in the body always matches the one in the header. {@code tagName} must be one of
     * {@link #NONCEABLE_TAGS}; the nonce is base64url, so it is safe inside a regex replacement.
     */
    static String applyNonce(String html, String tagName, String nonce) {
        final String stripped = STRIP_NONCE_PATTERNS.get(tagName).matcher(html)
                .replaceAll("<" + tagName + "$1");
        return INJECT_NONCE_PATTERNS.get(tagName).matcher(stripped)
                .replaceAll("<" + tagName + " nonce=\"" + nonce + "\"$1");
    }

    private static Map<String, Pattern> compileNoncePatterns(String template) {
        final Map<String, Pattern> patterns = new HashMap<>();
        for (String tag : NONCEABLE_TAGS) {
            patterns.put(tag, Pattern.compile(String.format(template, tag)));
        }
        return Collections.unmodifiableMap(patterns);
    }

    private String getNonceValue() {
        final UUID uuid = UUID.randomUUID();
        final byte[] src = ByteBuffer.wrap(new byte[16]).putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits()).array();
        return encoder.encodeToString(src).substring(0, 22);
    }
}

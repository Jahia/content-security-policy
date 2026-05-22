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
import org.jahia.settings.SettingsBean;
import org.jahia.settings.JahiaPropertiesUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

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
    private static final String CSP_HEADER = "Content-Security-Policy";
    private static final String CSP_REPORT_ONLY_HEADER = "Content-Security-Policy-Report-Only";
    private static final String REPORTING_ENDPOINTS_HEADER = "Reporting-Endpoints";
    private static final String CSP_WEB_NONCE_PLACEHOLDER = "nonce-";
    private static final String CSP_ENDPOINT_NAME = "csp-endpoint";
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

        // use CSP at page-level first, otherwise use the one defined at site-level
        final String policyDirectives;
        if (page.hasProperty(CSP_PROPERTY)) {
            policyDirectives = page.getProperty(CSP_PROPERTY).getString();
        } else {
            policyDirectives = site.hasProperty(CSP_PROPERTY) ? site.getProperty(CSP_PROPERTY).getString() : null;
        }

        final String nonce = getNonceValue();

        if (StringUtils.isNotEmpty(policyDirectives)) {
            String reportEndpoint = renderContext.getRequest().getContextPath() + resource.getNodePath() + ".contentSecurityPolicyReportOnly.do";
            if (site.hasProperty(ReportOnlyAction.CSP_REPORT_URL) && !site.getProperty(ReportOnlyAction.CSP_REPORT_URL).getString().isEmpty()) {
                try {
                    reportEndpoint = new URL(site.getProperty(ReportOnlyAction.CSP_REPORT_URL).getString()).toString();
                } catch (MalformedURLException e) {
                    LOGGER.warn("The provided CSP report URL is not valid, using the default one.", e);
                }
            }
            response.setHeader(REPORTING_ENDPOINTS_HEADER, CSP_ENDPOINT_NAME + "=\"" + reportEndpoint + "\"");

            String contentSecurityPolicy = policyDirectives.replace(CSP_WEB_NONCE_PLACEHOLDER, CSP_WEB_NONCE_PLACEHOLDER + nonce) +
                    CSP_SEPARATOR + " report-uri " + reportEndpoint +
                    CSP_SEPARATOR + " report-to " + CSP_ENDPOINT_NAME;

            final String cspHeader;
            if (site.hasProperty(ReportOnlyAction.CSP_REPORT_ONLY) && site.getProperty(ReportOnlyAction.CSP_REPORT_ONLY).getBoolean()) {
                cspHeader = CSP_REPORT_ONLY_HEADER;
            } else {
                cspHeader = CSP_HEADER;
            }
            response.setHeader(cspHeader, contentSecurityPolicy);
        }

        if (site.getInstalledModules().contains("content-security-policy")) {
            // Remove any existing nonce attributes from <script> tags
            String cleanedOut = previousOut.replaceAll("(?i)<script([^>]*?)\\snonce\\s*=\\s*(['\"]).*?\\2", "<script$1");
            // Replace all <script> tags with a nonce attribute
            String nonceScriptTag = "<script nonce=\"" + nonce + "\"";
            return cleanedOut.replaceAll("(?i)<script([\\s>])", nonceScriptTag + "$1");
        }

        return previousOut;
    }

    private String getNonceValue() {
        final UUID uuid = UUID.randomUUID();
        final byte[] src = ByteBuffer.wrap(new byte[16]).putLong(uuid.getMostSignificantBits())
                .putLong(uuid.getLeastSignificantBits()).array();
        return encoder.encodeToString(src).substring(0, 22);
    }
}

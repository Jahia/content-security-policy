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

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRPropertyWrapper;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;

/**
 * Orchestration tests for {@link AddContentSecurityPolicy#execute} — header emission, the report-only
 * toggle, nonce-driven cache control and the invalid-URL fallback — with the Jahia collaborators mocked.
 */
@DisplayName("AddContentSecurityPolicy.execute")
class AddContentSecurityPolicyExecuteTest {

    private static final String PAGE_HTML = "<html><head><style>.a{}</style></head>"
            + "<body><script src='a.js'></script></body></html>";

    private final AddContentSecurityPolicy filter = new AddContentSecurityPolicy();
    private RenderContext renderContext;
    private HttpServletResponse response;
    private JCRSiteNode site;
    private Resource resource;
    private JCRNodeWrapper page;

    @BeforeEach
    void setUp() {
        renderContext = mock(RenderContext.class);
        response = mock(HttpServletResponse.class);
        site = mock(JCRSiteNode.class);
        resource = mock(Resource.class);
        page = mock(JCRNodeWrapper.class);
        final Resource mainResource = mock(Resource.class);
        final HttpServletRequest request = mock(HttpServletRequest.class);

        when(renderContext.getResponse()).thenReturn(response);
        when(renderContext.getSite()).thenReturn(site);
        when(renderContext.getMainResource()).thenReturn(mainResource);
        when(renderContext.getRequest()).thenReturn(request);
        when(mainResource.getNode()).thenReturn(page);
        when(request.getContextPath()).thenReturn("");
        when(resource.getNodePath()).thenReturn("/sites/test/home");
    }

    private String execute() throws Exception {
        return filter.execute(PAGE_HTML, renderContext, resource, null);
    }

    private void givenSiteStringProperty(String name, String value) throws Exception {
        final JCRPropertyWrapper property = mock(JCRPropertyWrapper.class);
        when(property.getString()).thenReturn(value);
        when(site.hasProperty(name)).thenReturn(true);
        when(site.getProperty(name)).thenReturn(property);
    }

    private void givenSiteBooleanProperty(String name, boolean value) throws Exception {
        final JCRPropertyWrapper property = mock(JCRPropertyWrapper.class);
        when(property.getBoolean()).thenReturn(value);
        when(site.hasProperty(name)).thenReturn(true);
        when(site.getProperty(name)).thenReturn(property);
    }

    @Test
    @DisplayName("returns the markup unchanged and sets no header when no policy is configured")
    void execute_noPolicy_isPassThrough() throws Exception {
        // Arrange — Mockito defaults: no property anywhere

        // Act
        final String out = execute();

        // Assert — no header, and crucially no nonce injection on policy-less sites
        assertThat(out).isEqualTo(PAGE_HTML);
        verify(response, never()).setHeader(anyString(), anyString());
        verify(response, never()).addHeader(anyString(), anyString());
    }

    @Test
    @DisplayName("emits the enforced header, the reporting endpoint and injects nonces when a site policy is set")
    void execute_sitePolicy_emitsHeadersAndNonces() throws Exception {
        // Arrange
        givenSiteStringProperty("policy", "default-src 'self'");

        // Act
        final String out = execute();

        // Assert
        verify(response).addHeader(eq("Content-Security-Policy"),
                contains("default-src 'self'; report-uri /sites/test/home.contentSecurityPolicyReportOnly.do"));
        verify(response).setHeader(eq("Reporting-Endpoints"),
                eq("csp-endpoint=\"/sites/test/home.contentSecurityPolicyReportOnly.do\""));
        // No nonce placeholder in the policy: response caching must stay allowed
        verify(response, never()).setHeader(eq("Cache-Control"), anyString());
        assertThat(out).contains("<script nonce=\"").contains("<style nonce=\"");
    }

    @Test
    @DisplayName("delivers the enforced policy as report-only when the legacy toggle is set")
    void execute_reportOnlyToggle_usesReportOnlyHeader() throws Exception {
        // Arrange
        givenSiteStringProperty("policy", "default-src 'self'");
        givenSiteBooleanProperty("cspReportOnly", true);

        // Act
        execute();

        // Assert
        verify(response).addHeader(eq("Content-Security-Policy-Report-Only"), contains("default-src 'self'"));
        verify(response, never()).addHeader(eq("Content-Security-Policy"), anyString());
    }

    @Test
    @DisplayName("emits both headers when an enforced and a report-only policy are configured")
    void execute_dualPolicies_emitsBothHeaders() throws Exception {
        // Arrange
        givenSiteStringProperty("policy", "default-src 'self'");
        givenSiteStringProperty("policyReportOnly", "default-src 'none'");

        // Act
        execute();

        // Assert
        verify(response).addHeader(eq("Content-Security-Policy"), contains("default-src 'self'"));
        verify(response).addHeader(eq("Content-Security-Policy-Report-Only"), contains("default-src 'none'"));
    }

    @Test
    @DisplayName("forbids response caching and keeps header and body nonces identical for a nonce policy")
    void execute_noncePolicy_setsNoStoreAndConsistentNonce() throws Exception {
        // Arrange
        givenSiteStringProperty("policy", "script-src 'nonce-'");

        // Act
        final String out = execute();

        // Assert — no-store because a cached response could never match a fresh nonce
        verify(response).setHeader("Cache-Control", "no-store");
        final ArgumentCaptor<String> header = ArgumentCaptor.forClass(String.class);
        verify(response).addHeader(eq("Content-Security-Policy"), header.capture());
        final Matcher nonceMatcher = Pattern.compile("'nonce-([A-Za-z0-9_-]+)'").matcher(header.getValue());
        assertThat(nonceMatcher.find()).isTrue();
        assertThat(out).contains("nonce=\"" + nonceMatcher.group(1) + "\"");
    }

    @Test
    @DisplayName("page-level policy overrides the site-level one")
    void execute_pagePolicy_overridesSitePolicy() throws Exception {
        // Arrange
        givenSiteStringProperty("policy", "default-src 'self'");
        final JCRPropertyWrapper pageProperty = mock(JCRPropertyWrapper.class);
        when(pageProperty.getString()).thenReturn("img-src 'none'");
        when(page.hasProperty("policy")).thenReturn(true);
        when(page.getProperty("policy")).thenReturn(pageProperty);

        // Act
        execute();

        // Assert
        verify(response).addHeader(eq("Content-Security-Policy"), contains("img-src 'none'"));
    }

    @Test
    @DisplayName("falls back to the default report endpoint when the custom URL is invalid")
    void execute_invalidCustomReportUrl_fallsBackToDefault() throws Exception {
        // Arrange
        givenSiteStringProperty("policy", "default-src 'self'");
        givenSiteStringProperty("cspReportUrl", "ftp://internal.host/reports");

        // Act
        execute();

        // Assert — the ftp:// URL must never reach a response header
        verify(response).setHeader(eq("Reporting-Endpoints"),
                eq("csp-endpoint=\"/sites/test/home.contentSecurityPolicyReportOnly.do\""));
    }
}

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
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.stream.Stream;
import javax.servlet.ReadListener;
import javax.servlet.ServletInputStream;
import javax.servlet.http.HttpServletRequest;
import org.jahia.bin.ActionResult;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRPropertyWrapper;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

/**
 * Orchestration tests for {@link ReportOnlyAction#doExecute} — the unauthenticated endpoint shell —
 * exercising the content-type gate, the report-acceptance guard, the rate limit, the body-size cap and
 * the error handling, with the Jahia/servlet collaborators mocked.
 * <p>
 * The rate limiter is a static, JVM-wide singleton: every test uses its own remote address so tests
 * cannot interfere with each other.
 */
@DisplayName("ReportOnlyAction.doExecute")
class ReportOnlyActionDoExecuteTest {

    private static final String FIREFOX_REPORT = "{\"csp-report\":{"
            + "\"document-uri\":\"https://example.com/page\","
            + "\"effective-directive\":\"script-src\","
            + "\"blocked-uri\":\"https://evil.com/x.js\"}}";

    private final ReportOnlyAction action = new ReportOnlyAction();
    private HttpServletRequest request;
    private RenderContext renderContext;
    private JCRSiteNode site;
    private Resource resource;
    private JCRNodeWrapper pageNode;

    @BeforeEach
    void setUp() throws Exception {
        request = mock(HttpServletRequest.class);
        renderContext = mock(RenderContext.class);
        site = mock(JCRSiteNode.class);
        resource = mock(Resource.class);
        pageNode = mock(JCRNodeWrapper.class);

        when(renderContext.getSite()).thenReturn(site);
        when(resource.getNode()).thenReturn(pageNode);
        when(request.getContentType()).thenReturn("application/csp-report");
        when(request.getInputStream()).thenAnswer(invocation -> servletStream(FIREFOX_REPORT));
    }

    private ActionResult execute() throws Exception {
        return action.doExecute(request, renderContext, resource, null, null, null);
    }

    private void givenSiteStringProperty(String name, String value) throws Exception {
        final JCRPropertyWrapper property = mock(JCRPropertyWrapper.class);
        when(property.getString()).thenReturn(value);
        when(site.hasProperty(name)).thenReturn(true);
        when(site.getProperty(name)).thenReturn(property);
        when(site.getPropertyAsString(name)).thenReturn(value);
    }

    private void givenSiteReportOnlyToggle() throws Exception {
        final JCRPropertyWrapper property = mock(JCRPropertyWrapper.class);
        when(property.getBoolean()).thenReturn(true);
        when(site.hasProperty("cspReportOnly")).thenReturn(true);
        when(site.getProperty("cspReportOnly")).thenReturn(property);
    }

    @Test
    @DisplayName("rejects a request with a non-CSP content type")
    void doExecute_wrongContentType_returnsBadRequest() throws Exception {
        // Arrange
        when(request.getContentType()).thenReturn("text/plain");
        when(request.getRemoteAddr()).thenReturn("10.0.0.1");
        givenSiteReportOnlyToggle();

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(400);
    }

    @Test
    @DisplayName("rejects a report for a site with no CSP configuration at all")
    void doExecute_unconfiguredSite_returnsBadRequest() throws Exception {
        // Arrange — Mockito defaults: hasProperty(...) is false everywhere
        when(request.getRemoteAddr()).thenReturn("10.0.0.2");

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(400);
    }

    @Test
    @DisplayName("accepts a report when the legacy report-only toggle is set")
    void doExecute_reportOnlyToggle_returnsOk() throws Exception {
        // Arrange
        when(request.getRemoteAddr()).thenReturn("10.0.0.3");
        givenSiteReportOnlyToggle();

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("accepts a report when an enforced policy is configured at the site level (regression: reports were lost)")
    void doExecute_sitePolicyConfigured_returnsOk() throws Exception {
        // Arrange — the filter auto-appends report-uri pointing here whenever a policy exists,
        // so the endpoint must accept the resulting reports
        when(request.getRemoteAddr()).thenReturn("10.0.0.4");
        givenSiteStringProperty("policy", "default-src 'self'");

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("accepts a report when a report-only policy is configured at the page level")
    void doExecute_pageReportOnlyPolicyConfigured_returnsOk() throws Exception {
        // Arrange
        when(request.getRemoteAddr()).thenReturn("10.0.0.5");
        final JCRPropertyWrapper property = mock(JCRPropertyWrapper.class);
        when(property.getString()).thenReturn("default-src 'none'");
        when(pageNode.hasProperty("policyReportOnly")).thenReturn(true);
        when(pageNode.getProperty("policyReportOnly")).thenReturn(property);

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("accepts a report when the custom report URL routes back to the built-in action")
    void doExecute_customUrlPointingAtAction_returnsOk() throws Exception {
        // Arrange
        when(request.getRemoteAddr()).thenReturn("10.0.0.6");
        givenSiteStringProperty("cspReportUrl", "https://example.com/sites/x/home.contentSecurityPolicyReportOnly.do");

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("throttles a client exceeding the per-IP rate limit with HTTP 429")
    void doExecute_overRateLimit_returns429() throws Exception {
        // Arrange — a dedicated IP so the shared static limiter does not affect other tests
        when(request.getRemoteAddr()).thenReturn("10.99.99.99");
        givenSiteReportOnlyToggle();

        // Act — 30 allowed requests, then one more
        for (int i = 0; i < 30; i++) {
            assertThat(execute().getResultCode()).isEqualTo(200);
        }

        // Assert
        assertThat(execute().getResultCode()).isEqualTo(429);
    }

    static Stream<Arguments> rejectedBodies() {
        return Stream.of(
                Arguments.of("an oversized body", new byte[ReportOnlyAction.MAX_REPORT_BODY_BYTES + 1]),
                Arguments.of("a blank body", "   ".getBytes(StandardCharsets.UTF_8)),
                // Malformed JSON: no JSONException must escape doExecute
                Arguments.of("a malformed JSON body", "{\"csp-report\":".getBytes(StandardCharsets.UTF_8)));
    }

    @ParameterizedTest(name = "rejects {0} with BAD_REQUEST")
    @MethodSource("rejectedBodies")
    void doExecute_invalidBody_returnsBadRequest(String description, byte[] body) throws Exception {
        // Arrange
        when(request.getRemoteAddr()).thenReturn("10.0.0.7");
        givenSiteReportOnlyToggle();
        when(request.getInputStream()).thenAnswer(invocation -> servletStream(body));

        // Act / Assert
        assertThat(execute().getResultCode()).isEqualTo(400);
    }

    @Test
    @DisplayName("accepts a gutted, unactionable report (filtered from the warn log) with OK")
    void doExecute_unactionableReport_returnsOk() throws Exception {
        // Arrange — the production HeadlessChrome shape: document URL only, no blocked URI/directive
        when(request.getRemoteAddr()).thenReturn("10.0.0.11");
        givenSiteReportOnlyToggle();
        when(request.getInputStream()).thenAnswer(invocation -> servletStream(
                "{\"csp-report\":{\"document-uri\":\"https://example.com/p\"}}"));

        // Act / Assert — accepted so the sender does not retry, even though it is not warn-logged
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("accepts a complete violation report sent by a self-declared bot (filtered from the warn log) with OK")
    void doExecute_botReport_returnsOk() throws Exception {
        // Arrange — a fully actionable report, but from a crawler UA matched by the vendored bot list
        when(request.getRemoteAddr()).thenReturn("10.0.0.12");
        when(request.getHeader(anyString())).thenReturn(
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36");
        givenSiteReportOnlyToggle();

        // Act / Assert — accepted so the sender does not retry, even though it is not warn-logged
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    @Test
    @DisplayName("accepts a browser-extension violation report (filtered from the warn log) with OK")
    void doExecute_extensionReport_returnsOk() throws Exception {
        // Arrange
        when(request.getRemoteAddr()).thenReturn("10.0.0.10");
        when(request.getHeader(anyString())).thenReturn("Mozilla/5.0");
        givenSiteReportOnlyToggle();
        when(request.getInputStream()).thenAnswer(invocation -> servletStream(
                "{\"csp-report\":{\"document-uri\":\"https://example.com/p\","
                        + "\"effective-directive\":\"script-src\","
                        + "\"blocked-uri\":\"chrome-extension://abc/inject.js\"}}"));

        // Act / Assert — accepted so the browser does not retry, even though it is not warn-logged
        assertThat(execute().getResultCode()).isEqualTo(200);
    }

    private static ServletInputStream servletStream(String body) {
        return servletStream(body.getBytes(StandardCharsets.UTF_8));
    }

    private static ServletInputStream servletStream(byte[] body) {
        final ByteArrayInputStream delegate = new ByteArrayInputStream(body);
        return new ServletInputStream() {
            @Override
            public int read() {
                return delegate.read();
            }

            @Override
            public boolean isFinished() {
                return delegate.available() == 0;
            }

            @Override
            public boolean isReady() {
                return true;
            }

            @Override
            public void setReadListener(ReadListener readListener) {
                // not needed for synchronous test reads
            }
        };
    }
}

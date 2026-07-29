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
import java.util.regex.Pattern;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.io.IOUtils;
import org.jahia.bin.Action;
import org.jahia.bin.ActionResult;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.URLResolver;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Component(service = Action.class)
public final class ReportOnlyAction extends Action {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReportOnlyAction.class);
    public static final String CSP_REPORT_ONLY = "cspReportOnly";
    public static final String CSP_REPORT_URL = "cspReportUrl";

    /** The largest report this action accepts; a violation report is a small JSON document. */
    private static final int MAX_REPORT_BYTES = 64 * 1024;

    private static final Pattern CONTROL_CHARACTERS = Pattern.compile("\\p{Cntrl}");

    @Activate
    public void activate() {
        setName("contentSecurityPolicyReportOnly");
        setRequireAuthenticatedUser(false);
    }

    @Override
    public ActionResult doExecute(HttpServletRequest req, RenderContext renderContext, Resource resource, JCRSessionWrapper session, Map<String, List<String>> parameters, URLResolver urlResolver) throws Exception {
        if ("application/csp-report".equals(req.getContentType())) {
            final JCRSiteNode site = renderContext.getSite();
            if (site.hasProperty(CSP_REPORT_ONLY) && site.getProperty(CSP_REPORT_ONLY).getBoolean()) {
                // read one byte past the limit, so a report at the limit is still told apart from one over it
                final byte[] buffer = new byte[MAX_REPORT_BYTES + 1];
                final int length = IOUtils.read(req.getInputStream(), buffer);
                if (length > MAX_REPORT_BYTES) {
                    return ActionResult.BAD_REQUEST;
                }
                LOGGER.warn("{}", asSingleLine(new String(buffer, 0, length, StandardCharsets.UTF_8)));
                return ActionResult.OK;
            }
        }
        return ActionResult.BAD_REQUEST;
    }

    private static String asSingleLine(String report) {
        return CONTROL_CHARACTERS.matcher(report).replaceAll(" ");
    }

}

package org.jahia.modules.csp.actions;

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
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class ReportOnlyAction extends Action {

    private static final Logger LOGGER = LoggerFactory.getLogger(ReportOnlyAction.class);
    public static final String CSP_REPORT_ONLY = "cspReportOnly";

    @Override
    public ActionResult doExecute(HttpServletRequest req, RenderContext renderContext, Resource resource, JCRSessionWrapper session, Map<String, List<String>> parameters, URLResolver urlResolver) throws Exception {
        if ("application/csp-report".equals(req.getContentType())) {
            final JCRSiteNode site = renderContext.getSite();
            if (site.hasProperty(CSP_REPORT_ONLY) && site.getProperty(CSP_REPORT_ONLY).getBoolean()) {
                final String report = IOUtils.toString(req.getInputStream());
                LOGGER.warn(report);
                return ActionResult.OK;
            }
        }
        return ActionResult.BAD_REQUEST;
    }

}

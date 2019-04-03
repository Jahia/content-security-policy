package org.jahia.modules.csp;

import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.filter.AbstractFilter;
import org.jahia.services.render.filter.RenderChain;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

public class AddContentSecurityPolicy extends AbstractFilter implements ApplicationListener<ApplicationEvent> {

    private static final String CSP_SEPARATOR = ";";
    private static final String CSP_PROPERTY = "policy";

    @Override
    public String execute(String previousOut, RenderContext renderContext, Resource resource, RenderChain chain) throws Exception {
        final HttpServletResponse response = renderContext.getResponse();
        final StringBuffer contentSecurityPolicy = new StringBuffer();

        final String siteContentSecurityPolicy = renderContext.getSite().hasProperty(CSP_PROPERTY) ? renderContext.getSite().getProperty(CSP_PROPERTY).getString() : null;

        if (StringUtils.isNotEmpty(siteContentSecurityPolicy)) {
            contentSecurityPolicy.append(siteContentSecurityPolicy);
        }

        final JCRNodeWrapper page = renderContext.getMainResource().getNode();
        final String pageContentSecurityPolicy = page.hasProperty(CSP_PROPERTY) ? page.getProperty(CSP_PROPERTY).getString() : null;

        if (StringUtils.isNotEmpty(pageContentSecurityPolicy)) {
            if (contentSecurityPolicy.length() > 0) {
                contentSecurityPolicy.append(CSP_SEPARATOR);
            }
            contentSecurityPolicy.append(pageContentSecurityPolicy);
        }

        if (contentSecurityPolicy.length() > 0) {
            response.setHeader("Content-Security-Policy", contentSecurityPolicy.toString());
        }

        return previousOut;
    }

    @Override
    public void onApplicationEvent(ApplicationEvent e) {
    }
}

package org.jahia.modules.csp.taglib;

import org.jahia.modules.csp.AddContentSecurityPolicy;
import org.jahia.settings.SettingsBean;

/**
 * Generates nonce placeholder for inline scipts
 */
public class ContentSecurityPolicyNonce {

    public static String noncePlaceholder() {
        String placeHolderName= SettingsBean.getInstance().getPropertiesFile().getProperty(AddContentSecurityPolicy.CSP_NONCE_PLACEHOLDER_PROP, "XXXXX");
        return String.format("nonce=\"%s\"", placeHolderName);
    }
}

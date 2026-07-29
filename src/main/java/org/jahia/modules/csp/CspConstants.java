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

/**
 * Single source of truth for the JCR property names (defined in {@code definitions.cnd}) and the
 * report-action coordinates shared by the render filter and the report endpoint.
 */
public final class CspConstants {

    /** Enforced policy, on {@code jmix:siteContentSecurityPolicy} and {@code jmix:pageContentSecurityPolicy}. */
    public static final String PROP_POLICY = "policy";
    /** Report-only policy delivered alongside the enforced one, on both mixins. */
    public static final String PROP_POLICY_REPORT_ONLY = "policyReportOnly";
    /** Legacy toggle: deliver the enforced policy in report-only mode. Site level only. */
    public static final String PROP_CSP_REPORT_ONLY = "cspReportOnly";
    /** Custom violation report URL; blank means report to the built-in action. Site level only. */
    public static final String PROP_CSP_REPORT_URL = "cspReportUrl";

    /** Name of the built-in violation-report action. */
    public static final String REPORT_ACTION_NAME = "contentSecurityPolicyReportOnly";
    /** URL suffix of the built-in violation-report action. */
    public static final String REPORT_ACTION_SUFFIX = "." + REPORT_ACTION_NAME + ".do";
    /** Endpoint name used in the Reporting-Endpoints header and the report-to directive. */
    public static final String CSP_ENDPOINT_NAME = "csp-endpoint";

    private CspConstants() {
        // constants holder
    }
}

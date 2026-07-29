import {addMixins, createSite, deleteSite, enableModule, publishAndWaitJobEnding, setNodeProperty} from '@jahia/cypress';

/**
 * A violation report is a small JSON document, so what this endpoint accepts is bounded: anything
 * past that size is refused rather than read.
 */
describe('CSP violation report endpoint', () => {
    const SITE_KEY = 'csp-report-endpoint-test-site';
    const ENDPOINT = `/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do`;
    const REPORT = '{"csp-report":{"document-uri":"http://localhost/","violated-directive":"script-src"}}';

    const post = (body: string) =>
        cy.request({
            method: 'POST',
            url: ENDPOINT,
            body,
            headers: {'Content-Type': 'application/csp-report'},
            failOnStatusCode: false
        });

    beforeEach('create a site with report-only enabled', () => {
        createSite(SITE_KEY, {
            locale: 'en',
            serverName: 'localhost',
            templateSet: 'content-security-policy-test-module'
        });
        enableModule('content-security-policy', SITE_KEY);
        addMixins(`/sites/${SITE_KEY}`, ['jmix:siteContentSecurityPolicy']);
        setNodeProperty(`/sites/${SITE_KEY}`, 'policy', 'script-src \'self\'', 'en');
        setNodeProperty(`/sites/${SITE_KEY}`, 'cspReportOnly', 'true', 'en');
        publishAndWaitJobEnding(`/sites/${SITE_KEY}`, ['en']);
    });

    afterEach('delete the site', () => {
        deleteSite(SITE_KEY);
    });

    it('accepts a violation report', () => {
        post(REPORT).its('status').should('equal', 200);
    });

    it('refuses a report past the accepted size', () => {
        // Anchor: the same request under the size is accepted, so a refusal below is about the size
        post(REPORT).its('status').should('equal', 200);

        post('A'.repeat(1024 * 1024)).its('status').should('not.equal', 200);
    });
});

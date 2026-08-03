import {addMixins, createSite, deleteSite, enableModule, publishAndWaitJobEnding, setNodeProperty} from '@jahia/cypress';

/**
 * A violation report is a small JSON document, so what this endpoint accepts is bounded: anything
 * past that size is refused rather than read.
 */
describe('CSP violation report endpoint', () => {
    const SITE_KEY = 'csp-report-endpoint-test-site';
    const ENDPOINT = `/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do`;
    const MAX_REPORT_BYTES = 64 * 1024;

    const report = (blockedUri: string) =>
        JSON.stringify({'csp-report': {'document-uri': 'http://localhost/', 'violated-directive': 'script-src', 'blocked-uri': blockedUri}});

    // A report of an exact size is a valid one padded to it — the padding is ASCII, so one padding
    // character is one byte.
    const reportOf = (bytes: number) => report('x'.repeat(bytes - report('').length));

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
        post(report('http://localhost/inline')).its('status').should('equal', 200);
    });

    it('accepts a report at the accepted size and refuses one byte past it', () => {
        const atLimit = reportOf(MAX_REPORT_BYTES);
        // The assumption the pair rests on: this report is 64 KB on the wire, not 64 K characters
        expect(new TextEncoder().encode(atLimit)).to.have.length(MAX_REPORT_BYTES);

        // Anchor: the same report, one byte shorter, is accepted — so the refusal is about the size
        // alone. Both bodies are valid reports; only their length differs.
        post(atLimit).its('status').should('equal', 200);
        post(reportOf(MAX_REPORT_BYTES + 1)).its('status').should('equal', 400);
    });
});

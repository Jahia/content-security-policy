import {
    addMixins,
    createSite,
    deleteSite,
    enableModule,
    publishAndWaitJobEnding,
    setNodeProperty
} from '@jahia/cypress';

describe('Test response headers of the Content Security Policy (CSP) filter', () => {
    const SITE_KEY = 'content-security-policy-test-site';
    const PAGES = ['home', 'simple'];

    function enableCSPModule() {
        enableModule('content-security-policy', SITE_KEY);
    }

    function configureCSPPolicyGlobally(policy: string, reportOnly = false) {
        const path = `/sites/${SITE_KEY}`;
        addMixins(path, ['jmix:siteContentSecurityPolicy']);
        setNodeProperty(path, 'policy', policy, 'en');
        setNodeProperty(path, 'cspReportOnly', reportOnly.toString(), 'en');
    }

    beforeEach('create test data', () => {
        createSite(SITE_KEY, {
            locale: 'en',
            serverName: 'localhost',
            templateSet: 'content-security-policy-test-module'
        });
        publishAndWaitJobEnding('/sites/' + SITE_KEY, ['en']);
    });

    afterEach('delete test data', () => {
        deleteSite(SITE_KEY);
    });

    it('GIVEN CSP not enabled WHEN loading a page THEN the response headers are not set', () => {
        cy.request('/sites/' + SITE_KEY + '/home.html').then(response => {
            expect(response.headers['content-security-policy']).to.be.undefined;
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.be.undefined;
        });
    });

    it('GIVEN CSP configured at the site level with an empty policy WHEN loading a page THEN the response headers are not set', () => {
        enableCSPModule();
        configureCSPPolicyGlobally('');

        cy.request('/sites/' + SITE_KEY + '/home.html').then(response => {
            expect(response.headers['content-security-policy']).to.be.undefined;
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.be.undefined;
        });
    });

    it('GIVEN CSP configured at the site level with a policy WHEN loading a page THEN the response headers are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(policy);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.equal(`${policy}; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do`);
                expect(response.headers['content-security-policy-report-only']).to.be.undefined;
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level with a policy and report only WHEN loading a page THEN the response headers are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'default-src \'self\'';
        configureCSPPolicyGlobally(policy, true);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.be.undefined;
                expect(response.headers['content-security-policy-report-only']).to.equal(`${policy}; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do`);
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });
});

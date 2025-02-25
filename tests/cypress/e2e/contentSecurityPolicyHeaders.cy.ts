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

    function configureCSPPolicyForPage(page: string, policy: string, reportOnly = false) {
        const path = `/sites/${SITE_KEY}/${page}`;
        addMixins(path, ['jmix:siteContentSecurityPolicy']);
        setNodeProperty(path, 'policy', policy, 'en');
        setNodeProperty(path, 'cspReportOnly', reportOnly.toString(), 'en');
        publishAndWaitJobEnding(path, ['en']);
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

    it('GIVEN CSP configured at the site level with a policy WHEN loading pages THEN the response headers are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(policy);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.equal(`${policy}; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
                expect(response.headers['content-security-policy-report-only']).to.be.undefined;
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level with a policy and report only WHEN loading pages THEN the response headers are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'default-src \'self\'';
        configureCSPPolicyGlobally(policy, true);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.be.undefined;
                expect(response.headers['content-security-policy-report-only']).to.equal(`${policy}; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level and for a page WHEN loading pages THEN the response headers for that page contain the additional directives', () => {
        enableCSPModule();
        const sitePolicy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(sitePolicy);
        const pagePolicy = 'img-src \'none\'; style-src \'none\'';
        configureCSPPolicyForPage('home', pagePolicy);
        cy.intercept(`/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do`, {}).as('cspAttacks');

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            // Page with both site and page policies
            expect(response.headers['content-security-policy'], 'the header should contain both the site and the page policies').to.equal(`${sitePolicy};${pagePolicy}; report-uri /sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do"`);
        });
        cy.request(`/sites/${SITE_KEY}/simple.html`).then(response => {
            // Page with only site policy
            expect(response.headers['content-security-policy'], 'the header should only contain the site policy').to.equal(`${sitePolicy}; report-uri /sites/${SITE_KEY}/simple.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/simple.contentSecurityPolicyReportOnly.do"`);
        });
        cy.wait('@cspAttacks').its('request.body').should('include', 'blocked');
    });

    it('GIVEN CSP configured to restrict img src WHEN loading a page THEN only the legit resources should be loaded by the browser', () => {
        enableCSPModule();
        const sitePolicy = 'img-src example.com';
        configureCSPPolicyGlobally(sitePolicy);
        const legitResource = 'https://example.com/legit.jpg';
        const forbiddenResource = 'https://hacker.com/forbidden.jpg';
        cy.intercept('**/*.jpg', {statusCode: 200}).as('images');

        cy.visit(`/sites/${SITE_KEY}/home.html`);
        cy.get('#htmlInput').type(`Injected images:<img src="${forbiddenResource}"/><img src="${legitResource}"/>`);
        cy.get('#sendButton').click();
        cy.contains('#outputDiv', 'Injected images');

        cy.wait('@images').its('response.statusCode').should('eq', 200);
        cy.get('@images.all').then(interceptions => {
            const requestedUrls = interceptions.map(interception => interception.request.url);
            expect(requestedUrls).to.include(legitResource);
            expect(requestedUrls).to.not.include(forbiddenResource);
        });
        // NB: it's not possible to test that the browser actually calls the CSP endpoint as the endpoint must use https (which is not the case in our CI setup)
    });
});

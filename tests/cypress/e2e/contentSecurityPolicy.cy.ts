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

    function configureCSPPolicyGlobally(policy: string, reportUrl: string, reportOnly?: boolean, reportOnlyPolicy?: string) {
        const path = `/sites/${SITE_KEY}`;
        addMixins(path, ['jmix:siteContentSecurityPolicy']);
        setNodeProperty(path, 'policy', policy, 'en');
        setNodeProperty(path, 'cspReportUrl', reportUrl, 'en');
        setNodeProperty(path, 'cspReportOnly', (reportOnly ?? false).toString(), 'en');
        if (reportOnlyPolicy !== undefined) {
            setNodeProperty(path, 'policyReportOnly', reportOnlyPolicy, 'en');
        }
    }

    function configureCSPPolicyForPage(page: string, policy?: string, reportOnlyPolicy?: string) {
        const path = `/sites/${SITE_KEY}/${page}`;
        addMixins(path, ['jmix:pageContentSecurityPolicy']);
        if (policy !== undefined) {
            setNodeProperty(path, 'policy', policy, 'en');
        }

        if (reportOnlyPolicy !== undefined) {
            setNodeProperty(path, 'policyReportOnly', reportOnlyPolicy, 'en');
        }

        publishAndWaitJobEnding(path, ['en']);
    }

    function extractNonce(headerValue: string | undefined): string | null {
        if (!headerValue) {
            return null;
        }

        const match = headerValue.match(/'nonce-([a-zA-Z0-9_-]+)'/);
        return match ? match[1] : null;
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

    it('GIVEN CSP configured at the site level with an empty policy and no custom url WHEN loading a page THEN the response headers are not set', () => {
        enableCSPModule();
        configureCSPPolicyGlobally('', '');

        cy.request('/sites/' + SITE_KEY + '/home.html').then(response => {
            expect(response.headers['content-security-policy']).to.be.undefined;
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.be.undefined;
        });
    });

    it('GIVEN CSP configured at the site level with an empty policy and defined custom url WHEN loading a page THEN the response headers are not set', () => {
        enableCSPModule();
        configureCSPPolicyGlobally('', 'https://www.example.com/csp-report');

        cy.request('/sites/' + SITE_KEY + '/home.html').then(response => {
            expect(response.headers['content-security-policy']).to.be.undefined;
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.be.undefined;
        });
    });

    it('GIVEN CSP configured at the site level with a policy and empty custom url WHEN loading pages THEN the response headers with default report action are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(policy, '');

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.equal(`${policy}; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
                expect(response.headers['content-security-policy-report-only']).to.be.undefined;
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level with a policy using nonce WHEN loading pages THEN the response headers contains a unique nonce value', () => {
        enableCSPModule();
        const policy = 'script-src \'nonce-\' js.example.com';
        configureCSPPolicyGlobally(policy, '');

        PAGES.forEach(page => {
            // Perform two request to verify that the nonce is unique per request
            let firstNonce: string | null;
            let secondNonce: string | null;

            cy.request(`/sites/${SITE_KEY}/${page}.html`)
                .then(firstResponse => {
                    firstNonce = extractNonce(firstResponse.headers['content-security-policy']);
                    return cy.request(`/sites/${SITE_KEY}/${page}.html`);
                })
                .then(secondResponse => {
                    secondNonce = extractNonce(secondResponse.headers['content-security-policy']);

                    // Check that nonces exist and are different
                    expect(firstNonce, 'first nonce should exist').to.not.be.null;
                    expect(secondNonce, 'second nonce should exist').to.not.be.null;
                    expect(firstNonce, 'nonce should be unique per request').to.not.equal(secondNonce);
                });
        });
    });

    it('GIVEN CSP configured at the site level with a policy and defined custom url WHEN loading pages THEN the response headers with defined report url are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(policy, 'https://www.example.com/csp-report');

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.equal(`${policy}; report-uri https://www.example.com/csp-report; report-to csp-endpoint`);
                expect(response.headers['content-security-policy-report-only']).to.be.undefined;
                // eslint-disable-next-line quotes
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="https://www.example.com/csp-report"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level with a policy and empty custom url and report only WHEN loading pages THEN the response headers are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'default-src \'self\'';
        configureCSPPolicyGlobally(policy, '', true);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.be.undefined;
                expect(response.headers['content-security-policy-report-only']).to.equal(`${policy}; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level with a policy and defined custom url and report only WHEN loading pages THEN the response headers with defined report url are correctly set for all pages', () => {
        enableCSPModule();
        const policy = 'default-src \'self\'';
        configureCSPPolicyGlobally(policy, 'https://www.example.com/csp-report', true);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                expect(response.headers['content-security-policy']).to.be.undefined;
                expect(response.headers['content-security-policy-report-only']).to.equal(`${policy}; report-uri https://www.example.com/csp-report; report-to csp-endpoint`);
                // eslint-disable-next-line quotes
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="https://www.example.com/csp-report"`);
            });
        });
    });

    it('GIVEN CSP configured at the site level and at the page level WHEN loading pages THEN the page-level policies replace the site-level policies', () => {
        enableCSPModule();
        const sitePolicy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(sitePolicy, '');
        const pagePolicy = 'img-src \'none\'; style-src \'none\'';
        configureCSPPolicyForPage('home', pagePolicy);

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            // Page with page policies
            expect(response.headers['content-security-policy'], 'the header should contain both the site and the page policies').to.equal(`${pagePolicy}; report-uri /sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do"`);
        });
        cy.request(`/sites/${SITE_KEY}/simple.html`).then(response => {
            // Page with only site policy
            expect(response.headers['content-security-policy'], 'the header should only contain the site policy').to.equal(`${sitePolicy}; report-uri /sites/${SITE_KEY}/simple.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`);
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/simple.contentSecurityPolicyReportOnly.do"`);
        });
    });

    it('GIVEN CSP configured at the site level and at the page level and defined custom url WHEN loading pages THEN the page-level policies replace the site-level policies but keep the defined custom report url', () => {
        enableCSPModule();
        const sitePolicy = 'script-src \'self\' js.example.com';
        configureCSPPolicyGlobally(sitePolicy, 'https://www.example.com/csp-report');
        const pagePolicy = 'img-src \'none\'; style-src \'none\'';
        configureCSPPolicyForPage('home', pagePolicy);

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            // Page with page policies
            expect(response.headers['content-security-policy'], 'the header should contain both the site and the page policies').to.equal(`${pagePolicy}; report-uri https://www.example.com/csp-report; report-to csp-endpoint`);
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            // eslint-disable-next-line quotes
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="https://www.example.com/csp-report"`);
        });
        cy.request(`/sites/${SITE_KEY}/simple.html`).then(response => {
            // Page with only site policy
            expect(response.headers['content-security-policy'], 'the header should only contain the site policy').to.equal(`${sitePolicy}; report-uri https://www.example.com/csp-report; report-to csp-endpoint`);
            expect(response.headers['content-security-policy-report-only']).to.be.undefined;
            // eslint-disable-next-line quotes
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="https://www.example.com/csp-report"`);
        });
    });

    it('GIVEN an enforced policy AND a report-only policy WHEN loading pages THEN both headers are set independently', () => {
        enableCSPModule();
        const policy = 'script-src \'self\' js.example.com';
        const reportOnlyPolicy = 'default-src \'self\'';
        configureCSPPolicyGlobally(policy, '', false, reportOnlyPolicy);

        PAGES.forEach(page => {
            cy.request(`/sites/${SITE_KEY}/${page}.html`).then(response => {
                const suffix = `; report-uri /sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`;
                expect(response.headers['content-security-policy'], 'enforced policy header').to.equal(`${policy}${suffix}`);
                expect(response.headers['content-security-policy-report-only'], 'report-only policy header').to.equal(`${reportOnlyPolicy}${suffix}`);
                expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/${page}.contentSecurityPolicyReportOnly.do"`);
            });
        });
    });

    it('GIVEN only a report-only policy and no enforced policy WHEN loading a page THEN only the report-only header is set', () => {
        enableCSPModule();
        const reportOnlyPolicy = 'default-src \'self\'';
        configureCSPPolicyGlobally('', '', false, reportOnlyPolicy);

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            const suffix = `; report-uri /sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`;
            expect(response.headers['content-security-policy']).to.be.undefined;
            expect(response.headers['content-security-policy-report-only']).to.equal(`${reportOnlyPolicy}${suffix}`);
            expect(response.headers['reporting-endpoints']).to.equal(`csp-endpoint="/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do"`);
        });
    });

    it('GIVEN a site enforced policy and a page-level report-only policy WHEN loading the page THEN each header reflects its own level', () => {
        enableCSPModule();
        const sitePolicy = 'script-src \'self\'';
        configureCSPPolicyGlobally(sitePolicy, '');
        const pageReportOnlyPolicy = 'default-src \'none\'';
        configureCSPPolicyForPage('home', undefined, pageReportOnlyPolicy);

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            const suffix = `; report-uri /sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do; report-to csp-endpoint`;
            expect(response.headers['content-security-policy'], 'enforced policy stays at site level').to.equal(`${sitePolicy}${suffix}`);
            expect(response.headers['content-security-policy-report-only'], 'report-only policy comes from the page level').to.equal(`${pageReportOnlyPolicy}${suffix}`);
        });
    });

    it('GIVEN a policy that already declares report-uri WHEN loading a page THEN the module does not duplicate it', () => {
        enableCSPModule();
        const policy = 'default-src \'self\'; report-uri https://custom.example.com/r';
        configureCSPPolicyGlobally(policy, '');

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            const header = response.headers['content-security-policy'];
            // The author-declared report-uri is preserved and the default endpoint is NOT appended
            expect(header).to.contain('report-uri https://custom.example.com/r');
            expect(header).to.not.contain('contentSecurityPolicyReportOnly.do');
            expect((header.match(/report-uri/g) || []).length, 'report-uri should appear exactly once').to.equal(1);
            // Report-to was not declared, so it is still appended
            expect(header).to.contain('report-to csp-endpoint');
        });
    });

    it('GIVEN a policy using nonce WHEN loading a page THEN the header nonce is injected into script, style and link tags', () => {
        enableCSPModule();
        const policy = 'script-src \'nonce-\'; style-src \'nonce-\'';
        configureCSPPolicyGlobally(policy, '');

        cy.request(`/sites/${SITE_KEY}/home.html`).then(response => {
            const nonce = extractNonce(response.headers['content-security-policy']);
            expect(nonce, 'nonce should exist in the header').to.not.be.null;
            // The SAME nonce must appear in the body for scripts AND stylesheets (nonce-source covers both)
            expect(response.body, 'script tag carries the nonce').to.contain(`<script nonce="${nonce}"`);
            expect(response.body, 'style tag carries the nonce').to.contain(`<style nonce="${nonce}"`);
            expect(response.body, 'stylesheet link carries the nonce').to.contain(`<link nonce="${nonce}"`);
        });
    });

    it('GIVEN a policy using nonce WHEN loading the same page twice THEN header and body nonces match on every response and caching is forbidden', () => {
        enableCSPModule();
        configureCSPPolicyGlobally('script-src \'nonce-\'', '');

        const assertNonceConsistency = (response: Cypress.Response<string>) => {
            const nonce = extractNonce(response.headers['content-security-policy'] as string);
            expect(nonce, 'nonce should exist in the header').to.not.be.null;
            expect(response.headers['cache-control'], 'nonce responses must not be cacheable').to.equal('no-store');
            expect(response.body, 'body nonce must match the header nonce').to.contain(`nonce="${nonce}"`);
        };

        cy.request(`/sites/${SITE_KEY}/home.html`)
            .then(firstResponse => {
                assertNonceConsistency(firstResponse);
                return cy.request(`/sites/${SITE_KEY}/home.html`);
            })
            .then(secondResponse => {
                assertNonceConsistency(secondResponse);
            });
    });

    it('GIVEN a policy configured WHEN posting a violation report THEN the endpoint accepts it', () => {
        enableCSPModule();
        configureCSPPolicyGlobally('default-src \'self\'', '');

        cy.request({
            method: 'POST',
            url: `/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do`,
            headers: {'Content-Type': 'application/csp-report'},
            body: '{"csp-report":{"document-uri":"https://example.com/p","effective-directive":"script-src","blocked-uri":"https://evil.com/x.js"}}',
            failOnStatusCode: false
        }).then(response => {
            expect(response.status, 'a report for a configured site is accepted').to.equal(200);
        });
    });

    it('GIVEN a policy configured WHEN a self-declared bot posts a violation report THEN the endpoint still accepts it', () => {
        // The bot filter only demotes the log level: the report must keep getting HTTP 200
        // (this also verifies the vendored crawler-user-agents list loads inside the OSGi bundle)
        enableCSPModule();
        configureCSPPolicyGlobally('default-src \'self\'', '');

        cy.request({
            method: 'POST',
            url: `/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do`,
            headers: {
                'Content-Type': 'application/csp-report',
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/148.0.0.0 Safari/537.36'
            },
            body: '{"csp-report":{"document-uri":"https://example.com/p","effective-directive":"script-src","blocked-uri":"https://evil.com/x.js"}}',
            failOnStatusCode: false
        }).then(response => {
            expect(response.status, 'a bot report is accepted (only its log level changes)').to.equal(200);
        });
    });

    it('GIVEN no CSP configuration WHEN posting a violation report THEN the endpoint rejects it', () => {
        enableCSPModule();

        cy.request({
            method: 'POST',
            url: `/sites/${SITE_KEY}/home.contentSecurityPolicyReportOnly.do`,
            headers: {'Content-Type': 'application/csp-report'},
            body: '{"csp-report":{"document-uri":"https://example.com/p","effective-directive":"script-src","blocked-uri":"https://evil.com/x.js"}}',
            failOnStatusCode: false
        }).then(response => {
            expect(response.status, 'a report for an unconfigured site is rejected').to.equal(400);
        });
    });

    it('GIVEN CSP configured to restrict img src WHEN loading a page THEN only the legit resources should be loaded by the browser', () => {
        enableCSPModule();
        const sitePolicy = 'img-src example.com';
        configureCSPPolicyGlobally(sitePolicy, '');
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

package com.verithreat.ioc.api;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;

class GatewayTokenFilterTest {

    private MockFilterChain run(GatewayTokenFilter f, String uri, String token, MockHttpServletResponse res)
            throws Exception {
        MockHttpServletRequest req = new MockHttpServletRequest("GET", uri);
        req.setRequestURI(uri);
        if (token != null) {
            req.addHeader(GatewayTokenFilter.HEADER, token);
        }
        MockFilterChain chain = new MockFilterChain();
        f.doFilter(req, res, chain);
        return chain;
    }

    @Test
    void rejectsApiRequestsWithoutTheRightToken() throws Exception {
        GatewayTokenFilter f = new GatewayTokenFilter("s3cret");
        for (String token : new String[] {null, "", "wrong", "s3cret "}) {
            MockHttpServletResponse res = new MockHttpServletResponse();
            MockFilterChain chain = run(f, "/api/v1/indicators", token, res);
            assertEquals(401, res.getStatus(), "token " + token);
            assertNull(chain.getRequest(), "the request must not reach the controller");
        }
    }

    @Test
    void acceptsTheRightTokenAndLeavesNonApiPathsAlone() throws Exception {
        GatewayTokenFilter f = new GatewayTokenFilter("s3cret");
        MockHttpServletResponse ok = new MockHttpServletResponse();
        assertNotNull(run(f, "/api/v1/indicators", "s3cret", ok).getRequest());
        assertEquals(200, ok.getStatus());
        assertNotNull(run(f, "/swagger-ui/index.html", null, new MockHttpServletResponse()).getRequest());
    }

    @Test
    void withoutConfiguredTokenEverythingPasses() throws Exception {
        GatewayTokenFilter f = new GatewayTokenFilter("");
        assertNotNull(run(f, "/api/v1/indicators", null, new MockHttpServletResponse()).getRequest());
    }
}

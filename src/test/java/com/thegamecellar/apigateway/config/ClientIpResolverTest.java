package com.thegamecellar.apigateway.config;

import org.junit.jupiter.api.Test;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.test.util.ReflectionTestUtils;

import static org.assertj.core.api.Assertions.assertThat;

class ClientIpResolverTest {

    private ClientIpResolver newResolver(String trustedProxies) {
        ClientIpResolver resolver = new ClientIpResolver();
        ReflectionTestUtils.setField(resolver, "trustedProxiesConfig", trustedProxies);
        ReflectionTestUtils.invokeMethod(resolver, "init");
        return resolver;
    }

    private MockHttpServletRequest request(String remoteAddr, String xff) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setRemoteAddr(remoteAddr);
        if (xff != null) {
            request.addHeader("X-Forwarded-For", xff);
        }
        return request;
    }

    @Test
    void emptyAllowlist_ignoresForwardedHeader() {
        ClientIpResolver resolver = newResolver("");
        String ip = resolver.resolve(request("203.0.113.9", "1.2.3.4"));
        assertThat(ip).isEqualTo("203.0.113.9");
    }

    @Test
    void untrustedPeer_ignoresSpoofedForwardedHeader() {
        ClientIpResolver resolver = newResolver("10.0.0.0/8");
        String ip = resolver.resolve(request("203.0.113.9", "1.2.3.4"));
        assertThat(ip).isEqualTo("203.0.113.9");
    }

    @Test
    void trustedPeer_singleHop_returnsForwardedClient() {
        ClientIpResolver resolver = newResolver("10.0.0.0/8");
        String ip = resolver.resolve(request("10.0.0.5", "203.0.113.9"));
        assertThat(ip).isEqualTo("203.0.113.9");
    }

    @Test
    void trustedPeer_multiHopChain_skipsTrustedAndReturnsRealClient() {
        // Client-prepended spoof sits leftmost; real client + trusted proxies follow.
        ClientIpResolver resolver = newResolver("10.0.0.0/8");
        String ip = resolver.resolve(request("10.0.0.5", "6.6.6.6, 203.0.113.9, 10.0.0.9"));
        assertThat(ip).isEqualTo("203.0.113.9");
    }

    @Test
    void trustedPeer_noForwardedHeader_returnsRemoteAddr() {
        ClientIpResolver resolver = newResolver("10.0.0.0/8");
        String ip = resolver.resolve(request("10.0.0.5", null));
        assertThat(ip).isEqualTo("10.0.0.5");
    }

    @Test
    void trustedPeer_wholeChainTrusted_fallsBackToRemoteAddr() {
        ClientIpResolver resolver = newResolver("10.0.0.0/8");
        String ip = resolver.resolve(request("10.0.0.5", "10.0.0.7, 10.0.0.9"));
        assertThat(ip).isEqualTo("10.0.0.5");
    }

    @Test
    void singleIpEntry_matchesExactProxy() {
        ClientIpResolver resolver = newResolver("192.168.1.1");
        String ip = resolver.resolve(request("192.168.1.1", "203.0.113.9"));
        assertThat(ip).isEqualTo("203.0.113.9");
    }

    @Test
    void malformedForwardedToken_doesNotCrash_andIsTreatedAsClient() {
        ClientIpResolver resolver = newResolver("10.0.0.0/8");
        String ip = resolver.resolve(request("10.0.0.5", "not-an-ip"));
        assertThat(ip).isEqualTo("not-an-ip");
    }
}

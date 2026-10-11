package com.reiniertutoriales.nfdnsvpn.vpn

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsProvidersTest {
    @Test
    fun everyProviderIsEncrypted() {
        for (provider in DnsProviders.ALL) {
            assertTrue(provider.name, provider.servers.isNotEmpty() && provider.servers.all { DnsProviders.parseCustom(it) != null })
        }
        assertEquals("the default comes first", DnsProviders.DEFAULT, DnsProviders.ALL.first().id)
    }

    @Test
    fun customResolversMustBeEncrypted() {
        assertEquals(
            listOf("tls://9.9.9.9#dns.quad9.net", "tls://[2620:fe::fe]:853#dns.quad9.net"),
            DnsProviders.parseCustom(" tls://9.9.9.9#dns.quad9.net, tls://[2620:fe::fe]:853#dns.quad9.net "),
        )
        assertNull("plain DNS", DnsProviders.parseCustom("9.9.9.9"))
        assertNull("no certificate name", DnsProviders.parseCustom("tls://9.9.9.9"))
        assertNull(DnsProviders.parseCustom(""))
        // An invalid or unknown choice falls back to the encrypted default, never to plain DNS.
        assertEquals(DnsProviders.ALL.first().servers, DnsProviders.servers(DnsProviders.CUSTOM, "9.9.9.9"))
        assertEquals(DnsProviders.ALL.first().servers, DnsProviders.servers("network", ""))
    }
}

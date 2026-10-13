package com.reiniertutoriales.nfdnsvpn.vpn

import com.reiniertutoriales.nfdnsvpn.vpn.DnsProviders.Reason
import com.reiniertutoriales.nfdnsvpn.vpn.DnsProviders.Validation
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class DnsProvidersTest {
    @Test
    fun everyProviderIsEncryptedAndWithinTheLimits() {
        for (provider in DnsProviders.ALL) {
            val list = provider.servers.joinToString(",")
            assertEquals(provider.name, Validation.Valid(provider.servers), DnsProviders.validate(list))
        }
        assertEquals("the default comes first", DnsProviders.DEFAULT, DnsProviders.ALL.first().id)
    }

    /** The cases the core is tested against too (`upstream::tests::dot_lists_agree_with_the_app`). */
    @Test
    fun customListsAgreeWithTheCore() {
        val cases = javaClass.classLoader!!.getResource("dot-lists.txt")!!.readText()
        var checked = 0
        for (line in cases.lines().filter { it.isNotEmpty() && !it.startsWith('#') }) {
            val expected = line.substringBefore(' ')
            val list = line.substringAfter(' ', "")
            val got = when (val result = DnsProviders.validate(list)) {
                is Validation.Valid -> result.servers.size.toString()
                is Validation.Invalid -> result.reason.name
            }
            assertEquals(list, expected, got)
            checked++
        }
        assertTrue("$checked cases", checked > 50)
    }

    @Test
    fun theWholeListIsRefusedAtItsFirstBadEntry() {
        assertEquals(Validation.Invalid(Reason.PORT, 2), DnsProviders.validate("tls://1.1.1.1#a.b, ,tls://1.0.0.1:0#a.b,tls://x"))
        assertEquals(Validation.Invalid(Reason.DUPLICATE, 2), DnsProviders.validate("tls://1.1.1.1#a.b,tls://1.1.1.1#c.d"))
        assertEquals(Validation.Invalid(Reason.DUPLICATE, 2), DnsProviders.validate("tls://[2620:fe::fe]#a.b,tls://[2620:FE:0::FE]:853#a.b"))
        assertNull("plain DNS", DnsProviders.parseCustom("9.9.9.9"))
        // What is used and shown is the list as typed, trimmed and without empty entries.
        assertEquals(
            listOf("tls://9.9.9.9#dns.quad9.net", "tls://[2620:fe::fe]:853#dns.quad9.net"),
            DnsProviders.parseCustom(" tls://9.9.9.9#dns.quad9.net,, tls://[2620:fe::fe]:853#dns.quad9.net "),
        )
    }

    @Test
    fun aRefusedOrUnknownChoiceIsShownAndUsedAsTheDefault() {
        val default = DnsProviders.ALL.first().servers
        for ((id, custom) in listOf(DnsProviders.CUSTOM to "9.9.9.9", DnsProviders.CUSTOM to "", "network" to "")) {
            assertEquals(DnsProviders.DEFAULT, DnsProviders.effective(id, custom))
            assertEquals(default, DnsProviders.servers(id, custom))
        }
        // A list the older, looser rules let through: an address as the certificate name.
        assertEquals(DnsProviders.DEFAULT, DnsProviders.effective(DnsProviders.CUSTOM, "tls://1.1.1.1#1.1.1.1"))
        val custom = "tls://9.9.9.9#dns.quad9.net"
        assertEquals(DnsProviders.CUSTOM, DnsProviders.effective(DnsProviders.CUSTOM, custom))
        assertEquals(listOf(custom), DnsProviders.servers(DnsProviders.CUSTOM, custom))
        assertEquals("google", DnsProviders.effective("google", custom))
    }
}

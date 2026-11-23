package com.linko.gateway

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class GatewayCredentialCodecTest {
    @Test
    fun encodesAndDecodesApprovedSessionConfig() {
        val expectedPrivateKey = ByteArray(32) { (it + 1).toByte() }
        val expectedPeerKey = ByteArray(32) { (it + 33).toByte() }
        val expectedSessionId = ByteArray(16) { (it + 65).toByte() }
        val original = credentials(expectedPrivateKey, expectedPeerKey, expectedSessionId)

        val encoded = try {
            GatewayCredentialCodec.encode(original)
        } finally {
            original.close()
        }

        val restored = GatewayCredentialCodec.decode(encoded)
        encoded.fill(0)

        try {
            restored.useWireGuardConfig { privateKey, peerKey, sessionId, relay, local, peer, mtu ->
                assertArrayEquals(expectedPrivateKey, privateKey)
                assertArrayEquals(expectedPeerKey, peerKey)
                assertArrayEquals(expectedSessionId, sessionId)
                assertEquals("relay.linko.example:51820", relay)
                assertEquals("10.77.0.1", local)
                assertEquals("10.77.0.2", peer)
                assertEquals(1280, mtu)
            }
        } finally {
            restored.close()
        }
    }

    @Test
    fun rejectsUnsupportedPayloadVersion() {
        val original = credentials()
        val encoded = try {
            GatewayCredentialCodec.encode(original)
        } finally {
            original.close()
        }

        encoded[3] = 2
        try {
            GatewayCredentialCodec.decode(encoded)
            throw AssertionError("Expected unsupported credential version to fail")
        } catch (error: GatewayCredentialException) {
            assertTrue(error.message!!.contains("unsupported format"))
        } finally {
            encoded.fill(0)
        }
    }

    @Test
    fun rejectsTrailingPayloadBytes() {
        val original = credentials()
        val encoded = try {
            GatewayCredentialCodec.encode(original)
        } finally {
            original.close()
        }
        val withTrailingByte = encoded + byteArrayOf(1)
        encoded.fill(0)

        try {
            GatewayCredentialCodec.decode(withTrailingByte)
            throw AssertionError("Expected trailing data to fail")
        } catch (error: GatewayCredentialException) {
            assertTrue(error.message!!.contains("trailing data"))
        } finally {
            withTrailingByte.fill(0)
        }
    }

    @Test
    fun useCallbackWipesRawBuffersAfterItReturns() {
        val credentials = credentials()
        var privateKeyReference: ByteArray? = null
        var sessionIdReference: ByteArray? = null

        credentials.useWireGuardConfig { privateKey, _, sessionId, _, _, _, _ ->
            privateKeyReference = privateKey
            sessionIdReference = sessionId
        }

        assertTrue(privateKeyReference!!.all { it.toInt() == 0 })
        assertTrue(sessionIdReference!!.all { it.toInt() == 0 })
        assertFalse(runCatching {
            credentials.useWireGuardConfig { _, _, _, _, _, _, _ -> }
        }.isSuccess)
    }

    private fun credentials(
        privateKey: ByteArray = ByteArray(32) { (it + 1).toByte() },
        peerKey: ByteArray = ByteArray(32) { (it + 33).toByte() },
        sessionId: ByteArray = ByteArray(16) { (it + 65).toByte() }
    ) = GatewaySessionCredentials(
        privateKey = privateKey,
        peerPublicKey = peerKey,
        sessionId = sessionId,
        relayAddress = "relay.linko.example:51820",
        localAddress = "10.77.0.1",
        peerAddress = "10.77.0.2",
        mtu = 1280
    )
}

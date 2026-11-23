package com.linko.gateway

import java.io.ByteArrayInputStream
import java.io.ByteArrayOutputStream
import java.io.DataInputStream
import java.io.DataOutputStream

/**
 * Versioned binary encoding for the encrypted credential payload.
 *
 * The encoded bytes are always encrypted before they reach persistent storage.
 */
internal object GatewayCredentialCodec {
    const val MAX_PLAINTEXT_BYTES = 4096

    fun encode(credentials: GatewaySessionCredentials): ByteArray {
        val buffer = WipingByteArrayOutputStream()
        val output = DataOutputStream(buffer)

        output.writeInt(FORMAT_VERSION)
        credentials.writeTo(output)
        output.flush()

        val encoded = buffer.takeBytes()
        if (encoded.size > MAX_PLAINTEXT_BYTES) {
            encoded.fill(0)
            throw GatewayCredentialException("Gateway credential record is too large")
        }
        return encoded
    }

    fun decode(encoded: ByteArray): GatewaySessionCredentials {
        if (encoded.isEmpty() || encoded.size > MAX_PLAINTEXT_BYTES) {
            throw GatewayCredentialException("Stored gateway credential record has an invalid size")
        }

        var privateKey: ByteArray? = null
        var peerPublicKey: ByteArray? = null
        var sessionId: ByteArray? = null

        try {
            val input = DataInputStream(ByteArrayInputStream(encoded))
            val version = input.readInt()
            if (version != FORMAT_VERSION) {
                throw GatewayCredentialException("Stored gateway credentials use an unsupported format")
            }

            privateKey = ByteArray(GatewaySessionCredentials.WIREGUARD_KEY_SIZE)
                .also(input::readFully)
            peerPublicKey = ByteArray(GatewaySessionCredentials.WIREGUARD_KEY_SIZE)
                .also(input::readFully)
            sessionId = ByteArray(GatewaySessionCredentials.SESSION_ID_SIZE)
                .also(input::readFully)

            val relayAddress = input.readString()
            val localAddress = input.readString()
            val peerAddress = input.readString()
            val mtu = input.readInt()

            if (input.available() != 0) {
                throw GatewayCredentialException("Stored gateway credential record has trailing data")
            }

            return GatewaySessionCredentials(
                privateKey = privateKey,
                peerPublicKey = peerPublicKey,
                sessionId = sessionId,
                relayAddress = relayAddress,
                localAddress = localAddress,
                peerAddress = peerAddress,
                mtu = mtu
            )
        } catch (error: GatewayCredentialException) {
            throw error
        } catch (error: Exception) {
            throw GatewayCredentialException("Stored gateway credential record is invalid", error)
        } finally {
            privateKey?.fill(0)
            peerPublicKey?.fill(0)
            sessionId?.fill(0)
        }
    }

    private fun DataInputStream.readString(): String {
        val size = readUnsignedShort()
        if (size == 0 || size > GatewaySessionCredentials.MAX_ADDRESS_BYTES) {
            throw GatewayCredentialException("Stored gateway address has an invalid size")
        }

        val bytes = ByteArray(size)
        readFully(bytes)
        return try {
            String(bytes, Charsets.UTF_8)
        } finally {
            bytes.fill(0)
        }
    }

    private class WipingByteArrayOutputStream : ByteArrayOutputStream() {
        fun takeBytes(): ByteArray {
            val copy = toByteArray()
            buf.fill(0)
            reset()
            return copy
        }
    }

    private const val FORMAT_VERSION = 1
}

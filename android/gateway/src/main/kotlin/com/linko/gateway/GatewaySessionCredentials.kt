package com.linko.gateway

import java.io.Closeable
import java.io.DataOutputStream

/**
 * One approved Phone A session's configuration.
 *
 * Key and session-token arrays are copied on construction and wiped when this
 * object is closed. Consume raw values only inside [useWireGuardConfig].
 */
class GatewaySessionCredentials(
    privateKey: ByteArray,
    peerPublicKey: ByteArray,
    sessionId: ByteArray,
    val relayAddress: String,
    val localAddress: String,
    val peerAddress: String,
    val mtu: Int
) : Closeable {
    private val privateKeyBytes: ByteArray
    private val peerPublicKeyBytes: ByteArray
    private val sessionIdBytes: ByteArray

    private var closed = false

    init {
        require(privateKey.size == WIREGUARD_KEY_SIZE) {
            "WireGuard private key must be 32 bytes"
        }
        require(peerPublicKey.size == WIREGUARD_KEY_SIZE) {
            "WireGuard peer public key must be 32 bytes"
        }
        require(sessionId.size == SESSION_ID_SIZE) {
            "Relay session ID must be 16 bytes"
        }
        require(privateKey.any { it.toInt() != 0 }) {
            "WireGuard private key must not be empty"
        }
        require(peerPublicKey.any { it.toInt() != 0 }) {
            "WireGuard peer public key must not be empty"
        }
        require(sessionId.any { it.toInt() != 0 }) {
            "Relay session ID must not be empty"
        }
        require(relayAddress.isNotBlank() && relayAddress.utf8Size() <= MAX_ADDRESS_BYTES) {
            "Relay address is invalid"
        }
        require(localAddress.isIPv4Literal()) {
            "Local tunnel address must be IPv4"
        }
        require(peerAddress.isIPv4Literal()) {
            "Peer tunnel address must be IPv4"
        }
        require(localAddress != peerAddress) {
            "Local and peer tunnel addresses must differ"
        }
        require(mtu in MIN_MTU..MAX_MTU) {
            "MTU must be between $MIN_MTU and $MAX_MTU"
        }

        privateKeyBytes = privateKey.copyOf()
        peerPublicKeyBytes = peerPublicKey.copyOf()
        sessionIdBytes = sessionId.copyOf()
    }

    /**
     * Gives the raw Go bridge inputs to a synchronous consumer and wipes all
     * key/session-token buffers as soon as the consumer returns.
     */
    @Synchronized
    fun useWireGuardConfig(
        consumer: (
            privateKey: ByteArray,
            peerPublicKey: ByteArray,
            sessionId: ByteArray,
            relayAddress: String,
            localAddress: String,
            peerAddress: String,
            mtu: Int
        ) -> Unit
    ) {
        check(!closed) { "Gateway credentials have already been consumed" }

        try {
            consumer(
                privateKeyBytes,
                peerPublicKeyBytes,
                sessionIdBytes,
                relayAddress,
                localAddress,
                peerAddress,
                mtu
            )
        } finally {
            close()
        }
    }

    @Synchronized
    override fun close() {
        if (closed) return

        privateKeyBytes.fill(0)
        peerPublicKeyBytes.fill(0)
        sessionIdBytes.fill(0)
        closed = true
    }

    @Synchronized
    internal fun writeTo(output: DataOutputStream) {
        check(!closed) { "Gateway credentials have been cleared" }

        output.write(privateKeyBytes)
        output.write(peerPublicKeyBytes)
        output.write(sessionIdBytes)
        output.writeString(relayAddress)
        output.writeString(localAddress)
        output.writeString(peerAddress)
        output.writeInt(mtu)
    }

    private fun String.utf8Size(): Int = toByteArray(Charsets.UTF_8).size

    private fun String.isIPv4Literal(): Boolean {
        val parts = split('.')
        if (parts.size != 4) return false

        return parts.all { part ->
            if (part.isEmpty() || part.length > 3 ||
                (part.length > 1 && part[0] == '0') ||
                part.any { !it.isDigit() }
            ) {
                false
            } else {
                part.toIntOrNull() in 0..255
            }
        }
    }

    private fun DataOutputStream.writeString(value: String) {
        val bytes = value.toByteArray(Charsets.UTF_8)
        require(bytes.isNotEmpty() && bytes.size <= MAX_ADDRESS_BYTES) {
            "Gateway address field is too long"
        }
        writeShort(bytes.size)
        write(bytes)
    }

    companion object {
        internal const val WIREGUARD_KEY_SIZE = 32
        internal const val SESSION_ID_SIZE = 16
        internal const val MAX_ADDRESS_BYTES = 512
        internal const val MIN_MTU = 576
        internal const val MAX_MTU = 65535
    }
}

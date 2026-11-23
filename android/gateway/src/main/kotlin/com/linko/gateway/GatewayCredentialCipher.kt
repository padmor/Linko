package com.linko.gateway

import java.security.GeneralSecurityException
import javax.crypto.Cipher
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

internal interface GatewayKeyProvider {
    fun getOrCreateKey(): SecretKey
    fun getExistingKey(): SecretKey
    fun deleteKey()
}

/**
 * AES-256-GCM envelope encryption for the credential record.
 *
 * The header is authenticated as associated data, so format/version changes
 * and ciphertext modifications are rejected during decryption.
 */
internal class AesGcmCredentialCipher(
    private val keyProvider: GatewayKeyProvider
) {
    fun encrypt(plaintext: ByteArray): ByteArray {
        if (plaintext.isEmpty() || plaintext.size > GatewayCredentialCodec.MAX_PLAINTEXT_BYTES) {
            throw GatewayCredentialException("Gateway credential payload has an invalid size")
        }

        var nonce: ByteArray? = null
        var ciphertext: ByteArray? = null

        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(Cipher.ENCRYPT_MODE, keyProvider.getOrCreateKey())
            nonce = cipher.iv
                ?: throw GatewayCredentialException("Android Keystore did not provide an encryption nonce")

            if (nonce.size != NONCE_SIZE_BYTES) {
                throw GatewayCredentialException("Android Keystore returned an unsupported nonce size")
            }

            cipher.updateAAD(HEADER)
            ciphertext = cipher.doFinal(plaintext)

            return ByteArray(HEADER.size + nonce.size + ciphertext.size).also { envelope ->
                HEADER.copyInto(envelope, destinationOffset = 0)
                nonce.copyInto(envelope, destinationOffset = HEADER.size)
                ciphertext.copyInto(envelope, destinationOffset = HEADER.size + nonce.size)
            }
        } catch (error: GatewayCredentialException) {
            throw error
        } catch (error: Exception) {
            throw GatewayCredentialException("Could not encrypt gateway credentials", error)
        } finally {
            nonce?.fill(0)
            ciphertext?.fill(0)
        }
    }

    fun decrypt(envelope: ByteArray): ByteArray {
        val minimumSize = HEADER.size + NONCE_SIZE_BYTES + GCM_TAG_SIZE_BYTES
        if (envelope.size < minimumSize || envelope.size > MAX_ENVELOPE_BYTES) {
            throw GatewayCredentialException("Stored gateway credential envelope has an invalid size")
        }

        for (index in HEADER.indices) {
            if (envelope[index] != HEADER[index]) {
                throw GatewayCredentialException("Stored gateway credentials have an unsupported format")
            }
        }

        val nonce = envelope.copyOfRange(HEADER.size, HEADER.size + NONCE_SIZE_BYTES)
        val ciphertext = envelope.copyOfRange(HEADER.size + NONCE_SIZE_BYTES, envelope.size)

        try {
            val cipher = Cipher.getInstance(TRANSFORMATION)
            cipher.init(
                Cipher.DECRYPT_MODE,
                keyProvider.getExistingKey(),
                GCMParameterSpec(GCM_TAG_SIZE_BYTES * 8, nonce)
            )
            cipher.updateAAD(HEADER)
            return cipher.doFinal(ciphertext)
        } catch (error: GatewayCredentialException) {
            throw error
        } catch (error: GeneralSecurityException) {
            throw GatewayCredentialException(
                "Stored gateway credentials could not be authenticated; pair the devices again",
                error
            )
        } catch (error: Exception) {
            throw GatewayCredentialException(
                "Could not decrypt gateway credentials; pair the devices again",
                error
            )
        } finally {
            nonce.fill(0)
            ciphertext.fill(0)
        }
    }

    companion object {
        private val HEADER = byteArrayOf(0x4c, 0x4b, 0x43, 0x52, 0x01)
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val NONCE_SIZE_BYTES = 12
        private const val GCM_TAG_SIZE_BYTES = 16
        private val MAX_ENVELOPE_BYTES =
            GatewayCredentialCodec.MAX_PLAINTEXT_BYTES + HEADER.size +
                NONCE_SIZE_BYTES + GCM_TAG_SIZE_BYTES

        internal fun headerForTest(): ByteArray = HEADER.copyOf()
    }
}

/** A safe, non-secret error for gateway credential storage operations. */
class GatewayCredentialException(
    message: String,
    cause: Throwable? = null
) : IllegalStateException(message, cause)

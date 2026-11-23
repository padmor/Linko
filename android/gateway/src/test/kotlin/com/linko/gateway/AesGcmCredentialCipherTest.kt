package com.linko.gateway

import java.util.Arrays
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AesGcmCredentialCipherTest {
    @Test
    fun encryptsAndDecryptsPayloadWithFreshNonce() {
        val provider = TestKeyProvider(key(1))
        val cipher = AesGcmCredentialCipher(provider)
        val plaintext = "linko credential test".toByteArray()

        val first = cipher.encrypt(plaintext)
        val second = cipher.encrypt(plaintext)

        assertNotEquals(first.toList(), second.toList())
        assertArrayEquals(plaintext, cipher.decrypt(first))
        assertArrayEquals(plaintext, cipher.decrypt(second))

        first.fill(0)
        second.fill(0)
        plaintext.fill(0)
    }

    @Test
    fun rejectsModifiedCiphertext() {
        val cipher = AesGcmCredentialCipher(TestKeyProvider(key(2)))
        val plaintext = "authenticated data".toByteArray()
        val encrypted = cipher.encrypt(plaintext)
        encrypted[encrypted.lastIndex] = (encrypted.last().toInt() xor 1).toByte()

        try {
            cipher.decrypt(encrypted)
            throw AssertionError("Expected modified ciphertext to fail")
        } catch (error: GatewayCredentialException) {
            assertTrue(error.message!!.contains("authenticated"))
        } finally {
            plaintext.fill(0)
            encrypted.fill(0)
        }
    }

    @Test
    fun rejectsAnEnvelopeEncryptedWithAnotherKey() {
        val plaintext = "private session material".toByteArray()
        val encrypted = AesGcmCredentialCipher(TestKeyProvider(key(3))).encrypt(plaintext)

        try {
            AesGcmCredentialCipher(TestKeyProvider(key(4))).decrypt(encrypted)
            throw AssertionError("Expected a different key to fail")
        } catch (error: GatewayCredentialException) {
            assertTrue(error.message!!.contains("authenticated"))
        } finally {
            plaintext.fill(0)
            encrypted.fill(0)
        }
    }

    @Test
    fun rejectsTruncatedEnvelopeAndChangedHeader() {
        val cipher = AesGcmCredentialCipher(TestKeyProvider(key(5)))
        val encrypted = cipher.encrypt(byteArrayOf(1, 2, 3))

        try {
            cipher.decrypt(encrypted.copyOf(8))
            throw AssertionError("Expected truncated envelope to fail")
        } catch (error: GatewayCredentialException) {
            assertTrue(error.message!!.contains("invalid size"))
        }

        encrypted[0] = 0
        try {
            cipher.decrypt(encrypted)
            throw AssertionError("Expected modified header to fail")
        } catch (error: GatewayCredentialException) {
            assertTrue(error.message!!.contains("unsupported format"))
        } finally {
            encrypted.fill(0)
        }
    }

    private fun key(seed: Int): SecretKey {
        return SecretKeySpec(ByteArray(32) { (it + seed).toByte() }, "AES")
    }

    private class TestKeyProvider(private val key: SecretKey) : GatewayKeyProvider {
        override fun getOrCreateKey(): SecretKey = key
        override fun getExistingKey(): SecretKey = key
        override fun deleteKey() = Unit
    }
}

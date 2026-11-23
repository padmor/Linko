package com.linko.gateway

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyProperties
import java.security.KeyStore
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey

/**
 * Creates and retrieves a non-exportable AES key in Android Keystore.
 */
internal class AndroidKeystoreKeyProvider : GatewayKeyProvider {
    @Synchronized
    override fun getOrCreateKey(): SecretKey {
        val keyStore = loadKeyStore()
        val existingKey = keyStore.getKey(KEY_ALIAS, null) as? SecretKey
        if (existingKey != null) {
            if (existingKey.algorithm != KeyProperties.KEY_ALGORITHM_AES) {
                throw GatewayCredentialException("Stored gateway encryption key is invalid")
            }
            return existingKey
        }

        val generator = KeyGenerator.getInstance(
            KeyProperties.KEY_ALGORITHM_AES,
            ANDROID_KEYSTORE
        )
        generator.init(
            KeyGenParameterSpec.Builder(
                KEY_ALIAS,
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT
            )
                .setKeySize(KEY_SIZE_BITS)
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setRandomizedEncryptionRequired(true)
                .build()
        )

        return generator.generateKey()
    }

    @Synchronized
    override fun getExistingKey(): SecretKey {
        val key = loadKeyStore().getKey(KEY_ALIAS, null) as? SecretKey
            ?: throw GatewayCredentialException(
                "Gateway encryption key is missing; pair the devices again"
            )

        if (key.algorithm != KeyProperties.KEY_ALGORITHM_AES) {
            throw GatewayCredentialException("Stored gateway encryption key is invalid")
        }
        return key
    }

    @Synchronized
    override fun deleteKey() {
        val keyStore = loadKeyStore()
        if (keyStore.containsAlias(KEY_ALIAS)) {
            keyStore.deleteEntry(KEY_ALIAS)
        }
    }

    private fun loadKeyStore(): KeyStore {
        return try {
            KeyStore.getInstance(ANDROID_KEYSTORE).apply { load(null) }
        } catch (error: Exception) {
            throw GatewayCredentialException("Android Keystore is unavailable", error)
        }
    }

    private companion object {
        const val ANDROID_KEYSTORE = "AndroidKeyStore"
        const val KEY_ALIAS = "com.linko.gateway.credentials.aes.v1"
        const val KEY_SIZE_BITS = 256
    }
}

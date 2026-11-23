package com.linko.gateway

import android.content.Context
import android.util.AtomicFile
import java.io.File
import java.io.FileNotFoundException
import java.io.FileInputStream
import java.io.FileOutputStream

/**
 * Stores one Phone A session's credentials encrypted at rest.
 *
 * The encrypted file is placed in noBackupFilesDir. Android Keystore holds the
 * AES key; the key itself is never written to the credential file.
 */
class GatewayCredentialStore(context: Context) {
    private val credentialFile: AtomicFile
    private val cipher = AesGcmCredentialCipher(AndroidKeystoreKeyProvider())

    init {
        val directory = File(context.applicationContext.noBackupFilesDir, DIRECTORY_NAME)
        if (!directory.exists() && !directory.mkdirs()) {
            throw GatewayCredentialException("Could not create private gateway storage")
        }
        credentialFile = AtomicFile(File(directory, FILE_NAME))
    }

    /**
     * Encrypts and atomically saves the complete approved-session config.
     * The supplied credentials remain owned by the caller.
     */
    fun save(credentials: GatewaySessionCredentials) {
        synchronized(STORE_LOCK) {
            val plaintext = GatewayCredentialCodec.encode(credentials)
            val encrypted = try {
                cipher.encrypt(plaintext)
            } finally {
                plaintext.fill(0)
            }

            var output: FileOutputStream? = null
            try {
                output = credentialFile.startWrite()
                output.write(encrypted)
                credentialFile.finishWrite(output)
                output = null
            } catch (error: Exception) {
                output?.let { stream ->
                    runCatching { credentialFile.failWrite(stream) }
                }
                throw GatewayCredentialException("Could not save gateway credentials", error)
            } finally {
                encrypted.fill(0)
            }
        }
    }

    /**
     * Opens credentials only for this synchronous callback. The credential
     * object and its temporary key/session buffers are cleared on return.
     *
     * Returns false when no credential record exists. Invalid, modified, or
     * undecryptable records throw [GatewayCredentialException] and never
     * trigger automatic key regeneration or an unapproved session restart.
     */
    fun withCredentials(consumer: (GatewaySessionCredentials) -> Unit): Boolean {
        synchronized(STORE_LOCK) {
            val encrypted = try {
                credentialFile.openRead().use(::readBounded)
            } catch (_: FileNotFoundException) {
                return false
            } catch (error: Exception) {
                throw GatewayCredentialException("Could not read gateway credentials", error)
            }

            val plaintext = try {
                cipher.decrypt(encrypted)
            } finally {
                encrypted.fill(0)
            }

            val credentials = try {
                GatewayCredentialCodec.decode(plaintext)
            } finally {
                plaintext.fill(0)
            }

            try {
                consumer(credentials)
            } finally {
                credentials.close()
            }
            return true
        }
    }

    /** Removes the encrypted record and its Keystore key, for session revocation. */
    fun delete() {
        synchronized(STORE_LOCK) {
            credentialFile.delete()
            try {
                AndroidKeystoreKeyProvider().deleteKey()
            } catch (error: Exception) {
                throw GatewayCredentialException("Could not remove gateway encryption key", error)
            }
        }
    }

    fun hasStoredCredentials(): Boolean {
        synchronized(STORE_LOCK) {
            return credentialFile.baseFile.exists()
        }
    }

    private fun readBounded(input: FileInputStream): ByteArray {
        val buffer = ByteArray(MAX_ENVELOPE_BYTES + 1)
        var total = 0

        try {
            while (total < buffer.size) {
                val count = input.read(buffer, total, buffer.size - total)
                if (count < 0) break
                if (count == 0) continue
                total += count
            }

            if (total > MAX_ENVELOPE_BYTES) {
                throw GatewayCredentialException("Stored gateway credential file is too large")
            }
            return buffer.copyOf(total)
        } finally {
            buffer.fill(0)
        }
    }

    private companion object {
        const val DIRECTORY_NAME = "linko"
        const val FILE_NAME = "gateway-credentials.bin"
        const val MAX_ENVELOPE_BYTES =
            GatewayCredentialCodec.MAX_PLAINTEXT_BYTES + 5 + 12 + 16
        val STORE_LOCK = Any()
    }
}

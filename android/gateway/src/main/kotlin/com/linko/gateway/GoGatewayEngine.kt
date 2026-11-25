package com.linko.gateway

import android.content.Context
import com.linko.mobile.Mobile
import com.linko.mobile.PhoneAGateway

/**
 * Runs the shared Go Phone A endpoint using one already-approved session.
 *
 * Credentials are read only from GatewayCredentialStore. They are never
 * accepted from Android intents or copied into long-lived Kotlin fields.
 */
class GoGatewayEngine(context: Context) : GatewayEngine {
    private val credentialStore = GatewayCredentialStore(context.applicationContext)

    // Owned and accessed through synchronized lifecycle methods.
    private var endpoint: PhoneAGateway? = null

    @Synchronized
    override fun start() {
        check(endpoint == null) { "The Go gateway is already running" }

        var candidate: PhoneAGateway? = null
        try {
            val credentialsFound = credentialStore.withCredentials { credentials ->
                credentials.useWireGuardConfig {
                        privateKey,
                        peerPublicKey,
                        sessionId,
                        relayAddress,
                        localAddress,
                        peerAddress,
                        mtu ->
                    candidate = Mobile.newPhoneAGateway(
                        privateKey,
                        peerPublicKey,
                        sessionId,
                        relayAddress,
                        localAddress,
                        peerAddress,
                        mtu
                    )
                }
            }

            check(credentialsFound) {
                "No approved Phone A session credentials are stored"
            }
            endpoint = checkNotNull(candidate) {
                "The Go gateway did not return a running endpoint"
            }
        } catch (error: Exception) {
            runCatching { candidate?.close() }
            throw error
        }
    }

    @Synchronized
    override fun stop() {
        val current = endpoint ?: return
        endpoint = null
        current.close()
    }
}

/** Default factory used by GatewayService unless a test factory is installed. */
class GoGatewayEngineFactory : GatewayEngineFactory {
    override fun create(applicationContext: Context): GatewayEngine {
        return GoGatewayEngine(applicationContext)
    }
}

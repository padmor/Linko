package com.linko.gateway

import android.content.Context

/**
 * Platform-neutral lifecycle boundary for the Phone A Go gateway.
 *
 * The Android service owns this instance. The implementation that creates the
 * Go mobile binding will be installed by the app after secure session material
 * is available.
 */
interface GatewayEngine {
    @Throws(Exception::class)
    fun start()

    /**
     * Stops the gateway and releases its resources. Implementations must be
     * safe to call more than once.
     */
    fun stop()
}

/**
 * Creates an engine for an already approved session.
 *
 * The factory must obtain secrets from the secure session layer rather than
 * accepting private keys or session secrets through Android service intents.
 */
fun interface GatewayEngineFactory {
    fun create(applicationContext: Context): GatewayEngine
}

/**
 * App-level registration point for the Android-to-Go gateway adapter.
 */
object GatewayEngineRegistry {
    @Volatile
    private var factory: GatewayEngineFactory? = null

    @Synchronized
    fun install(factory: GatewayEngineFactory) {
        check(this.factory == null) {
            "The Linko gateway engine factory is already installed"
        }
        this.factory = factory
    }

    internal fun create(context: Context): GatewayEngine {
        val installedFactory = checkNotNull(factory) {
            "The Linko gateway engine has not been configured"
        }
        return installedFactory.create(context.applicationContext)
    }
}

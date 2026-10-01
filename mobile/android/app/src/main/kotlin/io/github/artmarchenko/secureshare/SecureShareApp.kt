package io.github.artmarchenko.secureshare

import android.app.Application
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.embedding.engine.FlutterEngineCache
import io.flutter.embedding.engine.dart.DartExecutor

/**
 * Owns the Flutter engine for the whole process (not the activity), so a
 * transfer keeps running when the user swipes the app away: the foreground
 * service keeps the process alive and Dart keeps going.
 */
class SecureShareApp : Application() {
    lateinit var bridge: NativeBridge
        private set

    override fun onCreate() {
        super.onCreate()
        val engine = FlutterEngine(this)
        bridge = NativeBridge(this, engine.dartExecutor.binaryMessenger)
        engine.dartExecutor.executeDartEntrypoint(DartExecutor.DartEntrypoint.createDefault())
        FlutterEngineCache.getInstance().put(ENGINE_ID, engine)
    }

    companion object {
        const val ENGINE_ID = "main"
    }
}

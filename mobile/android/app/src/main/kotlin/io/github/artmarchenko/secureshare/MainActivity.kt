package io.github.artmarchenko.secureshare

import android.content.Intent
import android.os.Bundle
import io.flutter.embedding.android.FlutterActivity

/** Attaches to the process-wide engine (see SecureShareApp) instead of owning one. */
class MainActivity : FlutterActivity() {
    private val bridge get() = (application as SecureShareApp).bridge

    override fun getCachedEngineId() = SecureShareApp.ENGINE_ID

    override fun shouldDestroyEngineWithHost() = false

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        bridge.attach(this)
        // a share from another app; ignore it when the activity is restored from history
        if (savedInstanceState == null) bridge.onIntent(intent)
    }

    override fun onNewIntent(intent: Intent) {
        super.onNewIntent(intent)
        setIntent(intent)
        bridge.onIntent(intent)
    }

    override fun onDestroy() {
        bridge.detach(this)
        super.onDestroy()
    }

    @Deprecated("Activity result API is not available to FlutterActivity")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        bridge.onActivityResult(requestCode, resultCode, data)
    }

    override fun onRequestPermissionsResult(requestCode: Int, permissions: Array<out String>, grantResults: IntArray) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        bridge.onPermissionResult(requestCode, grantResults)
    }
}

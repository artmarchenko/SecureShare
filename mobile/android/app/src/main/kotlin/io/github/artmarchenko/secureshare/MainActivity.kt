package io.github.artmarchenko.secureshare

import io.flutter.embedding.android.FlutterActivity
import io.flutter.embedding.engine.FlutterEngine
import io.flutter.plugin.common.MethodChannel
import org.bouncycastle.crypto.generators.SCrypt
import java.util.concurrent.Executors

class MainActivity : FlutterActivity() {
    private val worker = Executors.newSingleThreadExecutor()

    override fun configureFlutterEngine(flutterEngine: FlutterEngine) {
        super.configureFlutterEngine(flutterEngine)
        MethodChannel(flutterEngine.dartExecutor.binaryMessenger, "secureshare/native")
            .setMethodCallHandler { call, result ->
                when (call.method) {
                    // scrypt(password, salt, N, r, p, length) on a background thread
                    "scrypt" -> worker.execute {
                        try {
                            val key = SCrypt.generate(
                                call.argument<ByteArray>("password")!!,
                                call.argument<ByteArray>("salt")!!,
                                call.argument<Int>("n")!!,
                                call.argument<Int>("r")!!,
                                call.argument<Int>("p")!!,
                                call.argument<Int>("length")!!,
                            )
                            runOnUiThread { result.success(key) }
                        } catch (e: Exception) {
                            runOnUiThread { result.error("scrypt", e.message, null) }
                        }
                    }
                    else -> result.notImplemented()
                }
            }
    }
}

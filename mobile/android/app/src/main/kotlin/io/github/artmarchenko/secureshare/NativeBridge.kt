package io.github.artmarchenko.secureshare

import android.Manifest
import android.app.Activity
import android.content.ActivityNotFoundException
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.media.MediaScannerConnection
import android.net.Uri
import android.os.Build
import android.os.Environment
import android.os.Handler
import android.os.Looper
import android.os.ParcelFileDescriptor
import android.provider.OpenableColumns
import android.webkit.MimeTypeMap
import io.flutter.plugin.common.BinaryMessenger
import io.flutter.plugin.common.MethodCall
import io.flutter.plugin.common.MethodChannel
import org.bouncycastle.crypto.generators.SCrypt
import java.io.File
import java.io.FileInputStream
import java.nio.ByteBuffer
import java.nio.channels.FileChannel
import java.security.MessageDigest
import java.util.concurrent.Executors

/**
 * Everything the Dart side needs from Android, on channel "secureshare/native"
 * (see lib/app/device.dart for the other end).
 *
 * Files picked by the user (or shared from another app) are opened once and
 * kept open here; Dart reads them by handle with positional reads (Android
 * does not let Dart reopen a content URI's descriptor by path). Providers
 * that only stream (some cloud apps) are copied to the cache first, since
 * resume and retransmit need random access.
 */
class NativeBridge(private val context: Context, messenger: BinaryMessenger) {
    private val channel = MethodChannel(messenger, "secureshare/native")
    private val worker = Executors.newSingleThreadExecutor()
    private val reader = Executors.newSingleThreadExecutor()
    private val main = Handler(Looper.getMainLooper())
    private var activity: Activity? = null
    private var pendingPick: MethodChannel.Result? = null
    private var pendingPermission: MethodChannel.Result? = null
    private var sharedFile: Map<String, Any?>? = null
    private class OpenFile(val pfd: ParcelFileDescriptor, val channel: FileChannel, val cacheCopy: File?)
    private val openFiles = mutableMapOf<Int, OpenFile>()
    private var nextHandle = 1

    init {
        channel.setMethodCallHandler(::onCall)
        TransferService.onCancel = { main.post { channel.invokeMethod("cancelRequested", null) } }
    }

    fun attach(a: Activity) {
        activity = a
    }

    fun detach(a: Activity) {
        if (activity === a) activity = null
    }

    fun onIntent(intent: Intent?) {
        if (intent?.action != Intent.ACTION_SEND) return
        @Suppress("DEPRECATION")
        val uri = (if (Build.VERSION.SDK_INT >= 33) intent.getParcelableExtra(Intent.EXTRA_STREAM, Uri::class.java)
                   else intent.getParcelableExtra(Intent.EXTRA_STREAM)) ?: return
        intent.action = null // handled; don't pick it up again after a configuration change
        worker.execute {
            val file = try { openSource(uri) } catch (e: Exception) { mapOf("error" to e.toString()) }
            main.post {
                sharedFile = file
                channel.invokeMethod("sharedFile", null)
            }
        }
    }

    private fun onCall(call: MethodCall, result: MethodChannel.Result) {
        when (call.method) {
            "scrypt" -> background(result) {
                SCrypt.generate(
                    call.argument<ByteArray>("password")!!, call.argument<ByteArray>("salt")!!,
                    call.argument<Int>("n")!!, call.argument<Int>("r")!!, call.argument<Int>("p")!!,
                    call.argument<Int>("length")!!,
                )
            }
            "pickFile" -> pickFile(result)
            "takeSharedFile" -> {
                result.success(sharedFile)
                sharedFile = null
            }
            "releaseFile" -> {
                synchronized(openFiles) { openFiles.remove(call.argument<Int>("handle")) }?.let {
                    it.channel.close()
                    it.pfd.close()
                    it.cacheCopy?.delete()
                }
                result.success(null)
            }
            "readFile" -> background(result, reader) {
                val f = file(call.argument<Int>("handle")!!)
                val buf = ByteBuffer.allocate(call.argument<Int>("length")!!)
                var pos = call.argument<Number>("offset")!!.toLong()
                while (buf.hasRemaining()) {
                    val n = f.channel.read(buf, pos)
                    if (n < 0) break
                    pos += n
                }
                buf.array().copyOf(buf.position())
            }
            "hashFile" -> background(result, reader) {
                val f = file(call.argument<Int>("handle")!!)
                val md = MessageDigest.getInstance("SHA-256")
                val buf = ByteBuffer.allocate(1 shl 20)
                var pos = 0L
                while (true) {
                    buf.clear()
                    val n = f.channel.read(buf, pos)
                    if (n < 0) break
                    md.update(buf.array(), 0, n)
                    pos += n
                }
                md.digest().joinToString("") { "%02x".format(it) }
            }
            "receiveDir" -> result.success(receiveDir().absolutePath)
            "appDir" -> result.success(context.filesDir.absolutePath)
            "needsStoragePermission" -> result.success(needsStoragePermission())
            "requestStoragePermission" ->
                if (!needsStoragePermission()) result.success(true)
                else requestPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE, result)
            "requestNotificationPermission" ->
                if (Build.VERSION.SDK_INT < 33 ||
                    context.checkSelfPermission(Manifest.permission.POST_NOTIFICATIONS) == PackageManager.PERMISSION_GRANTED)
                    result.success(true)
                else requestPermission(Manifest.permission.POST_NOTIFICATIONS, result)
            "startService" -> {
                TransferService.show(context, call.argument("title")!!, call.argument("text")!!,
                    call.argument<Int>("progress") ?: -1, call.argument("cancelLabel")!!,
                    call.argument<Boolean>("upload") ?: true, start = true)
                result.success(null)
            }
            "updateService" -> {
                TransferService.show(context, call.argument("title")!!, call.argument("text")!!,
                    call.argument<Int>("progress") ?: -1, call.argument("cancelLabel")!!,
                    call.argument<Boolean>("upload") ?: true, start = false)
                result.success(null)
            }
            "stopService" -> {
                TransferService.stop(context)
                result.success(null)
            }
            "openFile" -> openFile(call.argument("path")!!, result)
            "shareText" -> {
                val send = Intent(Intent.ACTION_SEND).setType("text/plain")
                    .putExtra(Intent.EXTRA_TEXT, call.argument<String>("text"))
                startActivity(Intent.createChooser(send, null), result)
            }
            "openUrl" -> startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(call.argument("url"))), result)
            else -> result.notImplemented()
        }
    }

    private fun file(handle: Int) =
        synchronized(openFiles) { openFiles[handle] } ?: throw IllegalStateException("file is closed")

    private fun background(result: MethodChannel.Result, executor: java.util.concurrent.Executor = worker, work: () -> Any?) {
        executor.execute {
            try {
                val value = work()
                main.post { result.success(value) }
            } catch (e: Exception) {
                main.post { result.error("native", e.message, null) }
            }
        }
    }

    // ── Files ────────────────────────────────────────────────────────

    private fun pickFile(result: MethodChannel.Result) {
        val a = activity ?: return result.error("no_activity", "app is not in the foreground", null)
        pendingPick?.success(null)
        pendingPick = result
        val intent = Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE).setType("*/*")
        @Suppress("DEPRECATION")
        a.startActivityForResult(intent, REQUEST_PICK)
    }

    fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        if (requestCode != REQUEST_PICK) return
        val result = pendingPick ?: return
        pendingPick = null
        val uri = data?.data
        if (resultCode != Activity.RESULT_OK || uri == null) return result.success(null)
        background(result) { openSource(uri) }
    }

    /** {handle, name, size} for a content URI, opened for positional reads. */
    private fun openSource(uri: Uri): Map<String, Any?> {
        var name: String? = null
        var size = -1L
        context.contentResolver.query(uri, arrayOf(OpenableColumns.DISPLAY_NAME, OpenableColumns.SIZE), null, null, null)
            ?.use { c ->
                if (c.moveToFirst()) {
                    name = c.getString(0)
                    if (!c.isNull(1)) size = c.getLong(1)
                }
            }
        var pfd = context.contentResolver.openFileDescriptor(uri, "r") ?: throw IllegalStateException("cannot open $uri")
        var copy: File? = null
        if (pfd.statSize < 0) {
            // a pipe: copy it once so it can be read at any offset
            pfd.close()
            val dir = File(context.cacheDir, "outgoing").apply { mkdirs() }
            copy = File.createTempFile("send-", ".tmp", dir)
            context.contentResolver.openInputStream(uri)!!.use { input -> copy.outputStream().use { input.copyTo(it) } }
            pfd = ParcelFileDescriptor.open(copy, ParcelFileDescriptor.MODE_READ_ONLY)
        }
        size = pfd.statSize
        val channel = FileInputStream(pfd.fileDescriptor).channel
        val handle = synchronized(openFiles) { nextHandle++.also { openFiles[it] = OpenFile(pfd, channel, copy) } }
        return mapOf("handle" to handle, "name" to (name ?: uri.lastPathSegment ?: "file"), "size" to size)
    }

    /** Download/SecureShare — readable by the user in the Files app. */
    private fun receiveDir(): File {
        @Suppress("DEPRECATION")
        val dir = File(Environment.getExternalStoragePublicDirectory(Environment.DIRECTORY_DOWNLOADS), "SecureShare")
        dir.mkdirs()
        return dir
    }

    /** Android 10 and older need the storage permission to write to Download/. */
    private fun needsStoragePermission() = Build.VERSION.SDK_INT <= 29 &&
        context.checkSelfPermission(Manifest.permission.WRITE_EXTERNAL_STORAGE) != PackageManager.PERMISSION_GRANTED

    private fun openFile(path: String, result: MethodChannel.Result) {
        val ext = path.substringAfterLast('.', "").lowercase()
        val mime = MimeTypeMap.getSingleton().getMimeTypeFromExtension(ext) ?: "*/*"
        MediaScannerConnection.scanFile(context, arrayOf(path), arrayOf(mime)) { _, uri ->
            main.post {
                if (uri == null) return@post result.success(false)
                val view = Intent(Intent.ACTION_VIEW).setDataAndType(uri, mime)
                    .addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION)
                startActivity(Intent.createChooser(view, null), result)
            }
        }
    }

    private fun startActivity(intent: Intent, result: MethodChannel.Result) {
        val a = activity
        try {
            if (a != null) a.startActivity(intent)
            else context.startActivity(intent.addFlags(Intent.FLAG_ACTIVITY_NEW_TASK))
            result.success(true)
        } catch (e: ActivityNotFoundException) {
            result.success(false)
        }
    }

    // ── Permissions ──────────────────────────────────────────────────

    private fun requestPermission(permission: String, result: MethodChannel.Result) {
        val a = activity ?: return result.success(false)
        pendingPermission?.success(false)
        pendingPermission = result
        a.requestPermissions(arrayOf(permission), REQUEST_PERMISSION)
    }

    fun onPermissionResult(requestCode: Int, grantResults: IntArray) {
        if (requestCode != REQUEST_PERMISSION) return
        pendingPermission?.success(grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED)
        pendingPermission = null
    }

    companion object {
        private const val REQUEST_PICK = 4101
        private const val REQUEST_PERMISSION = 4102
    }
}

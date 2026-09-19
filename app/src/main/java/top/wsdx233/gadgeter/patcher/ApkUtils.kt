package top.wsdx233.gadgeter.patcher

import net.dongliu.apk.parser.ApkFile
import java.io.File
import java.util.zip.ZipEntry
import java.util.zip.ZipFile
import java.util.zip.ZipOutputStream
import java.io.FileOutputStream
import java.io.InputStream
import java.io.FileInputStream
import java.security.MessageDigest

object ApkUtils {
    interface ProgressListener {
        fun onProgress(msg: String, fraction: Float)
    }

    fun unzip(zipFilePath: File, destDirectory: File, listener: ProgressListener) {
        if (!destDirectory.exists()) {
            destDirectory.mkdirs()
        }
        ZipFile(zipFilePath).use { zip ->
            val entries = zip.entries()
            var count = 0
            val total = zip.size()
            while (entries.hasMoreElements()) {
                val entry = entries.nextElement()
                val entryDestination = File(destDirectory, entry.name)
                if (entry.isDirectory) {
                    entryDestination.mkdirs()
                } else {
                    entryDestination.parentFile?.mkdirs()
                    zip.getInputStream(entry).use { input ->
                        entryDestination.outputStream().use { output ->
                            input.copyTo(output)
                        }
                    }
                }
                count++
                if (count % 100 == 0) {
                    listener.onProgress("Unpacking... $count / $total", count.toFloat() / total.toFloat())
                }
            }
            listener.onProgress("Unpacking complete", 1.0f)
        }
    }

    fun zip(sourceDirectory: File, zipFilePath: File, listener: ProgressListener) {
        val files = sourceDirectory.walkTopDown().filter { it.isFile }.toList()
        val total = files.size
        var count = 0
        ZipOutputStream(FileOutputStream(zipFilePath)).use { zipOut ->
            for (file in files) {
                // 确保STORED for uncompressed files like .so, .png, resources.arsc maybe?
                // For simplicity we will just DEFLATE all, but V2 signature and zipalign might require certain things.
                // It's safer to just DEFLATE everything except some pre-compressed.
                val name = file.toRelativeString(sourceDirectory).replace("\\", "/")
                val entry = ZipEntry(name)
                
                // 特殊处理resources.arsc和已压缩的媒体文件
                if (name == "resources.arsc" || name.endsWith(".png") || name.endsWith(".jpg") || name.endsWith(".jpeg") || 
                    name.endsWith(".webp") || name.endsWith(".gif") || name.endsWith(".bmp")) {
                    entry.method = ZipEntry.STORED
                    entry.size = file.length()
                    entry.compressedSize = file.length()
                    val crc = java.util.zip.CRC32()
                    file.inputStream().use { input ->
                        val buffer = ByteArray(8192) // 8KB 的缓冲区
                        var bytesRead: Int
                        while (input.read(buffer).also { bytesRead = it } != -1) {
                            crc.update(buffer, 0, bytesRead) // 分块更新 CRC
                        }
                        entry.crc = crc.value
                    }
                }

                zipOut.putNextEntry(entry)
                file.inputStream().use { it.copyTo(zipOut) }
                zipOut.closeEntry()
                
                count++
                if (count % 100 == 0) {
                    listener.onProgress("Repacking... $count / $total", count.toFloat() / total.toFloat())
                }
            }
            listener.onProgress("Repacking complete", 1.0f)
        }
    }

    fun findAppConfig(apkPath: File): AppConfig {
        var applicationName: String? = null
        var mainActivityName: String? = null
        try {
            ApkFile(apkPath).use { apkFile ->
                val manifestXml = apkFile.manifestXml
                val appClassMatch = Regex("""<application[^>]*android:name="([^"]+)"""").find(manifestXml)
                applicationName = appClassMatch?.groupValues?.get(1)
                
                val activityMatch = Regex("""<activity[^>]*android:name="([^"]+)"""").find(manifestXml)
                mainActivityName = activityMatch?.groupValues?.get(1)
            }
        } catch (e: Exception) {
            throw RuntimeException("解析APK配置失败: ${e.message}", e)
        }
        return AppConfig(applicationName, mainActivityName)
    }

    fun validateApkStructure(unzippedDir: File): Boolean {
        try {
            // 检查必要的目录结构
            val requiredDirs = listOf("lib", "res", "assets", "META-INF")
            for (dir in requiredDirs) {
                val dirPath = File(unzippedDir, dir)
                if (!dirPath.exists() || !dirPath.isDirectory) {
                    throw RuntimeException("缺少必要的目录: $dir")
                }
            }

            // 检查AndroidManifest.xml
            val manifestFile = File(unzippedDir, "AndroidManifest.xml")
            if (!manifestFile.exists()) {
                throw RuntimeException("缺少AndroidManifest.xml")
            }

            // 检查resources.arsc
            val resourcesFile = File(unzippedDir, "resources.arsc")
            if (!resourcesFile.exists()) {
                throw RuntimeException("缺少resources.arsc")
            }

            // 验证resources.arsc文件
            if (!validateResourcesFile(resourcesFile)) {
                throw RuntimeException("resources.arsc文件无效")
            }

            return true
        } catch (e: Exception) {
            throw RuntimeException("APK结构验证失败: ${e.message}", e)
        }
    }

    private fun validateResourcesFile(resourcesFile: File): Boolean {
        try {
            // 检查文件大小
            if (resourcesFile.length() == 0L) {
                return false
            }

            // 检查文件头
            val header = ByteArray(8)
            resourcesFile.inputStream().use { input ->
                input.read(header)
            }

            // resources.arsc文件头应该以"arsc"开头
            val expectedHeader = byteArrayOf(0x61, 0x72, 0x73, 0x63, 0x00, 0x00, 0x00, 0x00)
            for (i in 0 until 4) {
                if (header[i] != expectedHeader[i]) {
                    return false
                }
            }

            return true
        } catch (e: Exception) {
            return false
        }
    }

    fun calculateFileHash(file: File, algorithm: String = "SHA-256"): String {
        try {
            val digest = MessageDigest.getInstance(algorithm)
            file.inputStream().use { input ->
                val buffer = ByteArray(8192)
                var bytesRead: Int
                while (input.read(buffer).also { bytesRead = it } != -1) {
                    digest.update(buffer, 0, bytesRead)
                }
            }
            val hashBytes = digest.digest()
            return hashBytes.joinToString("") { "%02x".format(it) }
        } catch (e: Exception) {
            throw RuntimeException("计算文件哈希失败: ${e.message}", e)
        }
    }

    data class AppConfig(val applicationName: String?, val mainActivityName: String?)
}
package top.wsdx233.gadgeter.patcher

import com.android.tools.smali.baksmali.Baksmali
import com.android.tools.smali.baksmali.BaksmaliOptions
import com.android.tools.smali.dexlib2.DexFileFactory
import com.android.tools.smali.dexlib2.Opcodes
import com.android.tools.smali.smali.Smali
import com.android.tools.smali.smali.SmaliOptions
import java.io.File
import java.security.MessageDigest

object GadgetInjector {

    fun disassembleDex(dexFile: File, outputDir: File): Boolean {
        try {
            // 验证DEX文件
            if (!validateDexFile(dexFile)) {
                throw RuntimeException("无效的DEX文件: ${dexFile.absolutePath}")
            }

            val dex = DexFileFactory.loadDexFile(dexFile, Opcodes.getDefault())
            val options = BaksmaliOptions()
            options.outputDirectory = outputDir.absolutePath
            options.apiLevel = 30 // Android 11
            options.useImplicitRefs = true
            options.useLocals = true
            
            Baksmali.disassembleDexFile(dex, outputDir, 4, options)
            
            // 验证反编译结果
            if (!outputDir.exists() || outputDir.listFiles()?.isEmpty() == true) {
                throw RuntimeException("反编译失败: 输出目录为空")
            }
            
            return true
        } catch (e: Exception) {
            throw RuntimeException("DEX反编译失败: ${e.message}", e)
        }
    }

    fun reassembleDex(smaliDir: File, outputDex: File): Boolean {
        try {
            // 验证Smali目录
            if (!smaliDir.exists() || smaliDir.listFiles()?.isEmpty() == true) {
                throw RuntimeException("无效的Smali目录: ${smaliDir.absolutePath}")
            }

            val options = SmaliOptions()
            options.outputDexFile = outputDex.absolutePath
            options.apiLevel = 30 // Android 11
            options.useImplicitRefs = true
            options.useLocals = true
            
            Smali.assemble(options, listOf(smaliDir.absolutePath))
            
            // 验证重新编译结果
            if (!outputDex.exists() || outputDex.length() == 0L) {
                throw RuntimeException("重新编译失败: 输出DEX文件无效")
            }
            
            // 验证重新编译的DEX文件
            if (!validateDexFile(outputDex)) {
                throw RuntimeException("重新编译的DEX文件无效")
            }
            
            return true
        } catch (e: Exception) {
            throw RuntimeException("DEX重新编译失败: ${e.message}", e)
        }
    }

    fun injectLoadLibrary(smaliFile: File, libName: String = "frida-gadget"): Boolean {
        if (!smaliFile.exists()) return false
        
        try {
            val lines = smaliFile.readLines().toMutableList()
            val originalContent = lines.joinToString("\n")
            
            // 1. 查找是否存在 <clinit> 静态代码块
            var clinitStartIdx = -1
            var clinitEndIdx = -1
            for (i in lines.indices) {
                val line = lines[i].trim()
                if (line.startsWith(".method") && line.contains("static") && line.contains("constructor <clinit>()V")) {
                    clinitStartIdx = i
                }
                if (clinitStartIdx != -1 && line.startsWith(".end method")) {
                    clinitEndIdx = i
                    break
                }
            }

            // 2. 如果不存在 <clinit>，最完美的状况！直接在文件末尾无损追加一个。
            if (clinitStartIdx == -1) {
                lines.add("")
                lines.add(".method static constructor <clinit>()V")
                lines.add("    .locals 1")
                lines.add("    const-string v0, \"$libName\"")
                lines.add("    invoke-static {v0}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")
                lines.add("    return-void")
                lines.add(".end method")
                smaliFile.writeText(lines.joinToString("\n"))
                return true
            }

            // 3. 如果存在 <clinit>，我们需要在开头无损插入
            var regIdx = -1
            var isLocals = false
            var currentRegs = 0

            // 寻找寄存器声明
            for (i in clinitStartIdx until clinitEndIdx) {
                val line = lines[i].trim()
                if (line.startsWith(".locals ")) {
                    regIdx = i
                    isLocals = true
                    currentRegs = line.substringAfter(".locals").trim().toIntOrNull() ?: 0
                    break
                } else if (line.startsWith(".registers ")) {
                    regIdx = i
                    isLocals = false
                    currentRegs = line.substringAfter(".registers").trim().toIntOrNull() ?: 0
                    break
                }
            }

            if (regIdx == -1) {
                // 极端罕见情况：有 <clinit> 但没有声明寄存器，主动加上
                regIdx = clinitStartIdx
                lines.add(regIdx + 1, "    .locals 1")
                currentRegs = 0
                isLocals = true
                regIdx++
                clinitEndIdx++
            }

            // 4. 安全策略：将寄存器数量 +1，使用新增出来的最高位寄存器！绝不污染原有的 v0, v1
            val newRegs = currentRegs + 1
            val targetReg = "v$currentRegs" // 例如原来是2 (v0, v1)，+1后变成3，我们就用新增的 v2

            // 更新寄存器数量
            lines[regIdx] = if (isLocals) "    .locals $newRegs" else "    .registers $newRegs"

            // 5. 寻找安全的插入点 (跳过 .param, .prologue, .line 等前置伪指令)
            var insertIdx = regIdx + 1
            for (i in (regIdx + 1) until clinitEndIdx) {
                val line = lines[i].trim()
                if (line.isEmpty() || line.startsWith("#") || line.startsWith(".param") || 
                    line.startsWith(".prologue") || line.startsWith(".line") || line.startsWith(".annotation")) {
                    insertIdx = i + 1
                } else {
                    break
                }
            }

            // 6. 插入注入代码
            lines.add(insertIdx, "    invoke-static {$targetReg}, Ljava/lang/System;->loadLibrary(Ljava/lang/String;)V")
            lines.add(insertIdx, "    const-string $targetReg, \"$libName\"")

            smaliFile.writeText(lines.joinToString("\n"))
            
            // 验证注入后的Smali文件
            if (!validateSmaliFile(smaliFile)) {
                throw RuntimeException("Smali文件验证失败")
            }
            
            return true
        } catch (e: Exception) {
            throw RuntimeException("注入失败: ${e.message}", e)
        }
    }

    private fun validateDexFile(dexFile: File): Boolean {
        try {
            // 检查文件大小
            if (dexFile.length() == 0L) {
                return false
            }

            // 检查文件头
            val header = ByteArray(8)
            dexFile.inputStream().use { input ->
                input.read(header)
            }

            // DEX文件头应该以"dex\n035"开头
            val expectedHeader = byteArrayOf(0x64, 0x65, 0x78, 0x0A, 0x30, 0x33, 0x35, 0x00)
            for (i in 0 until 8) {
                if (header[i] != expectedHeader[i]) {
                    return false
                }
            }

            return true
        } catch (e: Exception) {
            return false
        }
    }

    private fun validateSmaliFile(smaliFile: File): Boolean {
        try {
            val lines = smaliFile.readLines()
            if (lines.isEmpty()) {
                return false
            }

            // 检查基本的Smali语法
            var methodCount = 0
            var endMethodCount = 0
            
            for (line in lines) {
                if (line.trim().startsWith(".method")) {
                    methodCount++
                } else if (line.trim().startsWith(".end method")) {
                    endMethodCount++
                }
            }

            // 方法应该有对应的结束
            return methodCount == endMethodCount
        } catch (e: Exception) {
            return false
        }
    }
}
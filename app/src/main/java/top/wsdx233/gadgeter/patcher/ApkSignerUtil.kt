package top.wsdx233.gadgeter.patcher

import com.android.apksig.ApkSigner
import org.bouncycastle.asn1.x500.X500Name
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder
import java.io.File
import java.math.BigInteger
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.SecureRandom
import java.security.cert.X509Certificate
import java.util.Date

object ApkSignerUtil {
    fun signApk(inputApk: File, outputApk: File) {
        val (privateKey, cert) = generateKeyPairAndCertificate()
        val signerConfig = ApkSigner.SignerConfig.Builder(
            "GARGETER", privateKey, listOf(cert)
        ).build()

        val apkSigner = ApkSigner.Builder(listOf(signerConfig))
            .setInputApk(inputApk)
            .setOutputApk(outputApk)
            .setV1SigningEnabled(true)
            .setV2SigningEnabled(true)
            .setV3SigningEnabled(true)
            .setMinSdkVersion(24) // 确保兼容性
            .build()
        
        try {
            apkSigner.sign()
            // 验证签名
            validateSignature(outputApk)
        } catch (e: Exception) {
            throw RuntimeException("签名失败: ${e.message}", e)
        }
    }

    private fun generateKeyPairAndCertificate(): Pair<PrivateKey, X509Certificate> {
        val keyPairGen = KeyPairGenerator.getInstance("RSA")
        keyPairGen.initialize(2048, SecureRandom())
        val keyPair = keyPairGen.generateKeyPair()

        val issuer = X500Name("CN=Gadgeter, O=Gadgeter, C=CN")
        val serial = BigInteger.valueOf(System.currentTimeMillis())
        val notBefore = Date(System.currentTimeMillis() - 86400000L)
        val notAfter = Date(System.currentTimeMillis() + 86400000L * 365 * 10) // 10 years

        val certBuilder = JcaX509v3CertificateBuilder(
            issuer, serial, notBefore, notAfter, issuer, keyPair.public
        )
        
        // 添加基本约束
        certBuilder.addExtension(
            org.bouncycastle.asn1.x509.BasicConstraints.getInstance(),
            true,
            org.bouncycastle.asn1.x509.BasicConstraints(true)
        )
        
        // 添加密钥用法
        certBuilder.addExtension(
            org.bouncycastle.asn1.x509.KeyUsage.getInstance(),
            true,
            org.bouncycastle.asn1.x509.KeyUsage(
                org.bouncycastle.asn1.x509.KeyUsage.digitalSignature or 
                org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment or 
                org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment
            )
        )

        val signer = JcaContentSignerBuilder("SHA256WithRSAEncryption").build(keyPair.private)
        val certHolder = certBuilder.build(signer)
        val cert = JcaX509CertificateConverter().getCertificate(certHolder)

        // 验证证书
        cert.checkValidity()
        cert.verify(cert.publicKey)

        return Pair(keyPair.private, cert)
    }

    private fun validateSignature(apkFile: File) {
        try {
            val apkSigner = ApkSigner.Builder(listOf())
                .setInputApk(apkFile)
                .setV1SigningEnabled(true)
                .setV2SigningEnabled(true)
                .setV3SigningEnabled(true)
                .build()
            
            // 验证签名
            apkSigner.sign()
            
            // 检查签名是否有效
            val signatures = apkSigner.getSignerConfigs()
            if (signatures.isEmpty()) {
                throw RuntimeException("APK签名无效: 没有找到签名")
            }
            
            // 检查证书链
            for (signerConfig in signatures) {
                val certs = signerConfig.certs
                if (certs.isEmpty()) {
                    throw RuntimeException("APK签名无效: 没有证书")
                }
                
                // 验证证书链
                for (i in 0 until certs.size - 1) {
                    certs[i].verify(certs[i + 1].publicKey)
                }
            }
            
        } catch (e: Exception) {
            throw RuntimeException("签名验证失败: ${e.message}", e)
        }
    }
}
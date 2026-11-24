// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.security

import org.bouncycastle.crypto.digests.SHA256Digest
import org.bouncycastle.crypto.generators.Argon2BytesGenerator
import org.bouncycastle.crypto.generators.HKDFBytesGenerator
import org.bouncycastle.crypto.params.Argon2Parameters
import org.bouncycastle.crypto.params.HKDFParameters
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Derivación de claves del formato v3.
 *
 * - Contraseña maestra → Argon2id (RFC 9106). Por defecto, la "segunda recomendación" del RFC:
 *   64 MiB de memoria, 3 pasadas y 4 carriles. Resiste mucho mejor que PBKDF2 los ataques con
 *   GPU porque cada intento necesita esa memoria.
 * - Clave de recuperación (aleatoria, 160 bits) → HKDF-SHA256: no necesita ser lenta.
 */
object Argon2 {

    data class Params(val memoryKiB: Int = 65_536, val iterations: Int = 3, val parallelism: Int = 4) {
        init {
            require(memoryKiB in 8_192..1_048_576) { "Argon2 memory out of range" }
            require(iterations in 1..20) { "Argon2 iterations out of range" }
            require(parallelism in 1..16) { "Argon2 parallelism out of range" }
        }
    }

    fun deriveKey(password: String, salt: ByteArray, params: Params): SecretKey {
        require(password.isNotEmpty() && salt.size >= CryptoManager.MIN_SALT_LENGTH_BYTES)
        val generator = Argon2BytesGenerator()
        generator.init(
            Argon2Parameters.Builder(Argon2Parameters.ARGON2_id)
                .withVersion(Argon2Parameters.ARGON2_VERSION_13)
                .withMemoryAsKB(params.memoryKiB)
                .withIterations(params.iterations)
                .withParallelism(params.parallelism)
                .withSalt(salt)
                .build()
        )
        val out = ByteArray(32)
        val chars = password.toCharArray()
        try {
            generator.generateBytes(chars, out)
        } finally {
            chars.fill('\u0000')
        }
        return SecretKeySpec(out, "AES")
    }

    fun hkdf(ikm: ByteArray, salt: ByteArray, info: String): SecretKey {
        val gen = HKDFBytesGenerator(SHA256Digest())
        gen.init(HKDFParameters(ikm, salt, info.toByteArray(Charsets.UTF_8)))
        val out = ByteArray(32)
        gen.generateBytes(out, 0, out.size)
        return SecretKeySpec(out, "AES")
    }
}

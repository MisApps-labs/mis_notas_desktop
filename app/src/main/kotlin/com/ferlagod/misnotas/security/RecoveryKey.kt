// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.security

import java.security.SecureRandom

/**
 * Clave de recuperación: 160 bits aleatorios escritos en Base32 en 8 grupos de 4
 * (`ABCD-EFGH-…`). Sirve para entrar si se olvida la contraseña maestra. Al leerla se ignoran
 * guiones, espacios y mayúsculas, y se aceptan 0/1/8 por O/I/B.
 */
object RecoveryKey {

    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    const val BYTES = 20

    fun generate(): ByteArray = ByteArray(BYTES).also { SecureRandom().nextBytes(it) }

    fun format(bytes: ByteArray): String {
        val sb = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl 8) or (b.toInt() and 0xFF)
            bits += 8
            while (bits >= 5) {
                sb.append(ALPHABET[(buffer shr (bits - 5)) and 31])
                bits -= 5
            }
        }
        if (bits > 0) sb.append(ALPHABET[(buffer shl (5 - bits)) and 31])
        return sb.chunked(4).joinToString("-")
    }

    /** null si no es una clave válida. */
    fun parse(text: String): ByteArray? {
        val clean = text.uppercase().filter { !it.isWhitespace() && it != '-' }
            .map { when (it) { '0' -> 'O'; '1' -> 'I'; '8' -> 'B'; else -> it } }
        if (clean.size != 32) return null
        val out = ByteArray(BYTES)
        var buffer = 0
        var bits = 0
        var i = 0
        for (c in clean) {
            val v = ALPHABET.indexOf(c)
            if (v < 0) return null
            buffer = (buffer shl 5) or v
            bits += 5
            if (bits >= 8) {
                out[i++] = (buffer shr (bits - 8)).toByte()
                bits -= 8
            }
        }
        return out
    }
}

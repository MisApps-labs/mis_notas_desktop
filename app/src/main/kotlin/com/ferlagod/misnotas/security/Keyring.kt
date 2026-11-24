// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.security

import org.json.JSONObject
import java.security.SecureRandom
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * Claves de datos de la bóveda. Cada fichero v3 indica con `kid` qué clave lo cifró.
 *
 * - En una bóveda v2 solo hay una clave (la derivada de la contraseña con PBKDF2), con id [LEGACY_KID].
 * - Al pasar a v3 esa misma clave sigue siendo la actual: no hay que volver a cifrar nada.
 * - Al rotar se añade una clave nueva aleatoria, que pasa a ser la [current]; las anteriores se
 *   conservan (cifradas en el llavero) para leer ficheros que aún no se hayan reescrito.
 *
 * [vmk] es la clave maestra de la bóveda v3 (null en v2): cifra el llavero y es lo único que
 * protegen la contraseña y la clave de recuperación.
 */
class Keyring(
    val current: String,
    val keys: Map<String, SecretKey>,
    val vmk: SecretKey? = null
) {
    init {
        require(current in keys) { "Current key missing from keyring" }
    }

    val isV3: Boolean get() = vmk != null
    val currentKey: SecretKey get() = keys.getValue(current)

    fun key(kid: String?): SecretKey? = keys[kid ?: LEGACY_KID]

    /** Claves para probar en ficheros que no dicen cuál usaron (adjuntos): primero la actual. */
    fun candidates(): List<SecretKey> = listOf(currentKey) + keys.filterKeys { it != current }.values

    fun toJson(): JSONObject = JSONObject().apply {
        put("current", current)
        put("keys", JSONObject().apply { keys.forEach { (k, v) -> put(k, CryptoManager.keyToBase64(v)) } })
    }

    /** Llavero con una clave nueva como actual. */
    fun rotated(): Keyring {
        var kid: String
        do {
            kid = "k" + randomHex(6)
        } while (kid in keys)
        return Keyring(kid, keys + (kid to randomKey()), vmk)
    }

    fun withVmk(newVmk: SecretKey) = Keyring(current, keys, newVmk)

    companion object {
        /** Id de la clave de una bóveda v2 (y de los ficheros sin `kid`). */
        const val LEGACY_KID = "v2"

        private val random = SecureRandom()

        fun legacy(key: SecretKey) = Keyring(LEGACY_KID, mapOf(LEGACY_KID to key))

        fun fromJson(json: JSONObject, vmk: SecretKey?): Keyring {
            val keysJson = json.getJSONObject("keys")
            val keys = keysJson.keys().asSequence().associateWith { CryptoManager.keyFromBase64(keysJson.getString(it)) }
            return Keyring(json.getString("current"), keys, vmk)
        }

        fun randomKey(): SecretKey = SecretKeySpec(ByteArray(32).also { random.nextBytes(it) }, "AES")

        private fun randomHex(bytes: Int) = ByteArray(bytes).also { random.nextBytes(it) }.joinToString("") { "%02x".format(it) }
    }
}

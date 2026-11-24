// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.security.Argon2
import com.ferlagod.misnotas.security.CryptoManager
import com.ferlagod.misnotas.security.Keyring
import com.ferlagod.misnotas.security.RecoveryKey
import org.json.JSONObject
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec

/**
 * `keyinfo.json` del formato v3 (cifrado en sobre). Ver docs/SYNC_FORMAT.md.
 *
 * ```
 * contraseña ──Argon2id──► KEK ──┐
 * clave de recuperación ─HKDF─► RK ──┼─► VMK (aleatoria) ──► llavero { kid → clave de datos }
 * ```
 *
 * Cambiar la contraseña solo vuelve a cifrar la VMK; rotar la clave de datos solo cambia el llavero.
 */
data class KeyInfoV3(
    val kdf: Argon2.Params,
    val salt: ByteArray,
    /** VMK cifrada con la clave derivada de la contraseña (AAD `vmk:password`). */
    val passwordWrap: String,
    /** VMK cifrada con la clave de recuperación (AAD `vmk:recovery`), si se creó una. */
    val recoveryWrap: String?,
    val recoverySalt: ByteArray?,
    /** Llavero cifrado con la VMK (AAD `keyring`). */
    val keyring: String
) {
    fun toJson(): String = JSONObject().apply {
        put("format", "misnotas-keyinfo")
        put("version", VERSION)
        put("kdf", JSONObject().apply {
            put("name", KDF_NAME)
            put("version", 19)
            put("memoryKiB", kdf.memoryKiB)
            put("iterations", kdf.iterations)
            put("parallelism", kdf.parallelism)
            put("salt", CryptoManager.saltToBase64(salt))
        })
        put("password", passwordWrap)
        if (recoveryWrap != null && recoverySalt != null) {
            put("recovery", recoveryWrap)
            put("recoverySalt", CryptoManager.saltToBase64(recoverySalt))
        }
        put("keyring", keyring)
    }.toString(2)

    val hasRecovery: Boolean get() = recoveryWrap != null

    /** VMK a partir de una clave derivada de la contraseña; null si no es la correcta. */
    fun unwrapWithKek(kek: SecretKey): SecretKey? = unwrap(passwordWrap, kek, AAD_PASSWORD)

    fun unwrapWithRecovery(recovery: ByteArray): SecretKey? {
        val wrap = recoveryWrap ?: return null
        val salt = recoverySalt ?: return null
        return unwrap(wrap, recoveryKek(recovery, salt), AAD_RECOVERY)
    }

    /** Descifra el llavero; lanza excepción si [vmk] no es la de esta bóveda. */
    fun openKeyring(vmk: SecretKey): Keyring =
        Keyring.fromJson(JSONObject(CryptoManager.decrypt(keyring, vmk, AAD_KEYRING)), vmk)

    fun withPassword(password: String, vmk: SecretKey, params: Argon2.Params = Argon2.Params()): KeyInfoV3 {
        val newSalt = CryptoManager.generateSalt()
        val kek = Argon2.deriveKey(CryptoManager.canonicalPassword(password), newSalt, params)
        return copy(kdf = params, salt = newSalt, passwordWrap = wrap(vmk, kek, AAD_PASSWORD))
    }

    /** Crea (o sustituye) la clave de recuperación; devuelve la bóveda nueva y la clave para enseñarla. */
    fun withNewRecovery(vmk: SecretKey): Pair<KeyInfoV3, ByteArray> {
        val recovery = RecoveryKey.generate()
        val rSalt = CryptoManager.generateSalt()
        return copy(recoveryWrap = wrap(vmk, recoveryKek(recovery, rSalt), AAD_RECOVERY), recoverySalt = rSalt) to recovery
    }

    fun withoutRecovery() = copy(recoveryWrap = null, recoverySalt = null)

    fun withKeyring(ring: Keyring): KeyInfoV3 = copy(keyring = encryptKeyring(ring))

    override fun equals(other: Any?): Boolean = other is KeyInfoV3 && toJson() == other.toJson()
    override fun hashCode(): Int = toJson().hashCode()

    companion object {
        const val VERSION = 3
        const val KDF_NAME = "argon2id"
        private const val AAD_PASSWORD = "vmk:password"
        private const val AAD_RECOVERY = "vmk:recovery"
        private const val AAD_KEYRING = "keyring"
        private const val RECOVERY_INFO = "misnotas-recovery-v1"

        /** ¿Es [raw] un keyinfo v3? (sin validarlo del todo). */
        fun isV3(raw: String): Boolean = try {
            JSONObject(raw).optInt("version", 1) >= VERSION
        } catch (_: Exception) {
            false
        }

        fun create(password: String, ring: Keyring, params: Argon2.Params = Argon2.Params()): KeyInfoV3 {
            val vmk = ring.vmk ?: error("Keyring without VMK")
            val salt = CryptoManager.generateSalt()
            val kek = Argon2.deriveKey(CryptoManager.canonicalPassword(password), salt, params)
            return KeyInfoV3(
                kdf = params,
                salt = salt,
                passwordWrap = wrap(vmk, kek, AAD_PASSWORD),
                recoveryWrap = null,
                recoverySalt = null,
                keyring = CryptoManager.encrypt(ring.toJson().toString(), vmk, AAD_KEYRING)
            )
        }

        fun parse(raw: String): KeyInfoV3 {
            val json = JSONObject(raw)
            require(json.optString("format") == "misnotas-keyinfo") { "keyinfo.json no válido" }
            require(json.optInt("version") == VERSION) { "Versión de keyinfo no soportada; actualiza la app" }
            val kdf = json.getJSONObject("kdf")
            require(kdf.optString("name") == KDF_NAME) { "Algoritmo de derivación no soportado" }
            val salt = CryptoManager.saltFromBase64(kdf.getString("salt"))
            require(salt.size >= CryptoManager.MIN_SALT_LENGTH_BYTES) { "Salt demasiado corto" }
            val params = Argon2.Params(kdf.getInt("memoryKiB"), kdf.getInt("iterations"), kdf.getInt("parallelism"))
            val recovery = json.optString("recovery").ifBlank { null }
            return KeyInfoV3(
                kdf = params,
                salt = salt,
                passwordWrap = json.getString("password"),
                recoveryWrap = recovery,
                recoverySalt = if (recovery != null) CryptoManager.saltFromBase64(json.getString("recoverySalt")) else null,
                keyring = json.getString("keyring")
            )
        }

        fun newVmk(): SecretKey = Keyring.randomKey()

        private fun recoveryKek(recovery: ByteArray, salt: ByteArray) = Argon2.hkdf(recovery, salt, RECOVERY_INFO)

        private fun wrap(vmk: SecretKey, kek: SecretKey, aad: String) =
            CryptoManager.encrypt(CryptoManager.keyToBase64(vmk), kek, aad)

        private fun unwrap(wrap: String, kek: SecretKey, aad: String): SecretKey? = try {
            CryptoManager.keyFromBase64(CryptoManager.decrypt(wrap, kek, aad)).let { SecretKeySpec(it.encoded, "AES") }
        } catch (_: Exception) {
            null
        }
    }

    private fun encryptKeyring(ring: Keyring): String {
        val vmk = ring.vmk ?: error("Keyring without VMK")
        return CryptoManager.encrypt(ring.toJson().toString(), vmk, AAD_KEYRING)
    }
}

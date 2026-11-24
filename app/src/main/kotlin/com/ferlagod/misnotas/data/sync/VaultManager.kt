// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.platform.Log
import com.ferlagod.misnotas.data.local.pref.AuthPreferences
import com.ferlagod.misnotas.data.remote.webdav.RemoteFileMeta
import com.ferlagod.misnotas.data.remote.webdav.WebDavClient
import com.ferlagod.misnotas.data.remote.webdav.WebDavPreconditionFailedException
import com.ferlagod.misnotas.security.Argon2
import com.ferlagod.misnotas.security.CryptoManager
import com.ferlagod.misnotas.security.Keyring
import com.ferlagod.misnotas.security.RecoveryKey
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import javax.crypto.SecretKey

/**
 * Gestiona la "bóveda" cifrada: `keyinfo.json` en el servidor, verificación de la contraseña
 * maestra y las claves desbloqueadas ([Keyring]).
 *
 * Dos formatos:
 * - v2: la clave de datos se deriva de la contraseña con PBKDF2. Es el que leen la app de
 *   escritorio y la extensión actuales, y el de las cuentas nuevas.
 * - v3 (opcional, ver [upgradeToV3]): cifrado en sobre con Argon2id, clave de recuperación,
 *   cambio de contraseña y rotación de la clave de datos.
 *
 * Garantías:
 * - Nunca se acepta una clave que no se haya comprobado contra algo cifrado con la clave real.
 *   Así una contraseña equivocada no puede llegar a cifrar ni subir nada.
 * - Una contraseña correcta siempre desbloquea: se prueban sus formas Unicode equivalentes
 *   (ver [CryptoManager.passwordVariants]).
 * - Los cambios de `keyinfo.json` se suben con `If-Match`: dos dispositivos no pueden pisarse.
 */
class VaultManager(private val prefs: AuthPreferences) {

    private companion object {
        const val TAG = "VaultManager"
        /** Notas/carpetas del servidor que se intentan descifrar para validar una contraseña. */
        const val MAX_SAMPLES = 5
    }

    // ==================================================================
    // Desbloqueo
    // ==================================================================

    /**
     * Desbloquea (o crea) la bóveda remota con [masterPassword].
     *
     * - `keyinfo.json` v3: Argon2id → VMK → llavero.
     * - `keyinfo.json` v2: PBKDF2 → clave, comprobada con su verificador.
     * - Sin `keyinfo.json` pero con notas (v1.0, o fichero borrado): parámetros guardados en el
     *   dispositivo, comprobados contra esas notas.
     * - Carpeta vacía: bóveda v2 nueva (compatible con los demás clientes).
     *
     * @return el llavero y si la bóveda se acaba de crear.
     */
    suspend fun unlockRemote(client: WebDavClient, masterPassword: String): Pair<Keyring, Boolean> {
        require(masterPassword.isNotEmpty())
        val raw = client.downloadOrNull(KeyInfo.FILE_NAME)?.let { String(it, Charsets.UTF_8) }
        if (raw != null && KeyInfoV3.isV3(raw)) {
            val info = KeyInfoV3.parse(raw)
            val ring = unlockV3(info, masterPassword) ?: throw WrongMasterPasswordException()
            prefs.saveKeyInfoV3(raw)
            return ring to false
        }
        val existing = raw?.let { KeyInfo.parse(it) }
        if (existing != null) {
            val key = deriveFirstValid(masterPassword, existing.salt, listOf(existing.iterations)) { existing.verify(it) }
                ?: throw WrongMasterPasswordException()
            prefs.saveVaultParams(existing.salt, existing.iterations, existing.check)
            prefs.saveKeyInfoV3(null)
            return Keyring.legacy(key) to false
        }

        val dataFiles = client.listRemoteFiles().filter {
            (it.name.startsWith(SyncRepository.NOTE_PREFIX) || it.name.startsWith(SyncRepository.FOLDER_PREFIX)) &&
                it.name.endsWith(SyncRepository.JSON_EXT)
        }

        // Bóveda v3 cuyo keyinfo.json ha desaparecido: se restaura la copia del dispositivo.
        prefs.getKeyInfoV3()?.let { saved ->
            if (dataFiles.isNotEmpty()) {
                val info = KeyInfoV3.parse(saved)
                val ring = unlockV3(info, masterPassword) ?: throw WrongMasterPasswordException()
                try {
                    client.uploadText(KeyInfo.FILE_NAME, saved, ifNoneMatch = true)
                } catch (_: WebDavPreconditionFailedException) {
                    return unlockRemote(client, masterPassword)
                }
                return ring to false
            }
        }

        val salt: ByteArray
        val iterations: Int
        val key: SecretKey
        if (dataFiles.isEmpty()) {
            salt = CryptoManager.generateSalt()
            iterations = CryptoManager.DEFAULT_PBKDF2_ITERATIONS
            key = derive(CryptoManager.canonicalPassword(masterPassword), salt, iterations)
        } else {
            // Hay datos cifrados pero falta keyinfo.json. La clave solo se puede reconstruir con
            // el salt que este dispositivo guardó en su día.
            salt = prefs.getSalt() ?: throw VaultException(VaultException.Reason.LEGACY_NO_SALT)
            val candidates = listOf(
                prefs.getIterations(),
                CryptoManager.DEFAULT_PBKDF2_ITERATIONS,
                CryptoManager.LEGACY_PBKDF2_ITERATIONS
            ).distinct()
            val localCheck = prefs.getKeyCheck()
            val samples = loadSamples(client, dataFiles)

            var found: Pair<SecretKey, Int>? = null
            for (iter in candidates) {
                val k = deriveFirstValid(masterPassword, salt, listOf(iter)) { k ->
                    val checkOk = localCheck?.let { CryptoManager.verify(it, KeyInfo.CHECK_PLAINTEXT, k, KeyInfo.CHECK_AAD) }
                    when {
                        checkOk == false -> false
                        // Solo hay lápidas: no existe nada cifrado que pueda quedar ilegible.
                        samples.isEmpty() -> true
                        // AES-GCM autentica: si descifra una sola muestra, la clave es la correcta.
                        else -> samples.any { it(k) }
                    }
                }
                if (k != null) {
                    found = k to iter
                    break
                }
            }
            val (k, iter) = found ?: throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.MISMATCH_EXISTING)
            key = k
            iterations = iter
        }

        val info = KeyInfo.create(salt, iterations, key)
        try {
            client.uploadText(KeyInfo.FILE_NAME, info.toJson(), ifNoneMatch = true)
        } catch (_: WebDavPreconditionFailedException) {
            // Otro dispositivo creó la bóveda a la vez: usamos la suya.
            return unlockRemote(client, masterPassword)
        }
        prefs.saveVaultParams(salt, iterations, info.check)
        prefs.saveKeyInfoV3(null)
        return Keyring.legacy(key) to dataFiles.isEmpty()
    }

    /** Desbloqueo sin conexión con los parámetros guardados en el dispositivo. */
    suspend fun unlockLocal(masterPassword: String): Keyring {
        prefs.getKeyInfoV3()?.let { raw ->
            return unlockV3(KeyInfoV3.parse(raw), masterPassword) ?: throw WrongMasterPasswordException()
        }
        val salt = prefs.getSalt() ?: throw VaultException(VaultException.Reason.NO_LOCAL_DATA)
        val check = prefs.getKeyCheck()
        val key = deriveFirstValid(masterPassword, salt, listOf(prefs.getIterations())) { key ->
            check == null || CryptoManager.verify(check, KeyInfo.CHECK_PLAINTEXT, key, KeyInfo.CHECK_AAD)
        } ?: throw WrongMasterPasswordException()
        return Keyring.legacy(key)
    }

    /** true si la bóveda guardada en este dispositivo es v3. */
    fun isLocalV3(): Boolean = prefs.getKeyInfoV3() != null

    fun localHasRecovery(): Boolean =
        prefs.getKeyInfoV3()?.let { runCatching { KeyInfoV3.parse(it).hasRecovery }.getOrNull() } == true

    private suspend fun unlockV3(info: KeyInfoV3, password: String): Keyring? = withContext(Dispatchers.Default) {
        for (variant in CryptoManager.passwordVariants(password)) {
            val kek = Argon2.deriveKey(variant, info.salt, info.kdf)
            val vmk = info.unwrapWithKek(kek) ?: continue
            return@withContext info.openKeyring(vmk)
        }
        null
    }

    /**
     * Comprueba en cada sincronización que las claves locales siguen siendo las de la bóveda
     * remota y recoge los cambios de otros dispositivos (rotación de clave, cambio de contraseña).
     *
     * @return el llavero vigente (puede tener claves nuevas) y si se ha tenido que volver a crear
     *   `keyinfo.json` (el servidor puede haber perdido datos).
     */
    suspend fun verifyRemoteKey(client: WebDavClient, ring: Keyring): Pair<Keyring, Boolean> {
        val raw = client.downloadOrNull(KeyInfo.FILE_NAME)?.let { String(it, Charsets.UTF_8) }
        if (raw == null) return ring to restoreMissingKeyInfo(client, ring)

        if (KeyInfoV3.isV3(raw)) {
            val info = KeyInfoV3.parse(raw)
            val vmk = ring.vmk
                // Otro dispositivo actualizó la bóveda a v3: hace falta la contraseña una vez.
                ?: throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.VAULT_UPGRADED)
            val remoteRing = try {
                info.openKeyring(vmk)
            } catch (_: Exception) {
                throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.CHANGED_ON_SERVER)
            }
            // Un llavero remoto sin alguna de las claves conocidas sería una vuelta atrás.
            if (!remoteRing.keys.keys.containsAll(ring.keys.keys)) {
                throw VaultException(VaultException.Reason.KEYINFO_DOWNGRADED)
            }
            if (raw != prefs.getKeyInfoV3() || remoteRing.current != ring.current) {
                prefs.saveKeyInfoV3(raw)
                prefs.saveKeyring(remoteRing)
            }
            return remoteRing to false
        }

        // keyinfo v2 en el servidor pero este dispositivo ya está en v3: alguien lo ha sustituido
        // por uno antiguo. No se sigue (podría ser un intento de bajar la seguridad).
        if (ring.isV3) throw VaultException(VaultException.Reason.KEYINFO_DOWNGRADED)

        val info = KeyInfo.parse(raw)
        if (!info.verify(ring.currentKey)) {
            throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.CHANGED_ON_SERVER)
        }
        if (prefs.getKeyCheck() == null) prefs.saveVaultParams(info.salt, info.iterations, info.check)
        return ring to false
    }

    /**
     * `keyinfo.json` ha desaparecido del servidor (carpeta vaciada, restaurada…). Si este
     * dispositivo tiene una copia válida para sus claves la vuelve a subir en lugar de dejar la
     * sincronización bloqueada para siempre.
     */
    private suspend fun restoreMissingKeyInfo(client: WebDavClient, ring: Keyring): Boolean {
        val body: String = if (ring.isV3) {
            val saved = prefs.getKeyInfoV3() ?: throw VaultException(VaultException.Reason.KEYINFO_MISSING)
            val ok = runCatching { KeyInfoV3.parse(saved).openKeyring(ring.vmk!!) }.isSuccess
            if (!ok) throw VaultException(VaultException.Reason.KEYINFO_MISSING)
            saved
        } else {
            val salt = prefs.getSalt()
            val check = prefs.getKeyCheck()
            if (salt == null || check == null ||
                !CryptoManager.verify(check, KeyInfo.CHECK_PLAINTEXT, ring.currentKey, KeyInfo.CHECK_AAD)
            ) {
                throw VaultException(VaultException.Reason.KEYINFO_MISSING)
            }
            KeyInfo(salt, prefs.getIterations(), check).toJson()
        }
        return try {
            client.uploadText(KeyInfo.FILE_NAME, body, ifNoneMatch = true)
            Log.w(TAG, "keyinfo.json no estaba en el servidor; restaurado desde el dispositivo")
            true
        } catch (_: WebDavPreconditionFailedException) {
            // Otro dispositivo lo restauró a la vez.
            verifyRemoteKey(client, ring).second
        }
    }

    // ==================================================================
    // Formato v3: actualizar, contraseña, recuperación y rotación
    // ==================================================================

    /** Resultado de una operación que cambia la bóveda. [recoveryKey] solo si se ha creado una. */
    data class VaultChange(val ring: Keyring, val recoveryKey: String? = null)

    /**
     * Pasa la bóveda v2 a v3. La clave de datos actual se conserva (id [Keyring.LEGACY_KID]):
     * no hay que volver a cifrar nada. Se comprueba antes la contraseña contra el `keyinfo.json` v2.
     */
    suspend fun upgradeToV3(client: WebDavClient, ring: Keyring, masterPassword: String, withRecovery: Boolean): VaultChange {
        val etag = client.fetchEtag(KeyInfo.FILE_NAME) ?: throw VaultException(VaultException.Reason.KEYINFO_MISSING)
        val raw = client.downloadText(KeyInfo.FILE_NAME)
        if (KeyInfoV3.isV3(raw)) throw VaultException(VaultException.Reason.ALREADY_V3)
        val v2 = KeyInfo.parse(raw)
        val key = deriveFirstValid(masterPassword, v2.salt, listOf(v2.iterations)) { v2.verify(it) }
            ?: throw WrongMasterPasswordException()
        if (!CryptoManager.keyToBase64(key).contentEquals(CryptoManager.keyToBase64(ring.currentKey))) {
            throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.CHANGED_ON_SERVER)
        }
        val newRing = Keyring(Keyring.LEGACY_KID, mapOf(Keyring.LEGACY_KID to key), KeyInfoV3.newVmk())
        var info = withContext(Dispatchers.Default) { KeyInfoV3.create(masterPassword, newRing) }
        var recovery: ByteArray? = null
        if (withRecovery) info.withNewRecovery(newRing.vmk!!).let { (i, r) -> info = i; recovery = r }
        publish(client, info, etag)
        prefs.saveKeyring(newRing)
        return VaultChange(newRing, recovery?.let { RecoveryKey.format(it) })
    }

    /** Cambia la contraseña maestra (v3). Solo se vuelve a cifrar la VMK. */
    suspend fun changePassword(client: WebDavClient, ring: Keyring, oldPassword: String, newPassword: String): VaultChange {
        val (info, etag) = readV3(client)
        val checked = unlockV3(info, oldPassword) ?: throw WrongMasterPasswordException()
        val vmk = checked.vmk!!
        if (ring.vmk != null && !CryptoManager.keyToBase64(vmk).contentEquals(CryptoManager.keyToBase64(ring.vmk))) {
            throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.CHANGED_ON_SERVER)
        }
        val updated = withContext(Dispatchers.Default) { info.withPassword(newPassword, vmk) }
        publish(client, updated, etag)
        return VaultChange(checked)
    }

    /** Crea o sustituye la clave de recuperación (v3). La anterior deja de servir. */
    suspend fun createRecoveryKey(client: WebDavClient, ring: Keyring): VaultChange {
        val vmk = ring.vmk ?: throw VaultException(VaultException.Reason.NOT_V3)
        val (info, etag) = readV3(client)
        runCatching { info.openKeyring(vmk) }.getOrElse { throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.CHANGED_ON_SERVER) }
        val (updated, recovery) = info.withNewRecovery(vmk)
        publish(client, updated, etag)
        return VaultChange(ring, RecoveryKey.format(recovery))
    }

    /**
     * Entra con la clave de recuperación y pone una contraseña maestra nueva (v3).
     * Funciona en un dispositivo nuevo: solo necesita la cuenta del servidor.
     */
    suspend fun recover(client: WebDavClient, recoveryKey: String, newPassword: String): VaultChange {
        val bytes = RecoveryKey.parse(recoveryKey) ?: throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.BAD_RECOVERY_KEY)
        val (info, etag) = readV3(client)
        val vmk = info.unwrapWithRecovery(bytes) ?: throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.BAD_RECOVERY_KEY)
        val ring = info.openKeyring(vmk)
        val updated = withContext(Dispatchers.Default) { info.withPassword(newPassword, vmk) }
        publish(client, updated, etag)
        prefs.saveKeyring(ring)
        return VaultChange(ring)
    }

    /**
     * Rota la clave de datos (v3): añade una aleatoria nueva como actual. La sincronización
     * vuelve a subir después todas las notas, carpetas y adjuntos cifrados con ella.
     */
    suspend fun rotateKey(client: WebDavClient, ring: Keyring): VaultChange {
        if (!ring.isV3) throw VaultException(VaultException.Reason.NOT_V3)
        val (info, etag) = readV3(client)
        val remoteRing = runCatching { info.openKeyring(ring.vmk!!) }
            .getOrElse { throw WrongMasterPasswordException(WrongMasterPasswordException.Reason.CHANGED_ON_SERVER) }
        val rotated = remoteRing.rotated()
        publish(client, info.withKeyring(rotated), etag)
        prefs.saveKeyring(rotated)
        return VaultChange(rotated)
    }

    private suspend fun readV3(client: WebDavClient): Pair<KeyInfoV3, String> {
        val etag = client.fetchEtag(KeyInfo.FILE_NAME) ?: throw VaultException(VaultException.Reason.KEYINFO_MISSING)
        val raw = client.downloadText(KeyInfo.FILE_NAME)
        if (!KeyInfoV3.isV3(raw)) throw VaultException(VaultException.Reason.NOT_V3)
        return KeyInfoV3.parse(raw) to etag
    }

    /** Sube `keyinfo.json` solo si nadie lo ha cambiado desde que se leyó. */
    private suspend fun publish(client: WebDavClient, info: KeyInfoV3, etag: String) {
        val body = info.toJson()
        try {
            client.uploadText(KeyInfo.FILE_NAME, body, ifMatch = etag)
        } catch (_: WebDavPreconditionFailedException) {
            throw VaultException(VaultException.Reason.CONCURRENT_CHANGE)
        }
        prefs.saveKeyInfoV3(body)
    }

    // ==================================================================

    /**
     * Descarga hasta [MAX_SAMPLES] notas/carpetas con contenido (las lápidas no sirven: no
     * llevan nada cifrado con la clave) y devuelve una comprobación por cada una.
     */
    private suspend fun loadSamples(
        client: WebDavClient,
        files: List<RemoteFileMeta>
    ): List<(SecretKey) -> Boolean> {
        val samples = mutableListOf<(SecretKey) -> Boolean>()
        for (file in files.sortedByDescending { it.contentLength }) {
            if (samples.size >= MAX_SAMPLES) break
            val raw = client.downloadOrNull(file.name)?.let { String(it, Charsets.UTF_8) } ?: continue
            val isNote = file.name.startsWith(SyncRepository.NOTE_PREFIX)
            val id = if (isNote) idOf(file.name, SyncRepository.NOTE_PREFIX) else idOf(file.name, SyncRepository.FOLDER_PREFIX)
            if (RemoteCodec.isTombstone(raw)) continue
            samples += { key ->
                try {
                    val ring = Keyring.legacy(key)
                    if (isNote) RemoteCodec.decodeNote(raw, id, ring) else RemoteCodec.decodeFolder(raw, id, ring)
                    true
                } catch (_: Exception) {
                    false
                }
            }
        }
        return samples
    }

    /**
     * Prueba cada variante de la contraseña (y cada número de iteraciones) y devuelve la primera
     * clave que pasa [isValid], o null si ninguna.
     */
    private suspend fun deriveFirstValid(
        password: String,
        salt: ByteArray,
        iterations: List<Int>,
        isValid: (SecretKey) -> Boolean
    ): SecretKey? {
        for (iter in iterations) {
            for (variant in CryptoManager.passwordVariants(password)) {
                val key = derive(variant, salt, iter)
                if (isValid(key)) return key
            }
        }
        return null
    }

    private suspend fun derive(password: String, salt: ByteArray, iterations: Int): SecretKey =
        withContext(Dispatchers.Default) { CryptoManager.deriveKey(password, salt, iterations) }

    private fun idOf(fileName: String, prefix: String) =
        fileName.removePrefix(prefix).removeSuffix(SyncRepository.JSON_EXT)
}

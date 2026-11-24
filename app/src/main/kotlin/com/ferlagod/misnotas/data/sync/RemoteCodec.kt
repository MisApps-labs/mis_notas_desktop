// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.data.local.entity.FolderEntity
import com.ferlagod.misnotas.data.local.entity.NoteEntity
import com.ferlagod.misnotas.data.local.model.SyncStatus
import com.ferlagod.misnotas.security.CryptoManager
import com.ferlagod.misnotas.security.Keyring
import org.json.JSONObject
import javax.crypto.SecretKey

/** Registro remoto descodificado: o bien la entidad viva, o bien una lápida de borrado. */
sealed interface RemoteRecord<out T> {
    /**
     * Entidad viva. [legacy] es true si viene en el formato v1, cuyos metadatos (carpeta, fechas,
     * papelera…) no van cifrados ni autenticados: ver [SyncMerger.resolveLegacyNote].
     */
    data class Live<T>(val entity: T, val legacy: Boolean = false, val rev: Long = 0) : RemoteRecord<T>
    /**
     * Lápida de borrado. [verified] es true si lleva una prueba cifrada con la clave de la bóveda
     * (la generan las versiones actuales). Una lápida sin prueba puede venir de una versión
     * antigua... o del propio servidor, así que no se usa para borrar notas de forma definitiva.
     */
    data class Tombstone(val id: String, val deletedAt: Long, val verified: Boolean = false, val rev: Long = 0) : RemoteRecord<Nothing>
}

/**
 * Formato de los ficheros en Nextcloud (ver docs/SYNC_FORMAT.md).
 *
 * v2 (actual):
 * ```
 * { "format": "misnotas", "version": 2, "type": "note", "id": "<uuid>", "payload": "<base64 AES-GCM>" }
 * { "format": "misnotas", "version": 2, "type": "note", "id": "<uuid>", "deleted": true, "deletedAt": 0, "auth": "<base64 AES-GCM>" }
 * ```
 * El payload es un JSON cifrado con AAD = "<type>:<id>", así que todos los metadatos (carpeta,
 * color, fechas…) quedan ocultos al servidor y un fichero no puede hacerse pasar por otro.
 *
 * v3 (bóvedas actualizadas): como v2, más `kid` (qué clave del [Keyring] cifró el fichero),
 * `rev` (contador de versiones del fichero, para detectar vueltas atrás) y relleno del payload
 * a múltiplos de [PAD_BLOCK] bytes. Las lápidas también van cifradas:
 * ```
 * { "format": "misnotas", "version": 3, "type": "note", "id": "<uuid>", "kid": "v2", "payload": "<base64>" }
 * ```
 *
 * v1 (MisNotas 1.0, solo lectura): JSON plano con title/content/name cifrados por separado.
 */
object RemoteCodec {

    const val FORMAT = "misnotas"
    const val VERSION_V2 = 2
    const val VERSION_V3 = 3
    /** Versión más nueva que sabe leer esta app. */
    const val VERSION = VERSION_V3

    /** El payload cifrado se rellena hasta un múltiplo de este tamaño (oculta el tamaño exacto). */
    const val PAD_BLOCK = 512
    const val TYPE_NOTE = "note"
    const val TYPE_FOLDER = "folder"

    fun aad(type: String, id: String) = "$type:$id"

    // ------------------------------------------------------------------
    // Notas
    // ------------------------------------------------------------------

    fun encodeNote(note: NoteEntity, ring: Keyring, rev: Long = 0): String {
        val payload = JSONObject().apply {
            put("folderId", note.folderId ?: JSONObject.NULL)
            put("title", note.title)
            put("content", note.content)
            put("isPinned", note.isPinned)
            put("color", note.color)
            put("updatedAt", note.updatedAt)
            put("isTrashed", note.isDeleted)
        }
        return seal(TYPE_NOTE, note.id, payload, ring, rev)
    }

    fun decodeNote(raw: String, expectedId: String, ring: Keyring): RemoteRecord<NoteEntity> {
        val json = JSONObject(raw)
        val legacyKey = ring.key(Keyring.LEGACY_KID) ?: ring.currentKey
        if (!json.has("format")) return RemoteRecord.Live(decodeLegacyNote(json, expectedId, legacyKey), legacy = true)

        val id = checkEnvelope(json, TYPE_NOTE, expectedId)
        val (payload, rev) = when (val opened = open(json, TYPE_NOTE, id, ring)) {
            is Opened.Dead -> return opened.tombstone
            is Opened.Alive -> opened.payload to opened.rev
        }
        return RemoteRecord.Live(
            NoteEntity(
                id = id,
                folderId = payload.optStringOrNull("folderId"),
                title = payload.optString("title", ""),
                content = payload.optString("content", ""),
                isPinned = payload.optBoolean("isPinned", false),
                color = payload.optString("color", "DEFAULT"),
                updatedAt = payload.optLong("updatedAt", 0L),
                isDeleted = payload.optBoolean("isTrashed", false),
                syncStatus = SyncStatus.SYNCED
            ),
            rev = rev
        )
    }

    private fun decodeLegacyNote(json: JSONObject, expectedId: String, key: SecretKey): NoteEntity = NoteEntity(
        id = legacyId(json, expectedId),
        folderId = json.optStringOrNull("folderId"),
        title = CryptoManager.decrypt(json.getString("title"), key),
        content = CryptoManager.decrypt(json.getString("content"), key),
        isPinned = json.optBoolean("isPinned", false),
        color = json.optString("color", "DEFAULT"),
        updatedAt = json.optLong("updatedAt", 0L),
        isDeleted = json.optBoolean("isDeleted", false),
        syncStatus = SyncStatus.SYNCED
    )

    // ------------------------------------------------------------------
    // Carpetas
    // ------------------------------------------------------------------

    fun encodeFolder(folder: FolderEntity, ring: Keyring, rev: Long = 0): String {
        val payload = JSONObject().apply {
            put("parentId", folder.parentId ?: JSONObject.NULL)
            put("name", folder.name)
            put("color", folder.color)
            put("updatedAt", folder.updatedAt)
        }
        return seal(TYPE_FOLDER, folder.id, payload, ring, rev)
    }

    fun decodeFolder(raw: String, expectedId: String, ring: Keyring): RemoteRecord<FolderEntity> {
        val json = JSONObject(raw)
        val legacyKey = ring.key(Keyring.LEGACY_KID) ?: ring.currentKey
        if (!json.has("format")) return RemoteRecord.Live(decodeLegacyFolder(json, expectedId, legacyKey), legacy = true)

        val id = checkEnvelope(json, TYPE_FOLDER, expectedId)
        val (payload, rev) = when (val opened = open(json, TYPE_FOLDER, id, ring)) {
            is Opened.Dead -> return opened.tombstone
            is Opened.Alive -> opened.payload to opened.rev
        }
        return RemoteRecord.Live(
            FolderEntity(
                id = id,
                parentId = payload.optStringOrNull("parentId"),
                name = payload.optString("name", ""),
                color = payload.optString("color", "DEFAULT"),
                updatedAt = payload.optLong("updatedAt", 0L),
                isDeleted = false,
                syncStatus = SyncStatus.SYNCED
            ),
            rev = rev
        )
    }

    private fun decodeLegacyFolder(json: JSONObject, expectedId: String, key: SecretKey): FolderEntity = FolderEntity(
        id = legacyId(json, expectedId),
        parentId = json.optStringOrNull("parentId"),
        name = CryptoManager.decrypt(json.getString("name"), key),
        color = json.optString("color", "DEFAULT"),
        updatedAt = json.optLong("updatedAt", 0L),
        isDeleted = false,
        syncStatus = SyncStatus.SYNCED
    )

    // ------------------------------------------------------------------
    // Lápidas y adjuntos
    // ------------------------------------------------------------------

    /**
     * Lápida de borrado definitivo. Incluye `auth`: el instante del borrado cifrado con la clave
     * y AAD = "tombstone:<type>:<id>", para que el servidor no pueda fabricar borrados.
     */
    fun encodeTombstone(type: String, id: String, deletedAt: Long, ring: Keyring, rev: Long = 0): String {
        if (ring.isV3) {
            // v3: la lápida va cifrada como cualquier nota; el servidor no la distingue.
            return seal(type, id, JSONObject().put("deleted", true).put("deletedAt", deletedAt), ring, rev)
        }
        return envelope(type, id, VERSION_V2)
            .put("deleted", true)
            .put("deletedAt", deletedAt)
            .put("auth", CryptoManager.encrypt(tombstoneProof(deletedAt), ring.currentKey, tombstoneAad(type, id)))
            .toString()
    }

    /**
     * true si [raw] es una lápida legible sin clave (v2). Las lápidas v3 van cifradas y no se
     * pueden distinguir de una nota.
     */
    fun isTombstone(raw: String): Boolean = try {
        JSONObject(raw).optBoolean("deleted", false)
    } catch (_: Exception) {
        false
    }

    private fun tombstoneAad(type: String, id: String) = "tombstone:$type:$id"
    private fun tombstoneProof(deletedAt: Long) = "deleted:$deletedAt"

    fun encryptAttachment(bytes: ByteArray, id: String, ring: Keyring): ByteArray =
        CryptoManager.encryptBytes(bytes, ring.currentKey, aad("attachment", id))

    /** Los adjuntos no dicen qué clave los cifró: se prueba la actual y luego las anteriores. */
    fun decryptAttachment(bytes: ByteArray, id: String, ring: Keyring): ByteArray {
        var last: Exception? = null
        for (key in ring.candidates()) {
            try {
                return CryptoManager.decryptBytes(bytes, key, aad("attachment", id))
            } catch (e: java.security.GeneralSecurityException) {
                last = e
            }
        }
        throw last ?: javax.crypto.AEADBadTagException("No key")
    }

    // ------------------------------------------------------------------

    private fun envelope(type: String, id: String, version: Int) = JSONObject().apply {
        put("format", FORMAT)
        put("version", version)
        put("type", type)
        put("id", id)
    }

    /** Cifra [payload] en el formato que corresponde a la bóveda (v2 o v3). */
    private fun seal(type: String, id: String, payload: JSONObject, ring: Keyring, rev: Long): String {
        if (!ring.isV3) {
            return envelope(type, id, VERSION_V2)
                .put("payload", CryptoManager.encrypt(payload.toString(), ring.currentKey, aad(type, id)))
                .toString()
        }
        payload.put("rev", rev)
        return envelope(type, id, VERSION_V3)
            .put("kid", ring.current)
            .put("payload", CryptoManager.encrypt(padded(payload), ring.currentKey, aad(type, id)))
            .toString()
    }

    /** JSON con un campo `pad` de espacios para que su longitud sea múltiplo de [PAD_BLOCK]. */
    internal fun padded(payload: JSONObject): String {
        payload.remove("pad")
        val base = payload.toString().toByteArray(Charsets.UTF_8).size
        // `,"pad":""` añade 9 bytes además de los espacios.
        val overhead = 9
        val target = ((base + overhead + PAD_BLOCK - 1) / PAD_BLOCK) * PAD_BLOCK
        payload.put("pad", " ".repeat(target - base - overhead))
        return payload.toString()
    }

    private sealed interface Opened {
        class Alive(val payload: JSONObject, val rev: Long) : Opened
        class Dead(val tombstone: RemoteRecord.Tombstone) : Opened
    }

    /** Descifra un fichero v2/v3 ya validado; lápida o payload. */
    private fun open(json: JSONObject, type: String, id: String, ring: Keyring): Opened {
        if (json.optInt("version", 0) >= VERSION_V3) {
            val kid = json.optString("kid").ifBlank { null } ?: throw IllegalArgumentException("Falta kid")
            val key = ring.key(kid) ?: throw javax.crypto.AEADBadTagException("Clave $kid desconocida")
            val payload = JSONObject(CryptoManager.decrypt(json.getString("payload"), key, aad(type, id)))
            val rev = payload.optLong("rev", 0L)
            return if (payload.optBoolean("deleted", false)) {
                Opened.Dead(RemoteRecord.Tombstone(id, payload.optLong("deletedAt", 0L), verified = true, rev = rev))
            } else Opened.Alive(payload, rev)
        }
        val key = ring.key(Keyring.LEGACY_KID) ?: ring.currentKey
        tombstoneOrNull(json, type, id, key)?.let { return Opened.Dead(it) }
        return Opened.Alive(JSONObject(CryptoManager.decrypt(json.getString("payload"), key, aad(type, id))), 0L)
    }

    /**
     * El cifrado v1 no lleva AAD, así que nada ata el contenido a su fichero: al menos el id
     * declarado debe coincidir con el nombre, para que un fichero no pueda sobrescribir otra nota.
     */
    private fun legacyId(json: JSONObject, expectedId: String): String {
        val id = json.getString("id")
        require(id == expectedId) { "El id del fichero no coincide con su nombre" }
        return id
    }

    private fun checkEnvelope(json: JSONObject, type: String, expectedId: String): String {
        require(json.optString("format") == FORMAT) { "Formato desconocido" }
        require(json.optInt("version", 0) <= VERSION) {
            "Fichero creado con una versión más nueva de Mis Notas; actualiza la app"
        }
        require(json.optString("type") == type) { "Tipo inesperado" }
        val id = json.getString("id")
        require(id == expectedId) { "El id del fichero no coincide con su nombre" }
        return id
    }

    /**
     * Devuelve la lápida si [json] lo es. Si trae prueba y no es válida (falsificada o de otra
     * bóveda) lanza una excepción de cifrado y el fichero se ignora.
     */
    private fun tombstoneOrNull(json: JSONObject, type: String, id: String, key: SecretKey): RemoteRecord.Tombstone? {
        if (!json.optBoolean("deleted", false)) return null
        val deletedAt = json.optLong("deletedAt", 0L)
        val auth = json.optString("auth", "")
        if (auth.isEmpty()) return RemoteRecord.Tombstone(id, deletedAt, verified = false)
        val proof = CryptoManager.decrypt(auth, key, tombstoneAad(type, id))
        if (proof != tombstoneProof(deletedAt)) throw javax.crypto.AEADBadTagException("Lápida no válida")
        return RemoteRecord.Tombstone(id, deletedAt, verified = true)
    }

    private fun JSONObject.optStringOrNull(name: String): String? =
        if (!has(name) || isNull(name)) null else getString(name).takeIf { it.isNotBlank() }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.R
import com.ferlagod.misnotas.data.local.withTransaction
import com.ferlagod.misnotas.i18n.Strings
import com.ferlagod.misnotas.platform.Log
import java.util.Base64
import com.ferlagod.misnotas.data.attachment.AttachmentStore
import com.ferlagod.misnotas.data.backup.BackupManager
import com.ferlagod.misnotas.data.local.AppDatabase
import com.ferlagod.misnotas.data.local.entity.AttachmentEntity
import com.ferlagod.misnotas.data.local.entity.NoteEntity
import com.ferlagod.misnotas.data.local.entity.RemoteTombstoneEntity
import com.ferlagod.misnotas.data.local.model.NoteContentParser
import com.ferlagod.misnotas.data.local.model.SyncStatus
import com.ferlagod.misnotas.data.local.pref.AuthPreferences
import com.ferlagod.misnotas.data.local.pref.NextcloudCredentials
import com.ferlagod.misnotas.data.remote.webdav.RemoteFileMeta
import com.ferlagod.misnotas.data.remote.webdav.WebDavAuthException
import com.ferlagod.misnotas.data.remote.webdav.WebDavClient
import com.ferlagod.misnotas.data.remote.webdav.WebDavException
import com.ferlagod.misnotas.data.remote.webdav.WebDavPreconditionFailedException
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.withContext
import org.json.JSONException
import java.net.SocketTimeoutException
import java.net.UnknownHostException
import java.security.GeneralSecurityException
import java.util.UUID
import com.ferlagod.misnotas.security.Keyring
import javax.net.ssl.SSLException

/** Fase de una sincronización en curso; [labelRes] es la clave del texto que la describe. */
enum class SyncStage(val labelRes: String) {
    CONNECTING(R.string.sync_stage_connecting),
    DOWNLOADING(R.string.sync_stage_downloading),
    UPLOADING(R.string.sync_stage_uploading)
}

/** Estado de la sincronización que muestra la interfaz. */
sealed interface SyncState {
    /** Sin sincronizar (o sin cuenta conectada). */
    data object Idle : SyncState
    /** Sincronizando; [stage] indica la fase actual. */
    data class Syncing(val stage: SyncStage = SyncStage.CONNECTING) : SyncState
    /**
     * Sincronización terminada en [timestamp].
     *
     * @param warnings ficheros remotos que no se pudieron leer.
     * @param protectedNotes notas que el servidor quería retirar en bloque y se han conservado
     *   (ver [SyncMerger.isMassRemoval]).
     */
    data class Success(
        val timestamp: Long = System.currentTimeMillis(),
        val warnings: Int = 0,
        val protectedNotes: Int = 0,
        /** Ficheros que el servidor devolvió en una versión anterior a la conocida (bóveda v3). */
        val rollbacks: Int = 0
    ) : SyncState
    /** La última sincronización falló; [message] ya está traducido para mostrarlo. */
    data class Error(val message: String, val cause: Throwable? = null) : SyncState
}

/**
 * Sincronización bidireccional local-first con Nextcloud (WebDAV) y cifrado E2EE.
 *
 * Cada ronda:
 * 1. Comprueba credenciales y que la clave local coincide con `keyinfo.json`.
 * 2. Lista los ficheros remotos con sus ETags.
 * 3. Descarga lo que cambió en remoto y lo fusiona (ver [SyncMerger]).
 * 4. Sube adjuntos, carpetas y notas pendientes usando If-Match / If-None-Match.
 *
 * Es un singleton para que la app y la sincronización periódica compartan el mismo cerrojo.
 */
class SyncRepository private constructor() {

    private val database = AppDatabase.getInstance()
    private val folderDao = database.folderDao()
    private val noteDao = database.noteDao()
    private val attachmentDao = database.attachmentDao()
    private val tombstoneDao = database.remoteTombstoneDao()
    private val attachmentStore = AttachmentStore()

    /** Credenciales y parámetros de la bóveda. */
    val authPreferences = AuthPreferences.getInstance()
    /** Desbloqueo y verificación de la bóveda cifrada. */
    val vault = VaultManager(authPreferences)

    private val _syncState = MutableStateFlow<SyncState>(SyncState.Idle)
    /** Estado actual de la sincronización. */
    val syncState: StateFlow<SyncState> = _syncState.asStateFlow()

    /** Impide dos rondas a la vez; también protege la conexión de una cuenta. */
    private val syncMutex = Mutex()

    /**
     * Se pidió otra ronda (sincronización solicitada durante otra, o subida rechazada por un cambio remoto).
     */
    @Volatile
    private var rerunRequested = false
    /** Ficheros remotos que no se pudieron leer en esta sincronización. */
    private var warnings = 0
    /** Notas que el freno de borrados masivos ha conservado en esta sincronización. */
    private var protectedNotes = 0

    companion object {
        private const val TAG = "SyncRepository"
        /** Prefijo de los ficheros de carpeta en el servidor. */
        const val FOLDER_PREFIX = "folder_"
        /** Prefijo de los ficheros de nota en el servidor. */
        const val NOTE_PREFIX = "note_"
        /** Prefijo de los ficheros de adjunto en el servidor. */
        const val ATTACHMENT_PREFIX = "att_"
        /** Extensión de los ficheros de notas y carpetas. */
        const val JSON_EXT = ".json"
        /** Extensión de los adjuntos cifrados. */
        const val BIN_EXT = ".bin"
        /** Rondas máximas por sincronización cuando se piden repeticiones. */
        private const val MAX_ROUNDS = 3
        /** Tiempo que se conserva un adjunto sin usar antes de borrarlo (por si se deshace el cambio). */
        private const val ORPHAN_ATTACHMENT_GRACE_MS = 24L * 60 * 60 * 1000

        @Volatile
        private var INSTANCE: SyncRepository? = null

        /** Instancia única de la app. */
        fun getInstance(): SyncRepository =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: SyncRepository().also { INSTANCE = it }
            }

        /** Nombre del fichero remoto de una nota. */
        private fun noteFile(id: String) = "$NOTE_PREFIX$id$JSON_EXT"
        /** Nombre del fichero remoto de una carpeta. */
        private fun folderFile(id: String) = "$FOLDER_PREFIX$id$JSON_EXT"
        /** Nombre del fichero remoto de un adjunto. */
        private fun attachmentFile(id: String) = "$ATTACHMENT_PREFIX$id$BIN_EXT"

    }

    /** Traduce excepciones técnicas a mensajes comprensibles en el idioma de la app. */
    fun friendlyMessage(e: Throwable): String {
        val res = Strings
        return when (e) {
            is WrongMasterPasswordException -> res.get(
                when (e.reason) {
                    WrongMasterPasswordException.Reason.WRONG -> R.string.err_wrong_master
                    WrongMasterPasswordException.Reason.MISMATCH_EXISTING -> R.string.err_master_mismatch_existing
                    WrongMasterPasswordException.Reason.CHANGED_ON_SERVER -> R.string.err_master_changed
                    WrongMasterPasswordException.Reason.VAULT_UPGRADED -> R.string.err_vault_upgraded
                    WrongMasterPasswordException.Reason.BAD_RECOVERY_KEY -> R.string.err_bad_recovery
                }
            )
            is VaultException -> res.get(
                when (e.reason) {
                    VaultException.Reason.LEGACY_NO_SALT -> R.string.err_legacy_no_salt
                    VaultException.Reason.NO_LOCAL_DATA -> R.string.err_no_local_vault
                    VaultException.Reason.KEYINFO_MISSING -> R.string.err_keyinfo_missing
                    VaultException.Reason.KEYINFO_DOWNGRADED -> R.string.err_keyinfo_downgraded
                    VaultException.Reason.ALREADY_V3, VaultException.Reason.NOT_V3 -> R.string.err_keyinfo_missing
                    VaultException.Reason.CONCURRENT_CHANGE -> R.string.err_vault_concurrent
                }
            )
            is WebDavAuthException -> res.get(R.string.err_auth)
            is UnknownHostException -> res.get(R.string.err_unknown_host)
            is SocketTimeoutException -> res.get(R.string.err_timeout)
            is SSLException -> res.get(R.string.err_ssl)
            is WebDavException ->
                if (e.reason == WebDavException.Reason.PATH_NOT_FOUND) res.get(R.string.err_path_not_found)
                else res.get(R.string.err_server, e.code)
            is java.io.IOException -> res.get(
                R.string.err_network,
                e.localizedMessage ?: res.get(R.string.err_no_connection)
            )
            else -> e.localizedMessage ?: res.get(R.string.err_unknown)
        }
    }

    /** Vuelve al estado inicial (p. ej. al desconectar la cuenta). */
    fun resetSyncState() {
        _syncState.value = SyncState.Idle
    }

    /** Cliente WebDAV apuntando a la carpeta de la app de esa cuenta. */
    fun createClient(credentials: NextcloudCredentials): WebDavClient = WebDavClient(
        baseUrl = authPreferences.buildWebDavRootUrl(credentials),
        username = credentials.username,
        appPassword = credentials.appPassword
    )

    // ==================================================================
    // Conexión de cuenta
    // ==================================================================

    /**
     * Conecta una cuenta: valida credenciales, desbloquea o crea la bóveda y prepara los datos
     * locales para subirse completos en la primera sincronización.
     *
     * Antes de tocar nada guarda una copia ZIP de las notas (ver [BackupManager.exportSafetyCopy]).
     * El estado local se prepara antes de guardar las credenciales y con el cerrojo de la
     * sincronización tomado, para que ninguna ronda pueda ver la cuenta nueva con el estado viejo.
     */
    suspend fun connectAccount(credentials: NextcloudCredentials, masterPassword: String): Result<Unit> =
        withContext(Dispatchers.IO) {
            try {
                val client = createClient(credentials)
                client.ensureRootFolder()
                val (ring, _) = vault.unlockRemote(client, masterPassword)

                try {
                    val untitled = Strings.get(R.string.untitled)
                    BackupManager().exportSafetyCopy(untitled)
                } catch (e: Exception) {
                    // La copia es una red de seguridad; si falla, la sincronización sigue protegida
                    // por las reglas de fusión y el freno de borrados masivos.
                    Log.w(TAG, "No se pudo guardar la copia previa a la sincronización", e)
                }

                syncMutex.withLock {
                    // Puede ser otra cuenta u otra bóveda: se olvida el estado remoto previo.
                    database.withTransaction {
                        noteDao.resetSyncMetadata()
                        folderDao.resetSyncMetadata()
                        attachmentDao.markAllPendingUpload()
                        tombstoneDao.clear()
                    }
                    authPreferences.saveCredentials(credentials.serverUrl, credentials.username, credentials.appPassword)
                    authPreferences.saveKeyring(ring)
                }
                Result.success(Unit)
            } catch (e: Exception) {
                Log.w(TAG, "connectAccount", e)
                Result.failure(Exception(friendlyMessage(e), e))
            }
        }

    // ==================================================================
    // Sincronización
    // ==================================================================

    /**
     * Desbloqueo con el servidor si hay conexión (así se recoge una bóveda que otro dispositivo
     * haya actualizado a v3); sin conexión, con la copia local.
     */
    suspend fun unlock(masterPassword: String): Keyring = withContext(Dispatchers.IO) {
        val credentials = authPreferences.getCredentials()
        if (credentials != null) {
            try {
                return@withContext vault.unlockRemote(createClient(credentials), masterPassword).first
            } catch (e: java.io.IOException) {
                if (e is WebDavAuthException) throw e
                Log.w(TAG, "Sin conexión: desbloqueo local", e)
            }
        }
        vault.unlockLocal(masterPassword)
    }

    /**
     * Sincroniza ahora. Si no hay cuenta o clave no hace nada. Si ya hay una sincronización en
     * marcha, pide que repita una ronda al terminar y vuelve enseguida. Repite hasta [MAX_ROUNDS]
     * rondas mientras haya cambios remotos que fusionar antes de subir.
     */
    suspend fun synchronize(): Result<Unit> = withContext(Dispatchers.IO) {
        val credentials = authPreferences.getCredentials()
        val ring = authPreferences.getKeyring()
        if (credentials == null || ring == null) {
            _syncState.value = SyncState.Idle
            return@withContext Result.success(Unit)
        }

        if (!syncMutex.tryLock()) {
            rerunRequested = true
            return@withContext Result.success(Unit)
        }

        try {
            val client = createClient(credentials)
            warnings = 0
            protectedNotes = 0
            rollbacks = 0
            var rounds = 0
            do {
                rerunRequested = false
                runRound(client, ring)
                rounds++
            } while (rerunRequested && rounds < MAX_ROUNDS)

            val now = System.currentTimeMillis()
            authPreferences.setLastSync(now)
            _syncState.value = SyncState.Success(now, warnings, protectedNotes, rollbacks)
            Result.success(Unit)
        } catch (e: Exception) {
            Log.w(TAG, "synchronize", e)
            _syncState.value = SyncState.Error(friendlyMessage(e), e)
            Result.failure(e)
        } finally {
            syncMutex.unlock()
        }
    }

    /** Una ronda completa: comprueba la bóveda, descarga y fusiona, sube lo pendiente y limpia. */
    private suspend fun runRound(client: WebDavClient, ring: Keyring) {
        _syncState.value = SyncState.Syncing(SyncStage.CONNECTING)
        client.ensureRootFolder()
        val (current, restored) = vault.verifyRemoteKey(client, ring)
        @Suppress("NAME_SHADOWING") val ring = current
        if (restored) {
            // La bóveda se ha restaurado en una carpeta vacía o incompleta: se vuelve a subir
            // todo lo que tiene este dispositivo, sin interpretar lo que falta como borrados.
            database.withTransaction {
                noteDao.resetSyncMetadata()
                folderDao.resetSyncMetadata()
                attachmentDao.markAllPendingUpload()
                tombstoneDao.clear()
            }
        }

        val remote = client.listRemoteFiles().associateBy { it.name }
        if (ring.isV3) readManifest(client, ring, remote[Manifest.FILE_NAME])

        _syncState.value = SyncState.Syncing(SyncStage.DOWNLOADING)
        pullFolders(client, ring, remote)
        pullNotes(client, ring, remote)
        migrateLegacyImages()
        downloadMissingAttachments(client, ring, remote)

        _syncState.value = SyncState.Syncing(SyncStage.UPLOADING)
        pushFolders(client, ring, remote)
        pushAttachments(client, ring)
        pushNotes(client, ring, remote)

        if (ring.isV3) writeManifest(client, ring, remote[Manifest.FILE_NAME])
        cleanupOrphanAttachments()
        tombstoneDao.getAll().filter { it.fileName !in remote }.forEach { tombstoneDao.delete(it.fileName) }
    }

    // ------------------------------------------------------------------
    // Protección contra vueltas atrás (bóvedas v3, ver docs/SYNC_FORMAT.md)
    // ------------------------------------------------------------------

    private var rollbacks = 0
    /** `rev` más alto conocido de cada fichero; se guarda en el almacén seguro. */
    private val knownRevs = HashMap<String, Long>()
    private var revsDirty = false

    private suspend fun readManifest(client: WebDavClient, ring: Keyring, meta: RemoteFileMeta?) {
        knownRevs.clear()
        knownRevs.putAll(authPreferences.getKnownRevs())
        revsDirty = meta == null
        if (meta == null) return
        val manifest = downloadRecord(Manifest.FILE_NAME) { Manifest.decode(client.downloadText(Manifest.FILE_NAME), ring) } ?: return
        if (manifest.seq < authPreferences.getManifestSeq()) {
            Log.w(TAG, "El servidor devuelve un manifiesto anterior")
            rollbacks++
            revsDirty = true
        } else {
            authPreferences.setManifestSeq(manifest.seq)
        }
        for ((name, rev) in manifest.revs) if (rev > (knownRevs[name] ?: 0L)) knownRevs[name] = rev
        if (manifest.revs != knownRevs) revsDirty = true
        authPreferences.setKnownRevs(knownRevs)
    }

    private fun isRollback(ring: Keyring, name: String, rev: Long): Boolean {
        if (!ring.isV3) return false
        val known = knownRevs[name] ?: return false
        if (rev < known) {
            Log.w(TAG, "Vuelta atrás en $name: rev $rev < $known")
            rollbacks++
            return true
        }
        return false
    }

    private fun seenRev(ring: Keyring, name: String, rev: Long) {
        if (!ring.isV3 || rev <= (knownRevs[name] ?: 0L)) return
        knownRevs[name] = rev
        revsDirty = true
    }

    private fun nextRev(name: String): Long = (knownRevs[name] ?: 0L) + 1

    private fun revOf(record: RemoteRecord<*>): Long = when (record) {
        is RemoteRecord.Live -> record.rev
        is RemoteRecord.Tombstone -> record.rev
    }

    private suspend fun writeManifest(client: WebDavClient, ring: Keyring, meta: RemoteFileMeta?) {
        authPreferences.setKnownRevs(knownRevs)
        if (!revsDirty) return
        val seq = authPreferences.getManifestSeq() + 1
        try {
            client.uploadText(Manifest.FILE_NAME, Manifest(seq, knownRevs.toMap()).encode(ring), ifMatch = meta?.etag, ifNoneMatch = meta?.etag == null)
            authPreferences.setManifestSeq(seq)
            revsDirty = false
        } catch (_: WebDavPreconditionFailedException) {
            rerunRequested = true
        }
    }

    // ------------------------------------------------------------------
    // Descarga
    // ------------------------------------------------------------------

    /** Ficheros remotos de un tipo, indexados por el id que llevan en el nombre. */
    private fun idsWithPrefix(remote: Map<String, RemoteFileMeta>, prefix: String, ext: String) =
        remote.values.filter { it.name.startsWith(prefix) && it.name.endsWith(ext) }
            .associateBy { it.name.removePrefix(prefix).removeSuffix(ext) }

    /** Descarga y fusiona las carpetas que cambiaron en el servidor, y trata las que desaparecieron. */
    private suspend fun pullFolders(client: WebDavClient, ring: Keyring, remote: Map<String, RemoteFileMeta>) {
        val remoteFolders = idsWithPrefix(remote, FOLDER_PREFIX, JSON_EXT)
        val knownTombstones = tombstoneDao.getAll().associate { it.fileName to it.etag }

        for ((id, meta) in remoteFolders) {
            val local = folderDao.getFolderById(id)
            if (local?.remoteEtag != null && local.remoteEtag == meta.etag) continue
            if (local == null && meta.etag != null && knownTombstones[meta.name] == meta.etag) continue

            val record = downloadRecord(meta.name) { RemoteCodec.decodeFolder(client.downloadText(meta.name), id, ring) }
                ?: continue
            val folderRev = revOf(record)
            if (isRollback(ring, meta.name, folderRev)) {
                if (local != null) {
                    folderDao.setRemoteEtag(id, meta.etag)
                    folderDao.updateSyncStatus(id, SyncStatus.PENDING_UPLOAD)
                }
                continue
            }
            seenRev(ring, meta.name, folderRev)

            if (record is RemoteRecord.Tombstone) tombstoneDao.upsert(RemoteTombstoneEntity(meta.name, meta.etag))

            database.withTransaction {
                val current = folderDao.getFolderById(id)
                when (val action = SyncMerger.resolveFolder(current, record, meta.etag)) {
                    is MergeAction.SaveRemote -> folderDao.upsertFolder(action.entity)
                    is MergeAction.KeepLocal -> folderDao.setRemoteEtag(id, action.etag)
                    MergeAction.DeleteLocal, is MergeAction.TrashLocal -> folderDao.deletePermanently(id)
                    else -> Unit
                }
            }
        }

        for (local in folderDao.getAll()) {
            if (local.id in remoteFolders) continue
            when (SyncMerger.resolveMissingRemote(local.syncStatus, local.remoteEtag)) {
                MissingRemoteAction.DELETE_LOCAL -> folderDao.deletePermanently(local.id)
                MissingRemoteAction.MARK_FOR_UPLOAD -> folderDao.updateSyncStatus(local.id, SyncStatus.PENDING_UPLOAD)
                MissingRemoteAction.FORGET_ETAG -> folderDao.setRemoteEtag(local.id, null)
                MissingRemoteAction.NOTHING, MissingRemoteAction.TRASH_AND_REUPLOAD -> Unit
            }
        }
    }

    /**
     * Descarga y fusiona las notas que cambiaron en el servidor. Las notas visibles que el servidor
     * quiere retirar (lápidas o ficheros desaparecidos) se aplican al final, salvo que sean tantas
     * que parezca un borrado en bloque (ver [SyncMerger.isMassRemoval]); entonces se conservan.
     */
    private suspend fun pullNotes(client: WebDavClient, ring: Keyring, remote: Map<String, RemoteFileMeta>) {
        val remoteNotes = idsWithPrefix(remote, NOTE_PREFIX, JSON_EXT)
        val res = Strings
        val conflictSuffix = res.get(R.string.conflict_suffix)
        val untitled = res.get(R.string.untitled)
        val knownTombstones = tombstoneDao.getAll().associate { it.fileName to it.etag }

        // Retiradas de notas visibles: se aplican al final, y solo si no son un borrado en bloque.
        val pendingRemovals = mutableListOf<PendingRemoval>()

        for ((id, meta) in remoteNotes) {
            val local = noteDao.getNoteById(id)
            if (local?.remoteEtag != null && local.remoteEtag == meta.etag) continue
            if (local == null && meta.etag != null && knownTombstones[meta.name] == meta.etag) continue

            val record = downloadRecord(meta.name) { RemoteCodec.decodeNote(client.downloadText(meta.name), id, ring) }
                ?: continue
            val noteRev = revOf(record)
            if (isRollback(ring, meta.name, noteRev)) {
                if (local != null && local.syncStatus != SyncStatus.PENDING_DELETE) {
                    noteDao.setRemoteEtag(id, meta.etag)
                    noteDao.updateSyncStatus(id, SyncStatus.PENDING_UPLOAD)
                }
                continue
            }
            seenRev(ring, meta.name, noteRev)

            if (record is RemoteRecord.Tombstone) tombstoneDao.upsert(RemoteTombstoneEntity(meta.name, meta.etag))

            database.withTransaction {
                val current = noteDao.getNoteById(id)
                val action = SyncMerger.resolveNote(current, record, meta.etag, { UUID.randomUUID().toString() }, conflictSuffix, untitled)
                if (current != null && !current.isDeleted && (action is MergeAction.DeleteLocal || action is MergeAction.TrashLocal)) {
                    pendingRemovals += PendingRemoval.Tombstone(id, record, meta.etag)
                } else {
                    applyNoteAction(id, action)
                }
            }
        }

        for (local in noteDao.getAll()) {
            if (local.id in remoteNotes) continue
            when (SyncMerger.resolveMissingRemoteNote(local.syncStatus, local.remoteEtag)) {
                MissingRemoteAction.TRASH_AND_REUPLOAD ->
                    if (local.isDeleted) noteDao.trashForReupload(local.id)
                    else pendingRemovals += PendingRemoval.Missing(local.id)
                MissingRemoteAction.DELETE_LOCAL -> noteDao.deletePermanently(local.id)
                MissingRemoteAction.MARK_FOR_UPLOAD -> noteDao.updateSyncStatus(local.id, SyncStatus.PENDING_UPLOAD)
                MissingRemoteAction.FORGET_ETAG -> noteDao.setRemoteEtag(local.id, null)
                MissingRemoteAction.NOTHING -> Unit
            }
        }

        if (pendingRemovals.isEmpty()) return

        if (SyncMerger.isMassRemoval(pendingRemovals.size, noteDao.countLive())) {
            Log.w(TAG, "El servidor retiraría ${pendingRemovals.size} notas a la vez; se conservan y se vuelven a subir")
            database.withTransaction {
                for (removal in pendingRemovals) {
                    val current = noteDao.getNoteById(removal.id) ?: continue
                    if (current.syncStatus == SyncStatus.PENDING_DELETE) continue
                    // Con el ETag de la lápida, la subida la sobrescribe; sin fichero, se crea de nuevo.
                    val etag = (removal as? PendingRemoval.Tombstone)?.etag
                    noteDao.setRemoteEtag(removal.id, etag)
                    noteDao.updateSyncStatus(removal.id, SyncStatus.PENDING_UPLOAD)
                }
            }
            protectedNotes += pendingRemovals.size
            return
        }

        for (removal in pendingRemovals) {
            database.withTransaction {
                // Se vuelve a decidir con el estado actual: la nota pudo editarse durante la descarga.
                val current = noteDao.getNoteById(removal.id) ?: return@withTransaction
                when (removal) {
                    is PendingRemoval.Tombstone -> applyNoteAction(
                        removal.id,
                        SyncMerger.resolveNote(current, removal.record, removal.etag, { UUID.randomUUID().toString() }, conflictSuffix, untitled)
                    )
                    is PendingRemoval.Missing ->
                        if (SyncMerger.resolveMissingRemoteNote(current.syncStatus, current.remoteEtag) == MissingRemoteAction.TRASH_AND_REUPLOAD) {
                            Log.w(TAG, "La nota ${current.id} desapareció del servidor sin lápida; se mueve a la papelera")
                            noteDao.trashForReupload(current.id)
                        }
                }
            }
        }
    }

    /** Nota visible que el servidor quiere retirar; se decide al final de [pullNotes]. */
    private sealed interface PendingRemoval {
        val id: String
        class Tombstone(override val id: String, val record: RemoteRecord<NoteEntity>, val etag: String?) : PendingRemoval
        class Missing(override val id: String) : PendingRemoval
    }

    /** Aplica en la base de datos el resultado de fusionar una nota. */
    private suspend fun applyNoteAction(id: String, action: MergeAction<NoteEntity>) {
        when (action) {
            is MergeAction.SaveRemote -> noteDao.upsertNote(action.entity)
            is MergeAction.KeepLocal -> noteDao.setRemoteEtag(id, action.etag)
            is MergeAction.Conflict -> {
                noteDao.upsertNote(action.main)
                noteDao.upsertNote(action.copy)
            }
            MergeAction.DeleteLocal -> noteDao.deletePermanently(id)
            is MergeAction.TrashLocal -> noteDao.trashFromRemote(id, action.etag)
            MergeAction.Skip -> Unit
        }
    }

    /**
     * Descarga y descodifica un fichero. Un fichero corrupto o de una versión futura se omite
     * (se cuenta como aviso) en lugar de detener toda la sincronización.
     */
    private suspend fun <T> downloadRecord(name: String, block: suspend () -> T): T? = try {
        block()
    } catch (e: WebDavException) {
        if (e.code == 404) null else throw e
    } catch (e: GeneralSecurityException) {
        Log.w(TAG, "No se pudo descifrar $name", e); warnings++; null
    } catch (e: JSONException) {
        Log.w(TAG, "JSON no válido en $name", e); warnings++; null
    } catch (e: IllegalArgumentException) {
        Log.w(TAG, "Fichero no válido $name", e); warnings++; null
    }

    /** Descarga los adjuntos que citan las notas y aún no están en este dispositivo. */
    private suspend fun downloadMissingAttachments(
        client: WebDavClient,
        ring: Keyring,
        remote: Map<String, RemoteFileMeta>
    ) {
        val contents = noteDao.getAllLiveContents()
        val referenced = contents.flatMapTo(mutableSetOf()) { AttachmentStore.referencedIds(it) }
        // Los ficheros (no imágenes) llevan su nombre en el enlace: de ahí sale su tipo.
        val fileNames = HashMap<String, String>().apply { contents.forEach { putAll(AttachmentStore.fileNames(it)) } }
        for (id in referenced) {
            if (attachmentStore.exists(id)) continue
            val name = attachmentFile(id)
            if (name !in remote) continue
            val bytes = downloadRecord(name) { RemoteCodec.decryptAttachment(client.download(name), id, ring) } ?: continue
            attachmentStore.write(id, bytes)
            attachmentDao.upsert(
                AttachmentEntity(
                    id = id,
                    mimeType = fileNames[id]?.let { AttachmentStore.mimeForName(it) }
                        ?: AttachmentStore.detectMimeType(bytes, fallback = if (id in fileNames) "application/octet-stream" else "image/webp"),
                    size = bytes.size.toLong(),
                    isUploaded = true
                )
            )
        }
    }

    // ------------------------------------------------------------------
    // Subida
    // ------------------------------------------------------------------

    /** Sube las carpetas pendientes y las lápidas de las carpetas borradas. */
    private suspend fun pushFolders(client: WebDavClient, ring: Keyring, remote: Map<String, RemoteFileMeta>) {
        for (folder in folderDao.getFoldersBySyncStatus(SyncStatus.PENDING_UPLOAD)) {
            val name = folderFile(folder.id)
            val rev = nextRev(name)
            val etag = putGuarded(client, name, RemoteCodec.encodeFolder(folder, ring, rev), folder.remoteEtag) ?: continue
            seenRev(ring, name, rev)
            if (folderDao.markSynced(folder.id, folder.updatedAt, etag.value) == 0) {
                folderDao.setRemoteEtag(folder.id, etag.value)
            }
        }

        for (folder in folderDao.getFoldersBySyncStatus(SyncStatus.PENDING_DELETE)) {
            val name = folderFile(folder.id)
            val knownEtag = folder.remoteEtag ?: remote[name]?.etag
            if (knownEtag == null) {
                folderDao.deletePermanently(folder.id)
                continue
            }
            val rev = nextRev(name)
            val etag = putGuarded(client, name, RemoteCodec.encodeTombstone(RemoteCodec.TYPE_FOLDER, folder.id, folder.updatedAt, ring, rev), knownEtag)
                ?: continue
            seenRev(ring, name, rev)
            tombstoneDao.upsert(RemoteTombstoneEntity(name, etag.value))
            folderDao.deletePermanently(folder.id)
        }
    }

    /** Sube cifrados los adjuntos pendientes. Nunca sobrescribe: si ya existe, se da por subido. */
    private suspend fun pushAttachments(client: WebDavClient, ring: Keyring) {
        for (attachment in attachmentDao.getPendingUpload()) {
            if (!attachmentStore.exists(attachment.id)) {
                attachmentDao.delete(attachment.id)
                continue
            }
            val encrypted = RemoteCodec.encryptAttachment(attachmentStore.read(attachment.id), attachment.id, ring)
            try {
                client.upload(attachmentFile(attachment.id), encrypted, "application/octet-stream", ifNoneMatch = true)
            } catch (_: WebDavPreconditionFailedException) {
                // Ya existe en el servidor: los adjuntos son inmutables.
            }
            attachmentDao.markUploaded(attachment.id)
        }
    }

    /**
     * Sube las notas pendientes y las lápidas de las notas borradas definitivamente.
     * Si una nota nunca llegó al servidor, se borra sin subir lápida.
     */
    private suspend fun pushNotes(client: WebDavClient, ring: Keyring, remote: Map<String, RemoteFileMeta>) {
        for (note in noteDao.getNotesBySyncStatus(SyncStatus.PENDING_UPLOAD)) {
            val name = noteFile(note.id)
            val rev = nextRev(name)
            val etag = putGuarded(client, name, RemoteCodec.encodeNote(note, ring, rev), note.remoteEtag) ?: continue
            seenRev(ring, name, rev)
            if (noteDao.markSynced(note.id, note.updatedAt, etag.value) == 0) {
                // El usuario editó la nota mientras se subía: sigue pendiente, pero con el ETag nuevo.
                noteDao.setRemoteEtag(note.id, etag.value)
            }
        }

        for (note in noteDao.getNotesBySyncStatus(SyncStatus.PENDING_DELETE)) {
            val name = noteFile(note.id)
            val knownEtag = note.remoteEtag ?: remote[name]?.etag
            if (knownEtag == null) {
                noteDao.deletePermanently(note.id)
                continue
            }
            val rev = nextRev(name)
            val etag = putGuarded(client, name, RemoteCodec.encodeTombstone(RemoteCodec.TYPE_NOTE, note.id, note.updatedAt, ring, rev), knownEtag)
                ?: continue
            seenRev(ring, name, rev)
            tombstoneDao.upsert(RemoteTombstoneEntity(name, etag.value))
            noteDao.deletePermanently(note.id)
        }
    }

    /** ETag devuelto por una subida correcta (puede ser `null` si el servidor no lo da). */
    private class Etag(val value: String?)

    /**
     * PUT con control de concurrencia. Devuelve null si el servidor rechazó la subida porque
     * el fichero cambió (se pedirá otra ronda para fusionar primero).
     */
    private suspend fun putGuarded(client: WebDavClient, name: String, body: String, knownEtag: String?): Etag? {
        return try {
            val etag = client.uploadText(name, body, ifMatch = knownEtag, ifNoneMatch = knownEtag == null)
            Etag(etag ?: client.fetchEtag(name))
        } catch (_: WebDavPreconditionFailedException) {
            rerunRequested = true
            null
        }
    }

    // ------------------------------------------------------------------
    // Mantenimiento
    // ------------------------------------------------------------------

    /**
     * Convierte las imágenes Base64 incrustadas de la v1.0 en adjuntos independientes.
     */
    suspend fun migrateLegacyImages() = withContext(Dispatchers.IO) {
        for (note in noteDao.getNotesWithLegacyImages()) {
            val payload = NoteContentParser.parse(note.content)
            if (payload.images.isEmpty()) continue

            var text = payload.text
            for ((legacyKey, dataUri) in payload.images) {
                val base64 = dataUri.substringAfter("base64,", missingDelimiterValue = "")
                if (base64.isEmpty()) continue
                val bytes = try {
                    Base64.getMimeDecoder().decode(base64)
                } catch (_: IllegalArgumentException) {
                    continue
                }
                val id = UUID.randomUUID().toString()
                attachmentStore.write(id, bytes)
                attachmentDao.upsert(AttachmentEntity(id = id, mimeType = "image/webp", size = bytes.size.toLong()))
                text = text.replace("($legacyKey)", "(${AttachmentStore.reference(id)})")
            }
            noteDao.upsertNote(
                note.copy(
                    content = text,
                    updatedAt = System.currentTimeMillis(),
                    syncStatus = if (note.syncStatus == SyncStatus.PENDING_DELETE) note.syncStatus else SyncStatus.PENDING_UPLOAD
                )
            )
        }
    }

    /** Borra en local los adjuntos que ya no usa ninguna nota (tras un periodo de gracia). */
    private suspend fun cleanupOrphanAttachments() {
        val referenced = noteDao.getAllLiveContents().flatMapTo(mutableSetOf()) { AttachmentStore.referencedIds(it) }
        val threshold = System.currentTimeMillis() - ORPHAN_ATTACHMENT_GRACE_MS
        for (attachment in attachmentDao.getAll()) {
            if (attachment.id !in referenced && attachment.createdAt < threshold) {
                attachmentStore.delete(attachment.id)
                attachmentDao.delete(attachment.id)
            }
        }
    }
}

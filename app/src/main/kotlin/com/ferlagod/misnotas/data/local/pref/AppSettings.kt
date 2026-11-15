// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/ferlagod/mis_notas_desktop

package com.ferlagod.misnotas.data.local.pref

import com.ferlagod.misnotas.data.update.ReleaseInfo
import com.ferlagod.misnotas.platform.AppDirs
import com.ferlagod.misnotas.platform.PropertiesStore
import java.io.File
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/** Tema de la interfaz. */
enum class ThemeMode { SYSTEM, LIGHT, DARK }

/** Orden de las notas en las listas (las fijadas siempre van primero). */
enum class SortOrder { MODIFIED_DESC, MODIFIED_ASC, TITLE_ASC, TITLE_DESC }

/** Preferencias de la app que no son secretas (aspecto y comportamiento). */
data class AppSettingsState(
    /** Lista de notas en cuadrícula (`true`) o en una columna. */
    val gridLayout: Boolean = true,
    /** Orden de las notas. */
    val sortOrder: SortOrder = SortOrder.MODIFIED_DESC,
    /** Tema claro, oscuro o el del sistema. */
    val themeMode: ThemeMode = ThemeMode.SYSTEM,
    /** En modo oscuro, negro puro en lugar de gris (pantallas OLED). */
    val amoled: Boolean = false,
    /** Vaciar automáticamente las notas con más de [AppSettings.TRASH_RETENTION_DAYS] días en la papelera. */
    val autoPurgeTrash: Boolean = true,
    /** Pedir la contraseña de bloqueo al abrir la app. */
    val appLock: Boolean = false,
    /** Comprobar al arrancar si hay una versión nueva publicada en GitHub. */
    val checkUpdates: Boolean = true
)

/**
 * Preferencias no sensibles en `settings.properties` (carpeta de datos de la app), expuestas como [StateFlow]
 * para que la interfaz reaccione al instante. Comparte fichero con el idioma.
 */
class AppSettings private constructor(private val prefs: PropertiesStore) {

    private val _state = MutableStateFlow(read())
    /** Preferencias actuales; emite un valor nuevo con cada cambio. */
    val state: StateFlow<AppSettingsState> = _state.asStateFlow()

    /** Lee todas las preferencias del fichero, con los valores por defecto si faltan. */
    private fun read() = AppSettingsState(
        gridLayout = prefs.getBoolean(KEY_GRID, true),
        sortOrder = enumOrDefault(prefs.getString(KEY_SORT, null), SortOrder.MODIFIED_DESC),
        themeMode = enumOrDefault(prefs.getString(KEY_THEME, null), ThemeMode.SYSTEM),
        amoled = prefs.getBoolean(KEY_AMOLED, false),
        autoPurgeTrash = prefs.getBoolean(KEY_AUTO_PURGE, true),
        appLock = prefs.getBoolean(KEY_APP_LOCK, false),
        checkUpdates = prefs.getBoolean(KEY_CHECK_UPDATES, true)
    )

    /** Guarda los cambios en disco y publica el nuevo estado. */
    private fun update(block: PropertiesStore.Editor.() -> Unit) {
        prefs.edit(block)
        _state.value = read()
    }

    /** Cambia entre cuadrícula y lista. */
    fun setGridLayout(grid: Boolean) = update { putBoolean(KEY_GRID, grid) }
    /** Cambia el orden de las notas. */
    fun setSortOrder(order: SortOrder) = update { putString(KEY_SORT, order.name) }
    /** Cambia el tema. */
    fun setThemeMode(mode: ThemeMode) = update { putString(KEY_THEME, mode.name) }
    /** Activa o desactiva el negro puro en modo oscuro. */
    fun setAmoled(enabled: Boolean) = update { putBoolean(KEY_AMOLED, enabled) }
    /** Activa o desactiva el vaciado automático de la papelera. */
    fun setAutoPurgeTrash(enabled: Boolean) = update { putBoolean(KEY_AUTO_PURGE, enabled) }
    /** Activa o desactiva el bloqueo al abrir (la contraseña se gestiona en `AppLock`). */
    fun setAppLock(enabled: Boolean) = update { putBoolean(KEY_APP_LOCK, enabled) }
    /** Activa o desactiva la comprobación automática de versiones nuevas. */
    fun setCheckUpdates(enabled: Boolean) = update { putBoolean(KEY_CHECK_UPDATES, enabled) }

    /** Momento (ms) de la última comprobación automática de versiones, o 0 si nunca. */
    var lastUpdateCheck: Long
        get() = prefs.getLong(KEY_LAST_UPDATE_CHECK, 0L)
        set(value) = prefs.edit { putLong(KEY_LAST_UPDATE_CHECK, value) }

    /** Última versión publicada que se vio en GitHub, para avisar sin volver a consultar. */
    var lastSeenRelease: ReleaseInfo?
        get() {
            val version = prefs.getString(KEY_LAST_SEEN_VERSION, null) ?: return null
            val url = prefs.getString(KEY_LAST_SEEN_URL, null) ?: return null
            return ReleaseInfo(version, url)
        }
        set(value) = prefs.edit {
            putString(KEY_LAST_SEEN_VERSION, value?.version)
            putString(KEY_LAST_SEEN_URL, value?.url)
        }

    /** Versión de la que el usuario pidió no volver a avisar, o null. */
    var skippedVersion: String?
        get() = prefs.getString(KEY_SKIPPED_VERSION, null)
        set(value) = prefs.edit { putString(KEY_SKIPPED_VERSION, value) }

    companion object {
        /** Fichero compartido con el idioma (ver LanguageManager). */
        val store: PropertiesStore by lazy { PropertiesStore(File(AppDirs.dataDir, "settings.properties")) }
        private const val KEY_GRID = "grid_layout"
        private const val KEY_SORT = "sort_order"
        private const val KEY_THEME = "theme_mode"
        private const val KEY_AMOLED = "amoled"
        private const val KEY_AUTO_PURGE = "auto_purge_trash"
        private const val KEY_APP_LOCK = "app_lock"
        private const val KEY_CHECK_UPDATES = "check_updates"
        private const val KEY_LAST_UPDATE_CHECK = "last_update_check"
        private const val KEY_SKIPPED_VERSION = "skipped_update_version"
        private const val KEY_LAST_SEEN_VERSION = "last_seen_release_version"
        private const val KEY_LAST_SEEN_URL = "last_seen_release_url"

        /** Días que una nota permanece en la papelera antes del vaciado automático. */
        const val TRASH_RETENTION_DAYS = 30

        @Volatile
        private var INSTANCE: AppSettings? = null

        /** Instancia única de la app. */
        fun getInstance(): AppSettings =
            INSTANCE ?: synchronized(this) {
                INSTANCE ?: AppSettings(store).also { INSTANCE = it }
            }

        /** Convierte un nombre guardado en su valor del enum, o [default] si no existe. */
        private inline fun <reified E : Enum<E>> enumOrDefault(name: String?, default: E): E =
            name?.let { n -> enumValues<E>().firstOrNull { it.name == n } } ?: default
    }
}

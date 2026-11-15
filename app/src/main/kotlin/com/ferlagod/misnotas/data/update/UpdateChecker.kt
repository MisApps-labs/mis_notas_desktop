// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/ferlagod/mis_notas_desktop

package com.ferlagod.misnotas.data.update

import com.ferlagod.misnotas.data.remote.webdav.WebDavClient
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import okhttp3.OkHttpClient
import okhttp3.Request
import org.json.JSONObject
import java.util.concurrent.TimeUnit

/** Versión publicada en GitHub. */
data class ReleaseInfo(
    /** Número de versión sin la "v" inicial ("1.0.1"). */
    val version: String,
    /** Página de la versión, con los instaladores para descargar. */
    val url: String
)

/**
 * Consulta en GitHub la última versión publicada de la app. Solo hace una petición GET a la API
 * pública de *releases*; no envía ningún dato del usuario ni descarga instaladores.
 */
object UpdateChecker {

    private const val LATEST_RELEASE_API =
        "https://api.github.com/repos/ferlagod/mis_notas_desktop/releases/latest"
    private const val RELEASES_PAGE = "https://github.com/ferlagod/mis_notas_desktop/releases"

    private val client: OkHttpClient by lazy {
        WebDavClient.sharedHttpClient.newBuilder()
            .connectTimeout(10, TimeUnit.SECONDS)
            .readTimeout(15, TimeUnit.SECONDS)
            .build()
    }

    /**
     * Última versión publicada (excluye borradores y *prereleases*, como hace la API).
     *
     * @throws Exception si no hay conexión o GitHub responde con un error.
     */
    suspend fun fetchLatest(): ReleaseInfo = withContext(Dispatchers.IO) {
        val request = Request.Builder()
            .url(LATEST_RELEASE_API)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "MisNotas-Desktop")
            .build()
        client.newCall(request).execute().use { response ->
            check(response.isSuccessful) { "HTTP ${response.code}" }
            val json = JSONObject(response.body.string())
            ReleaseInfo(
                version = json.getString("tag_name").removePrefix("v").removePrefix("V"),
                url = json.optString("html_url").ifBlank { RELEASES_PAGE }
            )
        }
    }

    /**
     * `true` si [candidate] es posterior a [current]. Compara número a número ("1.10.0" > "1.9.2");
     * lo que vaya tras un guion ("1.1.0-beta") se ignora.
     */
    fun isNewer(candidate: String, current: String): Boolean {
        val a = parts(candidate)
        val b = parts(current)
        for (i in 0 until maxOf(a.size, b.size)) {
            val x = a.getOrElse(i) { 0 }
            val y = b.getOrElse(i) { 0 }
            if (x != y) return x > y
        }
        return false
    }

    private fun parts(version: String): List<Int> =
        version.trim().removePrefix("v").substringBefore('-').substringBefore('+')
            .split('.').map { it.filter(Char::isDigit).toIntOrNull() ?: 0 }
}

// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.security.CryptoManager
import com.ferlagod.misnotas.security.Keyring
import org.json.JSONObject

/**
 * `manifest.json` (solo bóvedas v3): número de secuencia y el `rev` más alto de cada fichero,
 * cifrado con la clave actual (AAD `manifest`). Cada dispositivo lo combina con lo que sabe
 * (máximo de cada `rev`) y lo sube con `If-Match` aumentando `seq`.
 *
 * Detecta que el servidor devuelva una versión anterior (válida y firmada) de una nota o del
 * propio manifiesto. No puede detectar que el servidor enseñe a cada dispositivo una historia
 * distinta sin que lleguen a verse entre ellos (ataque de bifurcación).
 */
data class Manifest(val seq: Long, val revs: Map<String, Long>) {

    fun encode(ring: Keyring): String {
        val payload = JSONObject().apply {
            put("seq", seq)
            put("revs", JSONObject(revs as Map<*, *>))
        }
        return JSONObject().apply {
            put("format", FORMAT)
            put("version", 1)
            put("kid", ring.current)
            put("payload", CryptoManager.encrypt(RemoteCodec.padded(payload), ring.currentKey, AAD))
        }.toString()
    }

    companion object {
        const val FILE_NAME = "manifest.json"
        const val FORMAT = "misnotas-manifest"
        private const val AAD = "manifest"

        fun decode(raw: String, ring: Keyring): Manifest {
            val json = JSONObject(raw)
            require(json.optString("format") == FORMAT) { "Manifiesto no válido" }
            val key = ring.key(json.optString("kid").ifBlank { null }) ?: throw javax.crypto.AEADBadTagException("Clave desconocida")
            val payload = JSONObject(CryptoManager.decrypt(json.getString("payload"), key, AAD))
            val revsJson = payload.getJSONObject("revs")
            val revs = revsJson.keys().asSequence().associateWith { revsJson.getLong(it) }
            return Manifest(payload.getLong("seq"), revs)
        }
    }
}

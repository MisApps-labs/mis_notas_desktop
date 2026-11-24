// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.util

import com.ferlagod.misnotas.data.attachment.AttachmentStore
import com.ferlagod.misnotas.platform.Log
import java.awt.Desktop
import java.io.File
import java.nio.file.Files

/**
 * Abre un fichero adjunto (PDF, audio, documento…) con la aplicación del sistema. Se copia a una
 * carpeta temporal con su nombre original para que el sistema sepa qué programa usar; la copia
 * anterior se borra al abrir otra.
 */
object AttachmentOpener {

    private var lastDir: File? = null

    fun open(id: String, name: String?) {
        val source = AttachmentStore.fileFor(id)
        if (!source.exists() || source.length() == 0L) {
            Log.w("AttachmentOpener", "El adjunto $id aún no se ha descargado")
            return
        }
        try {
            lastDir?.deleteRecursively()
            val dir = Files.createTempDirectory("misnotas-").toFile().also { lastDir = it }
            val fileName = (name?.takeIf { it.isNotBlank() } ?: "adjunto.bin").replace(Regex("[\\\\/:*?\"<>|]"), "_")
            val copy = File(dir, fileName)
            source.copyTo(copy, overwrite = true)
            copy.deleteOnExit()
            dir.deleteOnExit()
            if (Desktop.isDesktopSupported() && Desktop.getDesktop().isSupported(Desktop.Action.OPEN)) {
                Thread { runCatching { Desktop.getDesktop().open(copy) } }.start()
            }
        } catch (e: Exception) {
            Log.w("AttachmentOpener", "No se pudo abrir el adjunto $id", e)
        }
    }
}

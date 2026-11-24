// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.security.Argon2
import com.ferlagod.misnotas.security.CryptoManager
import com.ferlagod.misnotas.security.RecoveryKey
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bóveda v3 creada por la app Android (app/src/test/.../CliFixtureTest.kt, copiada en
 * `resources/android-v3-vault`): el escritorio debe abrirla y leer todo lo que contiene.
 */
class AndroidInteropTest {

    private fun res(name: String): ByteArray =
        requireNotNull(javaClass.getResourceAsStream("/android-v3-vault/$name")) { name }.use { it.readBytes() }

    private fun text(name: String) = String(res(name), Charsets.UTF_8)

    private fun openWithPassword(): com.ferlagod.misnotas.security.Keyring {
        val info = KeyInfoV3.parse(text("keyinfo.json"))
        val password = text("password.txt")
        val kek = Argon2.deriveKey(CryptoManager.canonicalPassword(password), info.salt, info.kdf)
        val vmk = info.unwrapWithKek(kek)
        assertNotNull("la contraseña abre la bóveda", vmk)
        return info.openKeyring(vmk!!)
    }

    @Test
    fun opensAndroidVaultAndReadsEverything() {
        val ring = openWithPassword()
        assertTrue(ring.isV3)
        assertEquals(2, ring.keys.size) // la de v2 y la rotada

        val note = RemoteCodec.decodeNote(text("note_n1.json"), "n1", ring) as RemoteRecord.Live
        assertEquals("Plan: Q1", note.entity.title)
        assertEquals("f2", note.entity.folderId)
        assertEquals(3L, note.rev)
        assertTrue(note.entity.content.contains("[📎 informe.pdf](attachment://doc1)"))

        val old = RemoteCodec.decodeNote(text("note_old.json"), "old", ring) as RemoteRecord.Live
        assertEquals("Antigua", old.entity.title)

        val folder = RemoteCodec.decodeFolder(text("folder_f2.json"), "f2", ring) as RemoteRecord.Live
        assertEquals("Proyecto", folder.entity.name)

        val tomb = RemoteCodec.decodeNote(text("note_n3.json"), "n3", ring)
        assertTrue(tomb is RemoteRecord.Tombstone && tomb.verified)

        assertArrayEquals("%PDF-1.7 hola".toByteArray(), RemoteCodec.decryptAttachment(res("att_doc1.bin"), "doc1", ring))
    }

    @Test
    fun recoveryKeyFromAndroidOpensTheVault() {
        val info = KeyInfoV3.parse(text("keyinfo.json"))
        val vmk = info.unwrapWithRecovery(RecoveryKey.parse(text("v3-recovery.txt"))!!)
        assertNotNull(vmk)
        assertEquals(openWithPassword().current, info.openKeyring(vmk!!).current)
    }

    @Test
    fun filesWrittenByDesktopReadBackWithTheSameKeys() {
        val ring = openWithPassword()
        val raw = RemoteCodec.encodeNote(
            com.ferlagod.misnotas.data.local.entity.NoteEntity(id = "d1", title = "Desde el escritorio", content = "hola"), ring, rev = 1
        )
        assertEquals(3, org.json.JSONObject(raw).getInt("version"))
        assertEquals(ring.current, org.json.JSONObject(raw).getString("kid"))
        assertEquals("hola", (RemoteCodec.decodeNote(raw, "d1", ring) as RemoteRecord.Live).entity.content)
    }
}

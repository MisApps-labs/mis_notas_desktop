// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.data.local.entity.FolderEntity
import com.ferlagod.misnotas.data.local.entity.NoteEntity
import com.ferlagod.misnotas.security.Argon2
import com.ferlagod.misnotas.security.CryptoManager
import com.ferlagod.misnotas.security.Keyring
import com.ferlagod.misnotas.security.RecoveryKey
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class VaultV3Test {

    /** Parámetros pequeños para que los tests vayan rápido (la app usa 64 MiB). */
    private val fast = Argon2.Params(memoryKiB = 8_192, iterations = 1, parallelism = 1)

    private val legacyKey = CryptoManager.deriveKey("contraseña", CryptoManager.generateSalt(), CryptoManager.MIN_PBKDF2_ITERATIONS)
    private val ring = Keyring(Keyring.LEGACY_KID, mapOf(Keyring.LEGACY_KID to legacyKey), KeyInfoV3.newVmk())

    private fun kek(info: KeyInfoV3, password: String) = Argon2.deriveKey(password, info.salt, info.kdf)

    @Test
    fun argon2IsDeterministicAndSaltDependent() {
        val salt = ByteArray(16) { it.toByte() }
        val a = Argon2.deriveKey("pw", salt, fast).encoded
        assertArrayEquals(a, Argon2.deriveKey("pw", salt, fast).encoded)
        assertFalse(a.contentEquals(Argon2.deriveKey("pw", ByteArray(16) { 1 }, fast).encoded))
        assertFalse(a.contentEquals(Argon2.deriveKey("pw2", salt, fast).encoded))
    }

    @Test
    fun envelopeUnwrapsOnlyWithTheRightPassword() {
        val info = KeyInfoV3.parse(KeyInfoV3.create("contraseña", ring, fast).toJson())
        val vmk = info.unwrapWithKek(kek(info, "contraseña"))
        assertNotNull(vmk)
        assertNull(info.unwrapWithKek(kek(info, "otra")))
        val opened = info.openKeyring(vmk!!)
        assertEquals(Keyring.LEGACY_KID, opened.current)
        assertArrayEquals(legacyKey.encoded, opened.currentKey.encoded)
    }

    @Test
    fun changingPasswordKeepsTheSameKeys() {
        val info = KeyInfoV3.create("vieja", ring, fast)
        val changed = KeyInfoV3.parse(info.withPassword("nueva", ring.vmk!!, fast).toJson())
        assertNull(changed.unwrapWithKek(kek(changed, "vieja")))
        val vmk = changed.unwrapWithKek(kek(changed, "nueva"))!!
        assertArrayEquals(ring.vmk!!.encoded, vmk.encoded)
        assertEquals(info.keyring, changed.keyring)
    }

    @Test
    fun recoveryKeyOpensTheVault() {
        val (info, recovery) = KeyInfoV3.create("pw", ring, fast).withNewRecovery(ring.vmk!!)
        val parsed = KeyInfoV3.parse(info.toJson())
        assertTrue(parsed.hasRecovery)
        val text = RecoveryKey.format(recovery)
        assertEquals(39, text.length) // 32 caracteres en 8 grupos
        val again = RecoveryKey.parse(text.lowercase().replace("-", " "))!!
        assertArrayEquals(ring.vmk!!.encoded, parsed.unwrapWithRecovery(again)!!.encoded)
        assertNull(parsed.unwrapWithRecovery(RecoveryKey.generate()))
        assertNull(RecoveryKey.parse("corta"))
    }

    @Test
    fun v3FilesArePaddedCarryKidAndRev() {
        val note = NoteEntity(id = "n1", title = "Hola", content = "x".repeat(700))
        val raw = RemoteCodec.encodeNote(note, ring, rev = 5)
        val json = JSONObject(raw)
        assertEquals(3, json.getInt("version"))
        assertEquals(Keyring.LEGACY_KID, json.getString("kid"))
        val plain = CryptoManager.decrypt(json.getString("payload"), legacyKey, "note:n1")
        assertEquals(0, plain.toByteArray().size % RemoteCodec.PAD_BLOCK)
        val back = RemoteCodec.decodeNote(raw, "n1", ring) as RemoteRecord.Live
        assertEquals(note.content, back.entity.content)
        assertEquals(5L, back.rev)
    }

    @Test
    fun v3TombstonesAreEncryptedAndVerified() {
        val raw = RemoteCodec.encodeTombstone(RemoteCodec.TYPE_NOTE, "n1", 99L, ring, rev = 2)
        assertFalse(raw.contains("deleted"))
        assertFalse(RemoteCodec.isTombstone(raw))
        assertEquals(RemoteRecord.Tombstone("n1", 99L, verified = true, rev = 2), RemoteCodec.decodeNote(raw, "n1", ring))
    }

    @Test
    fun rotationReadsOldAndNewFiles() {
        val oldFolder = RemoteCodec.encodeFolder(FolderEntity(id = "f1", name = "Viejo"), ring)
        val oldAttachment = RemoteCodec.encryptAttachment(byteArrayOf(1, 2, 3), "a1", ring)
        val rotated = ring.rotated()
        assertNotEquals(ring.current, rotated.current)
        val newNote = RemoteCodec.encodeNote(NoteEntity(id = "n1", title = "Nueva", content = ""), rotated)
        assertEquals(rotated.current, JSONObject(newNote).getString("kid"))
        assertEquals("Viejo", (RemoteCodec.decodeFolder(oldFolder, "f1", rotated) as RemoteRecord.Live).entity.name)
        assertArrayEquals(byteArrayOf(1, 2, 3), RemoteCodec.decryptAttachment(oldAttachment, "a1", rotated))
        // El llavero viaja cifrado en keyinfo.json y conserva todas las claves.
        val info = KeyInfoV3.create("pw", ring, fast).withKeyring(rotated)
        assertEquals(rotated.keys.keys, info.openKeyring(ring.vmk!!).keys.keys)
    }

    @Test(expected = javax.crypto.AEADBadTagException::class)
    fun unknownKidIsRejected() {
        val raw = JSONObject(RemoteCodec.encodeNote(NoteEntity(id = "n1", title = "t", content = ""), ring)).put("kid", "kZZ").toString()
        RemoteCodec.decodeNote(raw, "n1", ring)
    }

    @Test
    fun v2VaultsStillWriteV2() {
        val legacy = Keyring.legacy(legacyKey)
        val raw = RemoteCodec.encodeNote(NoteEntity(id = "n1", title = "t", content = "c"), legacy)
        assertEquals(2, JSONObject(raw).getInt("version"))
        assertFalse(JSONObject(raw).has("kid"))
        assertTrue(RemoteCodec.isTombstone(RemoteCodec.encodeTombstone(RemoteCodec.TYPE_NOTE, "n1", 1L, legacy)))
        // Una bóveda v3 lee los ficheros v2 que aún no se han reescrito.
        assertEquals("c", (RemoteCodec.decodeNote(raw, "n1", ring) as RemoteRecord.Live).entity.content)
    }
}

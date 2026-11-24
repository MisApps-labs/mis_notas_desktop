// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/MisApps-labs/mis_notas_desktop

package com.ferlagod.misnotas.data.sync

import com.ferlagod.misnotas.security.Keyring
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Test

class ManifestTest {

    private val ring = Keyring(Keyring.LEGACY_KID, mapOf(Keyring.LEGACY_KID to Keyring.randomKey()), KeyInfoV3.newVmk())

    @Test
    fun roundTripIsEncrypted() {
        val manifest = Manifest(7, mapOf("note_a.json" to 3L, "folder_b.json" to 1L))
        val raw = manifest.encode(ring)
        assertFalse(raw.contains("note_a"))
        assertEquals(manifest, Manifest.decode(raw, ring))
    }

    @Test
    fun readableAfterRotation() {
        val raw = Manifest(1, mapOf("x" to 1L)).encode(ring)
        assertEquals(1L, Manifest.decode(raw, ring.rotated()).seq)
    }

    @Test(expected = javax.crypto.AEADBadTagException::class)
    fun tamperedManifestIsRejected() {
        val json = JSONObject(Manifest(1, emptyMap()).encode(ring))
        val other = Keyring(Keyring.LEGACY_KID, mapOf(Keyring.LEGACY_KID to Keyring.randomKey()), KeyInfoV3.newVmk())
        Manifest.decode(json.toString(), other)
    }
}

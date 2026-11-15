// SPDX-License-Identifier: GPL-3.0-or-later
// Copyright (C) 2026 ferlagod
// Mis Notas — https://github.com/ferlagod/mis_notas_desktop

package com.ferlagod.misnotas.data.update

import org.junit.Test
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue

class UpdateCheckerTest {

    @Test
    fun comparesVersionsNumerically() {
        assertTrue(UpdateChecker.isNewer("1.0.1", "1.0.0"))
        assertTrue(UpdateChecker.isNewer("1.10.0", "1.9.9"))
        assertTrue(UpdateChecker.isNewer("2.0", "1.9.9"))
        assertTrue(UpdateChecker.isNewer("v1.1.0", "1.0.0"))
        assertFalse(UpdateChecker.isNewer("1.0.0", "1.0.0"))
        assertFalse(UpdateChecker.isNewer("1.0", "1.0.0"))
        assertFalse(UpdateChecker.isNewer("1.0.0", "1.0.1"))
        assertFalse(UpdateChecker.isNewer("1.0.0-beta", "1.0.0"))
    }
}

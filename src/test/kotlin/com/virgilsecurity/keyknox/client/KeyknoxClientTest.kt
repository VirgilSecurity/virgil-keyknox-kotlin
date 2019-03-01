/*
 * Copyright (c) 2015-2019, Virgil Security, Inc.
 *
 * Lead Maintainer: Virgil Security Inc. <support@virgilsecurity.com>
 *
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 *     (1) Redistributions of source code must retain the above copyright notice, this
 *     list of conditions and the following disclaimer.
 *
 *     (2) Redistributions in binary form must reproduce the above copyright notice,
 *     this list of conditions and the following disclaimer in the documentation
 *     and/or other materials provided with the distribution.
 *
 *     (3) Neither the name of virgil nor the names of its
 *     contributors may be used to endorse or promote products derived from
 *     this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

package com.virgilsecurity.keyknox.client

import com.virgilsecurity.crypto.VirgilCipher
import com.virgilsecurity.crypto.VirgilHash
import com.virgilsecurity.crypto.VirgilSigner
import com.virgilsecurity.keyknox.TestConfig
import com.virgilsecurity.keyknox.utils.base64Encode
import com.virgilsecurity.sdk.common.TimeSpan
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.jwt.JwtGenerator
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.BeforeEach
import org.junit.jupiter.api.Test
import java.util.*
import java.util.concurrent.TimeUnit

class KeyknoxClientTest {

    private val identity = UUID.randomUUID().toString()
    private lateinit var virgilCrypto: VirgilCrypto
    private lateinit var keyknoxClient: KeyknoxClientProtocol
    private lateinit var tokenStr: String
    private lateinit var publicKey: VirgilPublicKey
    private lateinit var privateKey: VirgilPrivateKey

    @BeforeEach
    fun setup() {
        this.virgilCrypto = VirgilCrypto(false)
        val keyPair = this.virgilCrypto.generateKeys(KeysType.FAST_EC_ED25519)
        this.privateKey = keyPair.privateKey
        this.publicKey = keyPair.publicKey
        this.keyknoxClient = KeyknoxClient()

        val jwtGenerator = JwtGenerator(TestConfig.appId, TestConfig.apiKey, TestConfig.apiPublicKeyId, TimeSpan.fromTime(600, TimeUnit.SECONDS),
                VirgilAccessTokenSigner(this.virgilCrypto))
        this.tokenStr = jwtGenerator.generateToken(this.identity).stringRepresentation()
    }

    @Test
    fun pushValue() {
        // KTC-1
        val data = base64Encode(UUID.randomUUID().toString())
        val privateKeyData = this.virgilCrypto.exportPrivateKey(this.privateKey)
        val publicKeyData = this.virgilCrypto.exportPublicKey(this.publicKey)

        val signer = VirgilSigner(VirgilHash.Algorithm.SHA512)
        val signature = signer.sign(data, privateKeyData)

        val cipher = VirgilCipher()
        val customData = cipher.customParams()
        customData.setData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID, privateKey.identifier)
        customData.setData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE, signature)
        cipher.addKeyRecipient(publicKey.identifier, publicKeyData)

        val encryptedData = cipher.encrypt(data)
        val meta = cipher.contentInfo

        val pushedValue = this.keyknoxClient.pushValue(meta, encryptedData, null, this.tokenStr)
        assertArrayEquals(encryptedData, pushedValue.value)
        assertArrayEquals(meta, pushedValue.meta)
        assertEquals("1.0", pushedValue.version)
        assertNotNull(pushedValue.keyknoxHash)
        assertFalse(pushedValue.keyknoxHash!!.isEmpty())

        val pulledValue = this.keyknoxClient.pullValue(this.tokenStr)
        assertArrayEquals(encryptedData, pulledValue.value)
        assertArrayEquals(meta, pulledValue.meta)
        assertEquals("1.0", pulledValue.version)
        assertNotNull(pulledValue.keyknoxHash)
        assertFalse(pulledValue.keyknoxHash!!.isEmpty())
    }

    @Test
    fun pushValue_updateData() {
        // KTC-2
        val data = base64Encode(UUID.randomUUID().toString())
        val data2 = base64Encode(UUID.randomUUID().toString())
        val privateKeyData = this.virgilCrypto.exportPrivateKey(this.privateKey)
        val publicKeyData = this.virgilCrypto.exportPublicKey(this.publicKey)

        val signer = VirgilSigner(VirgilHash.Algorithm.SHA512)
        val signature = signer.sign(data, privateKeyData)

        val cipher = VirgilCipher()
        val customData = cipher.customParams()
        customData.setData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID, privateKey.identifier)
        customData.setData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE, signature)
        cipher.addKeyRecipient(publicKey.identifier, publicKeyData)

        val encryptedData = cipher.encrypt(data)
        val meta = cipher.contentInfo

        val pushedValue = this.keyknoxClient.pushValue(meta, encryptedData, null, this.tokenStr)
        assertArrayEquals(encryptedData, pushedValue.value)

        val signature2 = signer.sign(data2, privateKeyData)

        val cipher2 = VirgilCipher()
        val customData2 = cipher2.customParams()
        customData2.setData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID, privateKey.identifier)
        customData2.setData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE, signature2)
        cipher2.addKeyRecipient(publicKey.identifier, publicKeyData)

        val encryptedData2 = cipher2.encrypt(data2)
        val meta2 = cipher2.contentInfo

        val pushedValue2 = this.keyknoxClient.pushValue(meta2, encryptedData2, pushedValue.keyknoxHash, this.tokenStr)
        assertArrayEquals(encryptedData2, pushedValue2.value)
        assertArrayEquals(meta2, pushedValue2.meta)
        assertEquals("2.0", pushedValue2.version)
        assertNotNull(pushedValue2.keyknoxHash)
        assertFalse(pushedValue2.keyknoxHash!!.isEmpty())
    }

    @Test
    fun pullValue_empty() {
        // KTC-3
        val pulledValue = this.keyknoxClient.pullValue(this.tokenStr)
        assertNotNull(pulledValue.value)
        assertTrue(pulledValue.value!!.isEmpty())
        assertNotNull(pulledValue.meta)
        assertTrue(pulledValue.meta!!.isEmpty())
        assertEquals("1.0", pulledValue.version)
    }

    @Test
    fun resetValue() {
        // KTC-4
        val data = base64Encode(UUID.randomUUID().toString())
        val meta = base64Encode(UUID.randomUUID().toString())
        val pushedValue = this.keyknoxClient.pushValue(meta, data, null, this.tokenStr)
        assertArrayEquals(data, pushedValue.value)

        val resetValue = this.keyknoxClient.resetValue(this.tokenStr)
        assertNotNull(resetValue.value)
        assertTrue(resetValue.value!!.isEmpty())
        assertNotNull(resetValue.meta)
        assertTrue(resetValue.meta!!.isEmpty())
        assertEquals("2.0", resetValue.version)
    }

    @Test
    fun resetValue_empty() {
        // KTC-5
        val resetValue = this.keyknoxClient.resetValue(this.tokenStr)
        assertNotNull(resetValue.value)
        assertTrue(resetValue.value!!.isEmpty())
        assertNotNull(resetValue.meta)
        assertTrue(resetValue.meta!!.isEmpty())
        assertEquals("1.0", resetValue.version)
    }
}

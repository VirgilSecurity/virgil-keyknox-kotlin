/*
 * Copyright (c) 2015-2018, Virgil Security, Inc.
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

package com.virgilsecurity.keyknox.crypto

import com.virgilsecurity.crypto.VirgilCipher
import com.virgilsecurity.crypto.VirgilHash.Algorithm
import com.virgilsecurity.crypto.VirgilSigner
import com.virgilsecurity.keyknox.exception.*
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.sdk.crypto.*
import com.virgilsecurity.sdk.crypto.exceptions.CryptoException
import com.virgilsecurity.sdk.crypto.exceptions.KeyNotSupportedException

class KeyknoxCrypto : KeyknoxCryptoProtocol {

    private val crypto: VirgilCrypto = VirgilCrypto(false)

    @Throws(CryptoException::class)
    override fun encrypt(data: ByteArray, privateKey: PrivateKey,
                         publicKeys: List<PublicKey>): Pair<ByteArray, ByteArray> {
        verifyPrivateKey(privateKey)
        verifyPublicKeys(publicKeys)

        val virgilPrivateKey = privateKey as VirgilPrivateKey

        VirgilSigner(Algorithm.SHA512).use({ signer ->
            VirgilCipher().use({ cipher ->
                val privateKeyData = this.crypto.exportPrivateKey(virgilPrivateKey)
                val signature = signer.sign(data, privateKeyData)

                val customData = cipher.customParams()
                customData.setData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID, virgilPrivateKey.identifier)
                customData.setData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE, signature)

                for (publicKey in publicKeys) {
                    val virgilPublicKey = publicKey as VirgilPublicKey
                    cipher.addKeyRecipient(virgilPublicKey.identifier,
                            this.crypto.exportPublicKey(virgilPublicKey))
                }

                val encryptedData = cipher.encrypt(data, false)
                val meta = cipher.contentInfo

                return Pair(meta, encryptedData)
            })
        })
    }

    @Throws(CryptoException::class)
    override fun decrypt(encryptedKeyknoxValue: EncryptedKeyknoxValue,
                         privateKey: PrivateKey, publicKeys: List<PublicKey>): DecryptedKeyknoxValue {

        if ((encryptedKeyknoxValue.meta == null || encryptedKeyknoxValue.meta.isEmpty()) &&
                (encryptedKeyknoxValue.value == null || encryptedKeyknoxValue.value.isEmpty())) {

            return DecryptedKeyknoxValue(meta = ByteArray(0), value = ByteArray(0),
                    version = encryptedKeyknoxValue.version, keyknoxHash = encryptedKeyknoxValue.keyknoxHash)
        }

        verifyPrivateKey(privateKey)
        verifyPublicKeys(publicKeys)

        val virgilPrivateKey = privateKey as VirgilPrivateKey
        VirgilSigner(Algorithm.SHA512).use({ signer ->
            VirgilCipher().use({ cipher ->

                cipher.contentInfo = encryptedKeyknoxValue.meta
                val privateKeyData = this.crypto.exportPrivateKey(virgilPrivateKey)

                val decryptedData = try {
                    cipher.decryptWithKey(encryptedKeyknoxValue.value,
                            virgilPrivateKey.identifier, privateKeyData)
                } catch (e: Exception) {
                    throw DecryptionFailedException()
                }

                val meta = cipher.contentInfo

                val customParams = cipher.customParams()
                val signedId = customParams.getData(VirgilCrypto.CUSTOM_PARAM_SIGNER_ID)
                val signature = customParams.getData(VirgilCrypto.CUSTOM_PARAM_SIGNATURE)

                val publicKey = publicKeys.find {
                    val id = (it as VirgilPublicKey).identifier
                    if (signedId != null && id != null) {
                        signedId.contentEquals(id)
                    } else {
                        false
                    }
                } as VirgilPublicKey?

                publicKey ?: throw SignerNotFoundException("Signer's Public key not found")

                val publicKeyData = this.crypto.exportPublicKey(publicKey)

                try {
                    signer.verify(decryptedData, signature, publicKeyData)
                } catch (e: Exception) {
                    throw SignatureVerificationException()
                }

                return DecryptedKeyknoxValue(meta, decryptedData!!, encryptedKeyknoxValue.version,
                        encryptedKeyknoxValue.keyknoxHash)
            })
        })
    }

    @Throws(KeyknoxCryptoException::class)
    private fun verifyPrivateKey(privateKey: PrivateKey) {
        if (privateKey !is VirgilPrivateKey) {
            throw KeyNotSupportedException()
        }
    }

    @Throws(KeyknoxCryptoException::class)
    private fun verifyPublicKeys(publicKeys: List<PublicKey>) {
        if (publicKeys.isEmpty()) {
            throw EmptyPublicKeysException("Public keys collection couldn't be empty")
        }
        for (key in publicKeys) {
            if (key !is VirgilPublicKey) {
                throw KeyNotSupportedException()
            }
        }
    }
}
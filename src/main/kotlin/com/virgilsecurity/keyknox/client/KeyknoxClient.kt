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

import com.google.gson.JsonObject
import com.google.gson.JsonParser
import com.virgilsecurity.keyknox.exception.InvalidHashHeaderException
import com.virgilsecurity.keyknox.model.DecryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.EncryptedKeyknoxValue
import com.virgilsecurity.keyknox.model.KeyknoxValue
import com.virgilsecurity.keyknox.utils.base64Decode
import com.virgilsecurity.keyknox.utils.base64Encode
import java.net.URL

/**
 * KeyknoxClientProtocol implementation.
 */
class KeyknoxClient @JvmOverloads constructor(
        val serviceUrl: URL = URL("https://api.virgilsecurity.com"),
        val httpClient: HttpClientProtocol = HttpClient()
) : KeyknoxClientProtocol {

    override fun pushValue(meta: ByteArray, value: ByteArray, previousHash: ByteArray?, token: String): EncryptedKeyknoxValue {
        val url = URL(this.serviceUrl, "keyknox/v1")
        val body = JsonObject()
        body.addProperty("meta", base64Encode(meta))
        body.addProperty("value", base64Encode(value))

        val headers = hashMapOf<String, String>()
        previousHash?.let {
            headers[VIRGIL_KEYKNOX_PREVIOUS_HASH_KEY] = base64Encode(previousHash)
        }
        val response = this.httpClient.send(url, Method.PUT, token, body, headers)
        val keyknoxValue = extractKeyknoxValue(response)

        return EncryptedKeyknoxValue(keyknoxValue)
    }

    override fun pullValue(token: String): EncryptedKeyknoxValue {
        val url = URL(this.serviceUrl, "keyknox/v1")
        val response = this.httpClient.send(url, Method.GET, token)
        val keyknoxValue = extractKeyknoxValue(response)

        return EncryptedKeyknoxValue(keyknoxValue)
    }

    override fun resetValue(token: String): DecryptedKeyknoxValue {
        val url = URL(this.serviceUrl, "keyknox/v1/reset")
        val response = this.httpClient.send(url, Method.POST, token)
        val keyknoxValue = extractKeyknoxValue(response)

        return DecryptedKeyknoxValue(keyknoxValue)
    }

    private fun extractKeyknoxValue(response: Response): KeyknoxValue {
        val body = JsonParser().parse(response.body) as JsonObject
        val meta = base64Decode(body["meta"].asString)
        val value = base64Decode(body["value"].asString)
        val version = body["version"].asString

        val hashStr = response.headers[VIRGIL_KEYKNOX_HASH_KEY]
        if (hashStr == null || hashStr.isBlank()) {
            throw InvalidHashHeaderException()
        }
        val hash = base64Decode(hashStr)

        return KeyknoxValue(meta, value, version, hash)
    }

    companion object {
        const val VIRGIL_KEYKNOX_HASH_KEY = "virgil-keyknox-hash"
        const val VIRGIL_KEYKNOX_PREVIOUS_HASH_KEY = "virgil-keyknox-previous-hash"
    }

}
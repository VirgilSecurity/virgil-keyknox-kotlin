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

package com.virgilsecurity.keyknox.utils

import com.beust.klaxon.Converter
import com.beust.klaxon.JsonObject
import com.beust.klaxon.JsonValue
import com.beust.klaxon.Klaxon
import com.virgilsecurity.keyknox.model.CloudEntries
import com.virgilsecurity.keyknox.model.CloudEntry
import java.util.*

interface Serializer {

    companion object {

        val klaxon: Klaxon by lazy {
            val dateConverter = object : Converter {
                override fun canConvert(cls: Class<*>): Boolean {
                    return cls == Date::class.java
                }

                override fun fromJson(jv: JsonValue): Date {
                    val value = jv.longValue
                    return if (value != null) {
                        Date(value)
                    } else {
                        Date()
                    }
                }

                override fun toJson(value: Any): String {
                    val date = value as Date
                    return date.time.toString()
                }
            }
            val byteArrayConverter = object : Converter {
                override fun canConvert(cls: Class<*>): Boolean {
                    return cls == ByteArray::class.java
                }

                override fun fromJson(jv: JsonValue): ByteArray {
                    val value = jv.string
                    return if (value != null) {
                        base64Decode(value)
                    } else {
                        byteArrayOf()
                    }
                }

                override fun toJson(value: Any): String {
                    val array = value as ByteArray
                    val base64Encoded = base64Encode(array)
                    return "\"$base64Encoded\""
                }
            }

            val cloudEntriesConverter = object : Converter {
                override fun canConvert(cls: Class<*>): Boolean {
                    return cls == CloudEntries::class.java
                }

                override fun fromJson(jv: JsonValue): CloudEntries {
                    val map = mutableMapOf<String, CloudEntry>()
                    jv.obj?.forEach { key, value ->
                        value as JsonObject
                        val entry = klaxon.parseFromJsonObject<CloudEntry>(value)
                        if (entry != null) {
                            if (entry.meta == null) {
                                entry.meta = mutableMapOf()
                            }
                            map[key] = entry
                        }
                    }
                    return CloudEntries(map)
                }

                override fun toJson(value: Any): String {
                    fun joinToString(list: Collection<*>, open: String, close: String) = open + list.joinToString(", ") + close

                    value as Map<*, *>
                    val valueList = arrayListOf<String>()
                    value.entries.forEach { entry ->
                        val jsonValue = klaxon.toJsonString(entry.value as Any)
                        valueList.add("\"${entry.key}\": $jsonValue")
                    }
                    return joinToString(valueList, "{", "}")
                }
            }

            val klaxon = Klaxon().converter(byteArrayConverter).converter(dateConverter).converter(cloudEntriesConverter)
                    .fieldConverter(Base64EncodedArray::class, byteArrayConverter)
                    .fieldConverter(DateAsTimestamp::class, dateConverter)
            klaxon
        }

    }
}

@Target(AnnotationTarget.FIELD)
annotation class Base64EncodedArray

@Target(AnnotationTarget.FIELD)
annotation class DateAsTimestamp

/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package net.tirasa.connid.bundles.okta.utils;

import java.util.Arrays;

public enum CipherAlgorithm {

    SHA("SHA-1"),
    SHA1("SHA-1"),
    SHA256("SHA-256"),
    SHA512("SHA-512"),
    SSHA("S-SHA-1"),
    SSHA1("S-SHA-1"),
    SSHA256("S-SHA-256"),
    SSHA512("S-SHA-512"),
    BCRYPT("BCRYPT");

    private final String algorithm;

    CipherAlgorithm(final String algorithm) {
        this.algorithm = algorithm;
    }

    public String getAlgorithm() {
        return algorithm;
    }

    public static CipherAlgorithm valueOfLabel(final String label) {
        return Arrays.stream(values()).filter(
                item -> item.getAlgorithm().equals(label)).findFirst().orElse(null);
    }
}

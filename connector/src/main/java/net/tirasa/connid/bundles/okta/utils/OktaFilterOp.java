/**
 * Copyright © 2019 ConnId (connid-dev@googlegroups.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.connid.bundles.okta.utils;

public enum OktaFilterOp {

    AND("and"),
    OR("or"),
    EQUALS("eq"),
    CONTAINS("co"),
    STARTS_WITH("sw"),
    ENDS_WITH("ew"),
    IS_PRESENT("pr"),
    GREATER_THAN("gt"),
    GREATER_OR_EQUAL("ge"),
    LESS_THAN("lt"),
    LESS_OR_EQUAL("le");

    private final String stringValue;

    OktaFilterOp(final String stringValue) {
        this.stringValue = stringValue;
    }

    public String getStringValue() {
        return stringValue;
    }

    @Override
    public String toString() {
        return getStringValue();
    }
}

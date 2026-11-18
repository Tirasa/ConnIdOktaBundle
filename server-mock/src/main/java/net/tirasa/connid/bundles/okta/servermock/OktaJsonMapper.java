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
package net.tirasa.connid.bundles.okta.servermock;

import com.fasterxml.jackson.annotation.JsonInclude;
import java.text.SimpleDateFormat;
import java.util.TimeZone;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.json.JsonMapper;

public class OktaJsonMapper extends JsonMapper {

    private static final long serialVersionUID = -8930787585752381161L;

    public static final TimeZone UTC_TIMEZONE = TimeZone.getTimeZone("UTC");

    public static final ThreadLocal<SimpleDateFormat> DATE_FORMAT = ThreadLocal.withInitial(() -> {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(UTC_TIMEZONE);
        return df;
    });

    public OktaJsonMapper() {
        super(JsonMapper.builder().findAndAddModules().
                defaultDateFormat(DATE_FORMAT.get()).
                changeDefaultPropertyInclusion(incl -> incl.
                        withValueInclusion(JsonInclude.Include.NON_NULL).
                        withContentInclusion(JsonInclude.Include.NON_NULL)).
                configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false));
    }
}

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

import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.TimeZone;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.ConnectorException;

public class OktaUtils {

    private static final Log LOG = Log.getLog(OktaUtils.class);

    public static final TimeZone UTC_TIMEZONE = TimeZone.getTimeZone("UTC");

    private static final ThreadLocal<SimpleDateFormat> DATE_FORMAT = ThreadLocal.withInitial(() -> {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(UTC_TIMEZONE);
        return df;
    });

    public static void handleGeneralError(final String message) {
        LOG.error("General error : {0}", message);
        throw new ConnectorException(message);
    }

    public static void handleGeneralError(final String message, final Exception ex) {
        LOG.error(ex, message);
        throw new ConnectorException(message, ex);
    }

    public static void wrapGeneralError(final String message, final Exception ex) {
        LOG.error(ex, message);
        throw ConnectorException.wrap(ex);
    }

    public static String buildSearchQuery(final String attributeName, final String attributeValue) {
        StringBuilder query = new StringBuilder("profile." + attributeName);
        query.append(" eq ");
        query.append("\"");
        query.append(attributeValue);
        query.append("\"");
        return query.toString();
    }

    public static Date convertToDate(final String source) {
        try {
            return new Date(Long.valueOf(source));
        } catch (Exception e) {
            LOG.info(e, "While converting {0} to date", source);
        }
        return null;
    }
}

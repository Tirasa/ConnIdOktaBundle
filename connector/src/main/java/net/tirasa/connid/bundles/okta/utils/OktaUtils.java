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

import com.okta.sdk.resource.client.ApiException;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.exceptions.AlreadyExistsException;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.ConnectorSecurityException;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.exceptions.RetryableException;
import org.identityconnectors.framework.common.exceptions.UnknownUidException;

public final class OktaUtils {

    private static final Log LOG = Log.getLog(OktaUtils.class);

    public static void handleGeneralError(final String message) {
        LOG.error("General error : {0}", message);
        throw new ConnectorException(message);
    }

    public static void handleGeneralError(final String message, final Throwable ex) {
        LOG.error(ex, message);
        throw new ConnectorException(message, ex);
    }

    public static void wrapGeneralError(final String message, final Exception ex) {
        LOG.error(ex, message);
        Exception wrapped = ex;
        if (ex instanceof ApiException) {
            wrapped = wrapResourceException((ApiException) ex);
        }
        throw ConnectorException.wrap(wrapped);
    }

    private static Exception wrapResourceException(final ApiException e) {
        // Error handling based on status code
        // https://developer.okta.com/docs/reference/error-codes/
        switch (e.getCode()) {
            case 400:
                if (e.getResponseBody().contains("E0000001")) {
                    if (e.getResponseBody().contains(
                            "An object with this field already exists in the current organization")) {
                        return new AlreadyExistsException(e);
                    }
                } else {
                    return new InvalidAttributeValueException(e);
                }
                break;

            case 401:
                return new ConnectorSecurityException(e);

            case 403:
                return new PermissionDeniedException(e);

            case 404:
                return new UnknownUidException(e);

            case 429:
                return RetryableException.wrap(e.getMessage(), e);

            default:
        }
        return e;
    }

    public static String buildSearchQuery(final String attributeName, final String attributeValue) {
        StringBuilder query = new StringBuilder("profile." + attributeName);
        query.append(" eq ");
        query.append("\"");
        query.append(attributeValue);
        query.append("\"");
        return query.toString();
    }

    public static OffsetDateTime convertToDate(final long source) {
        return Instant.ofEpochMilli(source).atOffset(ZoneOffset.UTC);
    }

    private OktaUtils() {
        // private constructor for static utility class
    }
}

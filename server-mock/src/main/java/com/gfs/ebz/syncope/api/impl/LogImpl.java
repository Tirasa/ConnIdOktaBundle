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
package com.gfs.ebz.syncope.api.impl;

import io.swagger.api.LogApi;
import io.swagger.model.LogEvent;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.TimeZone;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;

public class LogImpl extends AbstractApi<LogEvent> implements LogApi {

    public static final TimeZone UTC_TIMEZONE = TimeZone.getTimeZone("UTC");

    private static final ThreadLocal<SimpleDateFormat> DATE_FORMAT = ThreadLocal.withInitial(() -> {
        SimpleDateFormat df = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSS'Z'");
        df.setTimeZone(UTC_TIMEZONE);
        return df;
    });

    /**
     * Fetch a list of events from your Okta organization system log.
     *
     * The Okta System Log API provides read access to your organization’s system log. This API provides more
     * functionality than the Events API
     *
     */
    public Response getLogs(final String until,
            final String since,
            final String filter,
            final String q,
            final Integer limit,
            final String sortOrder,
            final String after) {
        return Response.ok().entity(searchEvents(filter, since, limit)).build();
    }

    public List<LogEvent> searchEvents(final String filter, final String since, final Integer limit) {
        List<String> eventTypeNames = filter != null
                ? Arrays.asList(filter.replaceAll("\\\\", "").split(" or ")).stream().map(
                        item -> item.substring(item.indexOf("\"") + 1, item.lastIndexOf("\""))).collect(Collectors.
                                toList())
                : Collections.emptyList();
        Date time = null;
        if (since != null) {
            try {
                time = DATE_FORMAT.get().parse(since);
            } catch (ParseException ex) {
            }
        }
        final Date tokenTS = time;

        if (limit != null) {
            return EVENT_REPOSITORY.entrySet().stream().filter(
                    event -> (tokenTS == null || event.getValue().getPublished().after(tokenTS))
                    && (!eventTypeNames.isEmpty() && eventTypeNames.contains(event.getValue().getEventType()))).map(
                            event -> event.getValue()).limit(limit).collect(Collectors.toList());
        } else {
            return EVENT_REPOSITORY.entrySet().stream().filter(
                    event -> (tokenTS == null || event.getValue().getPublished().after(tokenTS))
                    && (!eventTypeNames.isEmpty() && eventTypeNames.contains(event.getValue().getEventType()))).map(
                            event -> event.getValue()).collect(Collectors.toList());
        }
    }

    @Override
    protected String getNextPage(Integer limit, int after, List<LogEvent> repository) {
        throw new UnsupportedOperationException("Not supported yet.");
    }
}

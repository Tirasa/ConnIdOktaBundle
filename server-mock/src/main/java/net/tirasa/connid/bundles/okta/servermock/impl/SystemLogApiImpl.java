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
package net.tirasa.connid.bundles.okta.servermock.impl;

import static net.tirasa.connid.bundles.okta.servermock.impl.AbstractApiImpl.EVENT_REPOSITORY;

import io.swagger.api.SystemLogApi;
import io.swagger.model.LogEvent;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import javax.ws.rs.core.Response;

public class SystemLogApiImpl implements SystemLogApi {

    @Override
    public Response listLogEvents(
            final Date since,
            final Date until,
            final String filter,
            final String q,
            final Integer limit,
            final String sortOrder,
            final String after) {

        return Response.ok().entity(searchEvents(filter, since, limit)).build();
    }

    private List<LogEvent> searchEvents(final String filter, final Date since, final Integer limit) {
        List<String> eventTypeNames = filter == null
                ? Collections.emptyList()
                : Arrays.asList(filter.replaceAll("\\\\", "").split(" or ")).stream().
                        map(item -> item.substring(item.indexOf("\"") + 1, item.lastIndexOf("\""))).
                        collect(Collectors.toList());

        Stream<LogEvent> found = EVENT_REPOSITORY.entrySet().stream().filter(
                event -> (since == null || event.getKey().after(since))
                && eventTypeNames.contains(event.getValue().getEventType())).
                map(Map.Entry::getValue);
        if (limit != null) {
            found = found.limit(limit);
        }
        return found.collect(Collectors.toList());
    }
}

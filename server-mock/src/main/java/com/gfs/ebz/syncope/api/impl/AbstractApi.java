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

import io.swagger.model.Application;
import io.swagger.model.Group;
import io.swagger.model.LogEvent;
import io.swagger.model.LogTarget;
import io.swagger.model.User;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import javax.ws.rs.core.Context;
import javax.ws.rs.core.UriInfo;
import org.apache.commons.lang3.tuple.Pair;

public abstract class AbstractApi<T extends Object> {

    @Context
    protected UriInfo uriInfo;

    protected static final long DEFAULT_LIMIT = 200;

    protected static final String ERROR_MESSAGE = "Not supported yet.";

    protected static final List<Application> APPLICATION_REPOSITORY =
            Collections.synchronizedList(new ArrayList<>());

    protected static final List<Pair<String, String>> APPLICATION_USER_REPOSITORY =
            Collections.synchronizedList(new ArrayList<>());

    protected static final List<Group> GROUP_REPOSITORY = 
            Collections.synchronizedList(new ArrayList<>());

    protected static final List<Pair<String, String>> GROUP_USER_REPOSITORY =
            Collections.synchronizedList(new ArrayList<>());

    protected static final List<User> USER_REPOSITORY = Collections.synchronizedList(new ArrayList<>());

    protected static final Map<String, List<String>> USER_PASSWORD_REPOSITORY = new ConcurrentHashMap<>();

    protected static final SortedMap<Date, LogEvent> EVENT_REPOSITORY =
            Collections.synchronizedSortedMap(new TreeMap<Date, LogEvent>(Collections.reverseOrder()));

    protected static final Map<String, Set<String>> USER_IDP_REPOSITORY = new ConcurrentHashMap<>();

    protected abstract String getNextPage(final Integer limit, final int after, final List<T> repository);

    protected static void createLogEvent(final String eventTypeName, final String id) {
        LogEvent event = new LogEvent();
        OffsetDateTime utc = OffsetDateTime.now(ZoneOffset.UTC);
        Date date = Date.from(utc.toInstant());
        event.eventType(eventTypeName).target(Arrays.asList(new LogTarget().id(id))).setPublished(date);
        EVENT_REPOSITORY.put(date, event);
    }
}

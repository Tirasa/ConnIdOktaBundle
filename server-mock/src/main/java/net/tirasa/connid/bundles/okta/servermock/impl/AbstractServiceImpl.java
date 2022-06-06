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

import io.swagger.model.Application;
import io.swagger.model.Group;
import io.swagger.model.GroupProfile;
import io.swagger.model.GroupType;
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

public abstract class AbstractServiceImpl {

    @Context
    protected UriInfo uriInfo;

    protected static final long DEFAULT_LIMIT = 200;

    protected static final String EVERYONE = "Everyone";

    protected static final String EVERYONE_ID = "5602b236-6b6c-11ea-bc55-0242ac130003";

    protected static final List<User> USER_REPOSITORY = Collections.synchronizedList(new ArrayList<>());

    protected static final Map<String, List<String>> USER_PASSWORD_REPOSITORY = new ConcurrentHashMap<>();

    protected static final List<Group> GROUP_REPOSITORY =
            Collections.synchronizedList(new ArrayList<Group>(Arrays.asList(
                    new Group().id(EVERYONE_ID).type(GroupType.BUILT_IN).profile(new GroupProfile().name(EVERYONE).description(
                            EVERYONE)))));

    protected static final List<Pair<String, String>> GROUP_USER_REPOSITORY =
            Collections.synchronizedList(new ArrayList<>());

    protected static final Map<String, Set<String>> USER_IDP_REPOSITORY = new ConcurrentHashMap<>();

    protected static final SortedMap<Date, LogEvent> EVENT_REPOSITORY =
            Collections.synchronizedSortedMap(new TreeMap<Date, LogEvent>(Collections.reverseOrder()));

    protected static final List<Application> APPLICATION_REPOSITORY =
            Collections.synchronizedList(new ArrayList<>());

    protected static final List<Pair<String, String>> APPLICATION_USER_REPOSITORY =
            Collections.synchronizedList(new ArrayList<>());

    protected static void createLogEvent(final String eventTypeName, final String id) {
        Date now = Date.from(OffsetDateTime.now(ZoneOffset.UTC).toInstant());

        LogEvent event = new LogEvent();
        event.eventType(eventTypeName).target(Arrays.asList(new LogTarget().id(id))).setPublished(now);
        EVENT_REPOSITORY.put(now, event);
    }
}

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

import io.swagger.api.UserResourcesApi;
import io.swagger.model.Group;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;
import org.springframework.stereotype.Service;

@Service
public class UserResourcesApiImpl extends AbstractApiImpl implements UserResourcesApi {

    @Override
    public Response listAppLinks(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listUserClients(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listUserGroups(final String userId) {
        List<Pair<String, String>> foundUserGroups = GROUP_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(userId, pair.getRight())).
                collect(Collectors.toList());
        List<Group> groups = new ArrayList<>();
        foundUserGroups.forEach(pair -> groups.addAll(GROUP_REPOSITORY.stream().
                filter(group -> StringUtils.equals(group.getId(), pair.getLeft())).
                collect(Collectors.toList())));
        return Response.ok().entity(groups).build();
    }
}

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

import io.swagger.api.GroupApi;
import io.swagger.model.Group;
import io.swagger.model.GroupRule;
import io.swagger.model.User;
import java.lang.reflect.InvocationTargetException;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

public class GroupImpl extends AbstractApi<Group> implements GroupApi {

    @Override
    public Response activateRule(final String ruleId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response addUserToGroup(final String groupId, final String userId) {
        if (GROUP_REPOSITORY.stream().anyMatch(group -> StringUtils.equals(groupId, group.getId()))
                && USER_REPOSITORY.stream().anyMatch(user -> StringUtils.equals(userId, user.getId()))) {
            GROUP_USER_REPOSITORY.add(new ImmutablePair<>(groupId, userId));
            createLogEvent("group.user_membership.add", userId);
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @Override
    public Response createGroup(final Group body) {
        body.setId(UUID.randomUUID().toString());
        body.setCreated(Date.from(Instant.now()));
        body.setLastMembershipUpdated(Date.from(Instant.now()));
        body.setLastUpdated(Date.from(Instant.now()));
        body.setType(body.getType() == null ? "OKTA_GROUP" : null);
        GROUP_REPOSITORY.add(body);
        return Response.status(Response.Status.CREATED).entity(body).build();
    }

    @Override
    public Response createRule(final GroupRule body) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response deactivateRule(final String ruleId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response deleteGroup(final String groupId) {
        return GROUP_REPOSITORY.removeIf(group -> StringUtils.equals(groupId, group.getId())) ? Response.
                noContent().build() : Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response deleteRule(final String ruleId, final Boolean removeUsers) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response getGroup(final String groupId, final String expand) {
        Optional<Group> found = GROUP_REPOSITORY.stream()
                .filter(group -> StringUtils.equals(groupId, group.getId()))
                .findAny();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response getRule(final String ruleId, final String expand) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response listGroupUsers(
            final String groupId,
            final String after,
            final Integer limit,
            final String managedBy) {
        List<Pair<String, String>> foundGroupUsers = GROUP_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(groupId, pair.getLeft())).
                collect(Collectors.toList());
        List<User> users = new ArrayList<>();
        foundGroupUsers.forEach(pair -> users.addAll(USER_REPOSITORY.stream().
                filter(user -> StringUtils.equals(user.getId(), pair.getRight())).
                collect(Collectors.toList())));
        return Response.ok().entity(users.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                collect(Collectors.toList())).build();
    }

    @Override
    public Response listGroups(
            final String q,
            final String filter,
            final String after,
            final Integer limit,
            final String expand) {
        if (filter != null) {
            List<Group> groups = searchGroup(filter);
            return Response.ok().entity(groups).build();
        }

        if (after != null) {
            Optional<Group> found = GROUP_REPOSITORY.stream()
                    .filter(group -> StringUtils.equals(after, group.getId()))
                    .findAny();
            if (found.isPresent()) {
                int lastIndexOf = GROUP_REPOSITORY.lastIndexOf(found.get());
                return Response.ok().entity(GROUP_REPOSITORY.stream().
                        skip(lastIndexOf).
                        limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                        filter(q == null ? group -> true : group -> group.getProfile().getName().contains(q)).
                        collect(Collectors.toList())).header("link", getNextPage(limit, lastIndexOf, GROUP_REPOSITORY)).
                        build();
            }
        }
        return Response.ok().entity(GROUP_REPOSITORY.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                filter(q == null ? group -> true : group -> group.getProfile().getName().contains(q)).
                collect(Collectors.toList())).header("link", getNextPage(limit, 0, GROUP_REPOSITORY)).
                build();
    }

    @Override
    public Response listRules(final Integer limit, final String after, final String expand) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response removeGroupUser(final String groupId, final String userId) {
        createLogEvent("group.user_membership.remove", userId);
        if (EVERYONE_ID.equals(groupId)) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }
        return GROUP_USER_REPOSITORY.removeIf(pair
                -> StringUtils.equals(pair.getLeft(), groupId) && StringUtils.equals(pair.getRight(), userId))
                ? Response.noContent().build()
                : Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response updateGroup(final Group body, final String groupId) {
        Optional<Group> found = GROUP_REPOSITORY.stream()
                .filter(group -> StringUtils.equals(groupId, group.getId()))
                .findAny();
        if (found.isPresent()) {
            body.setId(found.get().getId());
            body.setCreated(found.get().getCreated());
            body.setLastMembershipUpdated(found.get().getLastMembershipUpdated());
            GROUP_REPOSITORY.remove(found.get());
            GROUP_REPOSITORY.add(body);
            body.setLastUpdated(Date.from(Instant.now()));
            return Response.ok().entity(body).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response updateRule(final GroupRule body, final String ruleId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    private List<Group> searchGroup(final String filter) {
        String[] split = filter.split(" ");
        String attribute = split[0];
        String value = StringUtils.substringBetween(filter, "\"", "\"");

        return GROUP_REPOSITORY.stream().
                filter(group -> {
                    try {
                        return StringUtils.equals(value, BeanUtils.getProperty(group, attribute));
                    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                        return false;
                    }
                }).collect(Collectors.toList());
    }

    @Override
    protected String getNextPage(Integer limit, int after, List<Group> repository) {
        if (limit != null && limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/groups?after="
                    + repository.get(limit + after).getId() + "&limit=" + limit + ">; rel=\"next\"";
        } else {
            return null;
        }
    }
}

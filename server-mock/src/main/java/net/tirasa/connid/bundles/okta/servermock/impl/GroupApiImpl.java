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

import io.swagger.api.GroupApi;
import io.swagger.model.AssignGroupOwnerRequestBody;
import io.swagger.model.Group;
import io.swagger.model.GroupRule;
import io.swagger.model.GroupType;
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
import org.apache.commons.lang3.tuple.Pair;

public class GroupApiImpl extends AbstractApiImpl implements GroupApi {

    @Override
    public Response activateGroupRule(final String ruleId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response assignUserToGroup(final String groupId, final String userId) {
        if (EVERYONE_ID.equals(groupId)) {
            // Okta Groups API returns 501 error when adding a user to default Everyone group
            return Response.status(Response.Status.NOT_IMPLEMENTED).build();
        }
        if (GROUP_REPOSITORY.stream().anyMatch(group -> StringUtils.equals(groupId, group.getId()))
                && USER_REPOSITORY.stream().anyMatch(user -> StringUtils.equals(userId, user.getId()))) {
            GROUP_USER_REPOSITORY.add(Pair.of(groupId, userId));
            createLogEvent("group.user_membership.add", userId);
            return Response.ok().build();
        }

        return Response.status(Response.Status.BAD_REQUEST).build();
    }

    @Override
    public Response createGroup(final Group body) {
        if (body.getId() == null) {
            body.setId(UUID.randomUUID().toString());
        }
        if (body.getType() == null) {
            body.setType(GroupType.OKTA_GROUP);
        }
        body.setCreated(Date.from(Instant.now()));
        body.setLastMembershipUpdated(Date.from(Instant.now()));
        body.setLastUpdated(Date.from(Instant.now()));
        GROUP_REPOSITORY.add(body);
        return Response.status(Response.Status.CREATED).entity(body).build();
    }

    @Override
    public Response createGroupRule(final GroupRule body) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deactivateGroupRule(final String ruleId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deleteGroup(final String groupId) {
        return GROUP_REPOSITORY.removeIf(group -> StringUtils.equals(groupId, group.getId())) ? Response.
                noContent().build() : Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response deleteGroupRule(final String ruleId, final Boolean removeUsers) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getGroup(final String groupId) {
        Optional<Group> found = GROUP_REPOSITORY.stream()
                .filter(group -> StringUtils.equals(groupId, group.getId()))
                .findAny();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response getGroupRule(final String ruleId, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listAssignedApplicationsForGroup(final String groupId, final String after, final Integer limit) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGroupRules(final Integer limit, final String after, final String search, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGroupUsers(final String groupId, final String after, final Integer limit) {
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

    private String nextPage(final long limit, final int after, final List<Group> repository) {
        if (limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/groups?after="
                    + repository.get((int) (limit + after)).getId()
                    + "&limit=" + limit + ">; rel=\"next\"";
        }

        return "<" + uriInfo.getBaseUri().toString() + "api/v1/groups?after="
                + repository.get(repository.size() - 1).getId()
                + "&limit=" + limit + ">; rel=\"self\"";
    }

    @Override
    public Response listGroups(
            final String q,
            final String filter,
            final String after,
            final Integer limit,
            final String expand,
            final String search,
            final String sortBy,
            final String sortOrder) {

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
                        collect(Collectors.toList())).header("link", nextPage(limit, lastIndexOf, GROUP_REPOSITORY)).
                        build();
            }
        }

        long actualLimit = limit == null || limit < 0 ? DEFAULT_LIMIT : limit.longValue();
        return Response.ok().entity(GROUP_REPOSITORY.stream().
                limit(actualLimit).
                filter(q == null ? group -> true : group -> group.getProfile().getName().contains(q)).
                collect(Collectors.toList())).header("link", nextPage(limit, 0, GROUP_REPOSITORY)).
                build();
    }

    @Override
    public Response unassignUserFromGroup(final String groupId, final String userId) {
        createLogEvent("group.user_membership.remove", userId);
        if (EVERYONE_ID.equals(groupId)) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }
        return GROUP_USER_REPOSITORY.removeIf(pair -> StringUtils.equals(pair.getLeft(), groupId)
                && StringUtils.equals(pair.getRight(), userId))
                ? Response.noContent().build()
                : Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response replaceGroup(final Group body, final String groupId) {
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
        }

        return Response.status(Response.Status.NOT_FOUND).build();
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
    public Response assignGroupOwner(final AssignGroupOwnerRequestBody body, final String groupId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deleteGroupOwner(final String groupId, final String ownerId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGroupOwners(
            final String groupId, final String filter, final String after, final Integer limit) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response replaceGroupRule(final GroupRule body, final String ruleId) {
        return Response.ok().entity("magic!").build();
    }
}

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
import io.swagger.model.AssignRoleRequest;
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
import org.apache.commons.lang3.tuple.ImmutablePair;
import org.apache.commons.lang3.tuple.Pair;

/**
 * Okta API
 *
 * <p>
 * Allows customers to easily access the Okta API
 *
 */
public class GroupApiServiceImpl extends AbstractServiceImpl implements GroupApi {

    /**
     * Activate a group Rule
     *
     * Activates a specific group rule by id from your organization
     *
     */
    @Override
    public Response activateGroupRule(String ruleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add App Instance Target to App Administrator Role given to a Group
     *
     * Add App Instance Target to App Administrator Role given to a Group
     *
     */
    @Override
    public Response addApplicationInstanceTargetToAppAdminRoleGivenToGroup(String groupId, String roleId, String appName,
            String applicationId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response addApplicationTargetToAdminRoleGivenToGroup(String groupId, String roleId, String appName) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response addGroupTargetToGroupAdministratorRoleForGroup(String groupId, String roleId, String targetGroupId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add User to Group
     *
     * Adds a user to a group with &#x27;OKTA_GROUP&#x27; type.
     *
     */
    @Override
    public Response addUserToGroup(String groupId, String userId) {
        if (GROUP_REPOSITORY.stream().anyMatch(group -> StringUtils.equals(groupId, group.getId()))
                && USER_REPOSITORY.stream().anyMatch(user -> StringUtils.equals(userId, user.getId()))) {
            GROUP_USER_REPOSITORY.add(Pair.of(groupId, userId));
            createLogEvent("group.user_membership.add", userId);
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @Override
    public Response assignRoleToGroup(AssignRoleRequest body, String groupId, String disableNotifications) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add Group
     *
     * Adds a new group with &#x60;OKTA_GROUP&#x60; type to your organization.
     *
     */
    @Override
    public Response createGroup(Group body) {
        if (body.getId() == null) {
            body.setId(UUID.randomUUID().toString());
        }
        body.setCreated(Date.from(Instant.now()));
        body.setLastMembershipUpdated(Date.from(Instant.now()));
        body.setLastUpdated(Date.from(Instant.now()));
        body.setType(body.getType() == null ? GroupType.OKTA_GROUP : null);
        GROUP_REPOSITORY.add(body);
        return Response.status(Response.Status.CREATED).entity(body).build();
    }

    /**
     * Create Group Rule
     *
     * Creates a group rule to dynamically add users to the specified group if they match the condition
     *
     */
    @Override
    public Response createGroupRule(GroupRule body) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Deactivate a group Rule
     *
     * Deactivates a specific group rule by id from your organization
     *
     */
    @Override
    public Response deactivateGroupRule(String ruleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Remove Group
     *
     * Removes a group with &#x60;OKTA_GROUP&#x60; type from your organization.
     *
     */
    @Override
    public Response deleteGroup(String groupId) {
        return GROUP_REPOSITORY.removeIf(group -> StringUtils.equals(groupId, group.getId())) ? Response.
                noContent().build() : Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * Delete a group Rule
     *
     * Removes a specific group rule by id from your organization
     *
     */
    @Override
    public Response deleteGroupRule(String ruleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Group Rules
     *
     * Lists all group rules for your organization.
     *
     */
    @Override
    public Response getGroup(String groupId) {
        Optional<Group> found = GROUP_REPOSITORY.stream()
                .filter(group -> StringUtils.equals(groupId, group.getId()))
                .findAny();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Get Group Rule
     *
     * Fetches a specific group rule by id from your organization
     *
     */
    @Override
    public Response getGroupRule(String ruleId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getRole(String groupId, String roleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listApplicationTargetsForApplicationAdministratorRoleForGroup(String groupId, String roleId,
            String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Assigned Applications
     *
     * Enumerates all applications that are assigned to a group.
     *
     */
    @Override
    public Response listAssignedApplicationsForGroup(String groupId, String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGroupAssignedRoles(String groupId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Group Rules
     *
     * Lists all group rules for your organization.
     *
     */
    @Override
    public Response listGroupRules(Integer limit, String after, String search, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGroupTargetsForGroupRole(String groupId, String roleId, String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Group Members
     *
     * Enumerates all users that are a member of a group.
     *
     */
    @Override
    public Response listGroupUsers(String groupId, String after, Integer limit) {
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

    /**
     * List Groups
     *
     * Enumerates groups in your organization with pagination. A subset of groups can be returned that match a supported
     * filter expression or query.
     *
     */
    @Override
    public Response listGroups(String q, String filter, String after, Integer limit, String expand) {
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

    /**
     * Remove App Instance Target to App Administrator Role given to a Group
     *
     * Remove App Instance Target to App Administrator Role given to a Group
     *
     */
    @Override
    public Response removeApplicationTargetFromAdministratorRoleGivenToGroup(String groupId, String roleId,
            String appName, String applicationId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeApplicationTargetFromApplicationAdministratorRoleGivenToGroup(String groupId, String roleId,
            String appName) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeGroupTargetFromGroupAdministratorRoleGivenToGroup(String groupId, String roleId,
            String targetGroupId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeRoleFromGroup(String groupId, String roleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Remove User from Group
     *
     * Removes a user from a group with &#x27;OKTA_GROUP&#x27; type.
     *
     */
    @Override
    public Response removeUserFromGroup(String groupId, String userId) {
        createLogEvent("group.user_membership.remove", userId);
        if (EVERYONE_ID.equals(groupId)) {
            return Response.status(Response.Status.FORBIDDEN).build();
        }
        return GROUP_USER_REPOSITORY.removeIf(pair
                -> StringUtils.equals(pair.getLeft(), groupId) && StringUtils.equals(pair.getRight(), userId))
                ? Response.noContent().build()
                : Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * Update Group
     *
     * Updates the profile for a group with &#x60;OKTA_GROUP&#x60; type from your organization.
     *
     */
    @Override
    public Response updateGroup(Group body, String groupId) {
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
    public Response updateGroupRule(GroupRule body, String ruleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
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

    private String getNextPage(Integer limit, int after, List<Group> repository) {
        if (limit != null && limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/groups?after="
                    + repository.get(limit + after).getId() + "&limit=" + limit + ">; rel=\"next\"";
        } else {
            return null;
        }
    }
}

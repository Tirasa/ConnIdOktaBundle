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

import io.swagger.api.UserApi;
import io.swagger.model.ChangePasswordRequest;
import io.swagger.model.CreateUserRequest;
import io.swagger.model.Group;
import io.swagger.model.IdentityProvider;
import io.swagger.model.IdentityProviderType;
import io.swagger.model.PasswordCredential;
import io.swagger.model.UpdateUserRequest;
import io.swagger.model.User;
import io.swagger.model.UserCredentials;
import io.swagger.model.UserNextLogin;
import io.swagger.model.UserProfile;
import io.swagger.model.UserStatus;
import java.lang.reflect.InvocationTargetException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

public class UserApiImpl extends AbstractApiImpl implements UserApi {

    @Override
    public Response activateUser(final String userId, final Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && found.get().getStatus() != UserStatus.ACTIVE) {
            found.get().setStatus(UserStatus.ACTIVE);
            found.get().setActivated(new Date());
            found.get().setLastUpdated(new Date());
            found.get().setStatusChanged(new Date());
            createLogEvent("user.lifecycle.activate", userId);
            return Response.ok().entity(found.get()).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response changePassword(
            final ChangePasswordRequest changePasswordRequest,
            final String userId,
            final Boolean strict) {

        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && (found.get().getStatus().equals(UserStatus.ACTIVE)
                || found.get().getStatus().equals(UserStatus.PASSWORD_EXPIRED)
                || found.get().getStatus().equals(UserStatus.STAGED)
                || found.get().getStatus().equals(UserStatus.RECOVERY))) {
            if (USER_PASSWORD_REPOSITORY.get(userId).isEmpty()
                    || changePasswordRequest.getOldPassword().getValue().
                            equals(USER_PASSWORD_REPOSITORY.get(userId).get(
                                    USER_PASSWORD_REPOSITORY.get(userId).size() - 1))) {
                if (!USER_PASSWORD_REPOSITORY.get(userId).
                        contains(changePasswordRequest.getNewPassword().getValue())) {
                    USER_PASSWORD_REPOSITORY.get(userId).add(changePasswordRequest.getNewPassword().getValue());
                    found.get().setLastUpdated(new Date());
                    found.get().setPasswordChanged(new Date());
                    createLogEvent("user.account.update_password", userId);
                    return Response.ok().entity(found.get().getCredentials()).build();
                }

                return Response.status(Response.Status.FORBIDDEN).
                        header("Okta-Request-Id", "E0000014").
                        entity(buildErrorResponse("000123",
                                "Password requirements were not met. "
                                + "Password requirements: at least 8 characters, a lowercase letter, "
                                + "an uppercase letter, a number, "
                                + "no parts of your username. "
                                + "Your password cannot be any of your last 4 passwords.")).build();
            }

            return Response.status(Response.Status.FORBIDDEN).
                    header("Okta-Request-Id", "E0000014").
                    entity(buildErrorResponse("000123", "Old Password is not correct")).build();
        }

        return Response.status(Response.Status.NOT_FOUND).
                header("Okta-Request-Id", "E0000014").
                entity(buildErrorResponse("000123", "User not found or status not valid")).build();
    }

    @Override
    public Response changeRecoveryQuestion(final UserCredentials body, final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response createUser(
            final CreateUserRequest req,
            final Boolean activate,
            final Boolean provider,
            final UserNextLogin nextLogin) {

        User user = new User();
        user.setCredentials(req.getCredentials());
        user.setProfile(Optional.ofNullable(req.getProfile()).orElseGet(() -> new UserProfile()));
        user.setType(req.getType());

        if (Boolean.TRUE.equals(activate)) {
            user.setStatus(UserStatus.ACTIVE);
            user.setActivated(new Date());
            if (nextLogin != null && UserNextLogin.CHANGEPASSWORD.equals(nextLogin)) {
                PasswordCredential expired = new PasswordCredential();
                expired.setValue("EXPIRED");
                user.getCredentials().setPassword(expired);
            }
        } else {
            user.setStatus(UserStatus.STAGED);
        }
        user.setId(UUID.randomUUID().toString());
        user.setCreated(new Date());
        user.setLastUpdated(new Date());
        user.setStatusChanged(new Date());
        List<String> passwords = new ArrayList<>();
        if (user.getCredentials() != null) {
            user.setPasswordChanged(new Date());
            if (user.getCredentials().getPassword().getHash() != null) {
                user.getCredentials().getPassword().
                        setValue(user.getCredentials().getPassword().getHash().getValue());
                user.getCredentials().getPassword().setHash(null);
            }
            passwords.add(user.getCredentials().getPassword().getValue());
            user.getCredentials().setPassword(null);
        }
        USER_PASSWORD_REPOSITORY.put(user.getId(), passwords);

        Optional.ofNullable(req.getGroupIds()).
                ifPresent(groupIds -> groupIds.stream().filter(g -> !EVERYONE_ID.equals(g)).
                forEach(g -> GROUP_USER_REPOSITORY.add(Pair.of(g, user.getId()))));
        GROUP_USER_REPOSITORY.add(Pair.of(EVERYONE_ID, user.getId()));

        USER_IDP_REPOSITORY.put(user.getId(), new HashSet<>(Arrays.asList("6e77c44bf27d4750a10f1489ce4100df")));
        USER_REPOSITORY.add(user);
        createLogEvent("user.lifecycle.create", user.getId());
        return Response.status(Response.Status.CREATED).entity(user).build();
    }

    @Override
    public Response deleteUser(final String userId, final Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (!found.isPresent()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        } else if (found.get().getStatus() == UserStatus.DEPROVISIONED) {
            USER_REPOSITORY.remove(found.get());
            USER_PASSWORD_REPOSITORY.remove(userId);
            createLogEvent("user.lifecycle.delete", userId);
            return Response.noContent().build();
        }

        found.get().setStatus(UserStatus.DEPROVISIONED);
        found.get().setLastUpdated(new Date());
        found.get().setStatusChanged(new Date());
        createLogEvent("user.lifecycle.deactivate", userId);
        return Response.ok().entity(found.get()).build();
    }

    @Override
    public Response deactivateUser(final String userId, final Boolean sendEmail) {
        return USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId())
                && user.getStatus() != UserStatus.DEPROVISIONED).
                map(user -> {
                    user.setStatus(UserStatus.DEPROVISIONED);
                    user.setLastUpdated(new Date());
                    user.setStatusChanged(new Date());
                    createLogEvent("user.lifecycle.deactivate", userId);
                    return Response.ok().entity(user).build();
                }).findFirst().
                orElse(Response.status(Response.Status.NOT_FOUND).build());
    }

    @Override
    public Response expirePassword(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response expirePasswordAndGetTemporaryPassword(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getRefreshTokenForUserAndClient(
            final String userId,
            final String clientId,
            final String tokenId,
            final String expand,
            final Integer limit,
            final String after) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getUser(final String userId) {
        return USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId())
                || StringUtils.equals(userId, user.getProfile().getLogin()))
                .findFirst()
                .map(found -> Response.ok().entity(found).build())
                .orElseGet(() -> Response.status(Response.Status.NOT_FOUND).build());
    }

    @Override
    public Response getUserGrant(final String userId, final String grantId, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listAppLinks(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGrantsForUserAndClient(
            final String userId,
            final String clientId,
            final String expand,
            final String after,
            final Integer limit) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listRefreshTokensForUserAndClient(
            final String userId,
            final String clientId,
            final String expand,
            final String after,
            final Integer limit) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listUserClients(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listUserGrants(
            final String userId,
            final String scopeId,
            final String expand,
            final String after,
            final Integer limit) {

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

    @Override
    public Response listUserIdentityProviders(final String userId) {
        Set<String> userIdps = USER_IDP_REPOSITORY.get(userId);
        if (userIdps != null) {
            return Response.ok(
                    userIdps.isEmpty()
                    ? Collections.emptyList()
                    : userIdps.stream().map(item -> new IdentityProvider().
                    id("6e77c44bf27d4750a10f1489ce4100df").
                    type(IdentityProviderType.SAML2).
                    name("CAS 5 IDP")).collect(Collectors.toList())).build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    private String nextPage(final long limit, final int after, final List<User> repository) {
        if (limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/users?after="
                    + repository.get((int) limit + after).getId()
                    + "&limit=" + limit + ">; rel=\"next\"";
        }

        StringBuilder queryString = new StringBuilder().append('?');
        if (!repository.isEmpty()) {
            queryString.append("after=").append(repository.get(repository.size() - 1).getId()).append('&');
        }
        queryString.append("limit=").append(limit).append(">; rel=\"self\"");

        return "<" + uriInfo.getBaseUri().toString() + "api/v1/users?" + queryString.toString();
    }

    @Override
    public Response listUsers(
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String search,
            final String sortBy,
            final String sortOrder) {

        if (search != null) {
            return Response.ok().
                    entity(searchUsers(USER_REPOSITORY, search)).
                    header("link", nextPage(limit, 0, USER_REPOSITORY)).
                    build();
        }
        if (filter != null) {
            return Response.ok().
                    entity(searchUsers(USER_REPOSITORY, filter)).
                    header("link", nextPage(limit, 0, USER_REPOSITORY)).
                    build();
        }

        Predicate<? super User> predicate = q == null
                ? user -> user.getStatus() != UserStatus.DEPROVISIONED
                : user -> user.getStatus() != UserStatus.DEPROVISIONED
                && (user.getProfile().getFirstName().contains(q)
                || user.getProfile().getLastName().contains(q)
                || user.getProfile().getEmail().contains(q));

        if (after != null) {
            Optional<User> found = USER_REPOSITORY.stream().
                    filter(group -> StringUtils.equals(after, group.getId())).
                    findFirst();
            if (found.isPresent()) {
                int lastIndexOf = USER_REPOSITORY.lastIndexOf(found.get());
                return Response.ok().entity(USER_REPOSITORY.stream().
                        skip(lastIndexOf).
                        limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                        filter(predicate).
                        collect(Collectors.toList())).
                        header("link", nextPage(limit, lastIndexOf, USER_REPOSITORY)).
                        build();
            }
        }

        long actualLimit = limit == null || limit < 0 ? DEFAULT_LIMIT : limit.longValue();
        return Response.ok().entity(USER_REPOSITORY.stream().
                limit(actualLimit).
                filter(predicate).
                filter(user -> user.getStatus() != UserStatus.DEPROVISIONED).
                collect(Collectors.toList())).header("link", nextPage(limit, 0, USER_REPOSITORY)).
                build();
    }

    @Override
    public Response reactivateUser(final String userId, final Boolean sendEmail) {
        return USER_REPOSITORY.stream().
                filter(user -> StringUtils.equals(userId, user.getId())).
                findFirst().
                map(user -> {
                    if (user.getStatus() == UserStatus.PROVISIONED) {
                        user.setStatus(UserStatus.RECOVERY);
                        user.setStatusChanged(new Date());
                        createLogEvent("user.lifecycle.reactivate", userId);
                        return Response.ok().entity("{}").build();
                    } else {
                        return Response.status(Response.Status.FORBIDDEN).build();
                    }
                }).
                orElseGet(() -> Response.status(Response.Status.NOT_FOUND).build());
    }

    @Override
    public Response resetFactors(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response resetPassword(final String userId, final Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent()) {
            User user = found.get();
            if (user.getStatus() == UserStatus.ACTIVE) {
                found.get().setStatus(UserStatus.RECOVERY);
                found.get().setStatusChanged(new Date());
                createLogEvent("user.lifecycle.reset_password", userId);
                return Response.ok().entity("{}").build();
            }

            return Response.status(Response.Status.FORBIDDEN).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response revokeGrantsForUserAndClient(final String userId, final String clientId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeTokenForUserAndClient(final String userId, final String clientId, final String tokenId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeTokensForUserAndClient(final String userId, final String clientId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeUserGrant(final String userId, final String grantId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeUserGrants(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response setLinkedObjectForUser(
            final String associatedUserId,
            final String primaryRelationshipName,
            final String primaryUserId) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response suspendUser(final String userId) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && found.get().getStatus() == UserStatus.ACTIVE) {
            found.get().setStatus(UserStatus.SUSPENDED);
            found.get().setStatusChanged(new Date());
            createLogEvent("user.lifecycle.suspend", userId);
            return Response.ok().entity(found.get()).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response unlockUser(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response unsuspendUser(String userId) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && found.get().getStatus() == UserStatus.SUSPENDED) {
            found.get().setStatus(UserStatus.ACTIVE);
            found.get().setStatusChanged(new Date());
            createLogEvent("user.lifecycle.unsuspend", userId);
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response updateUser(final UpdateUserRequest req, final String userId, final Boolean strict) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(u -> StringUtils.equals(userId, u.getId()))
                .findFirst();
        if (found.isPresent()) {
            User user = found.get();
            user.setLastUpdated(new Date());
            Optional.ofNullable(req.getProfile()).ifPresent(user::setProfile);

            if (req.getCredentials() != null && req.getCredentials().getPassword() != null) {
                if (req.getCredentials().getPassword().getValue() != null
                        && !USER_PASSWORD_REPOSITORY.get(userId).
                                contains(req.getCredentials().getPassword().getValue())) {

                    USER_PASSWORD_REPOSITORY.get(userId).add(req.getCredentials().getPassword().getValue());
                } else if (req.getCredentials().getPassword().getHash() != null
                        && !USER_PASSWORD_REPOSITORY.get(userId).
                                contains(req.getCredentials().getPassword().getHash().getValue())) {

                    USER_PASSWORD_REPOSITORY.get(userId).add(req.getCredentials().getPassword().getHash().getValue());
                } else {
                    return Response.status(Response.Status.CONFLICT).build();
                }
            }

            createLogEvent("user.lifecycle.update", userId);
            return Response.ok().entity(user).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response replaceUser(final UpdateUserRequest body, final String userId, final Boolean strict) {
        return updateUser(body, userId, strict);
    }

    private Map<String, Object> buildErrorResponse(final String errorId, final String message) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("errorCode", "E0000014");
        error.put("errorSummary", "Update of credentials failed");
        error.put("errorLink", "E0000014");
        error.put("errorId", errorId);
        error.put("errorCauses", Collections.singletonList(Collections.singletonMap("errorSummary", message)));
        return error;
    }

    public List<User> searchUsers(final List<User> users, final String filter) {
        String[] split = filter.split(" ");
        return users.stream().
                filter(user -> {
                    try {
                        return user.getStatus() != UserStatus.DEPROVISIONED
                                && StringUtils.equals(
                                        StringUtils.remove(split[2], "\""),
                                        BeanUtils.getProperty(user, split[0]));
                    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                        return false;
                    }
                }).collect(Collectors.toList());
    }

    @Override
    public Response deleteLinkedObjectForUser(final String userId, final String relationshipName) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response forgotPassword(final String userId, final Boolean sendEmail) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response forgotPasswordSetNewPassword(
            final UserCredentials body, final String userId, final Boolean sendEmail) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listLinkedObjectsForUser(
            final String userId, final String relationshipName, final String after, final Integer limit) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeUserSessions(final String userId, final Boolean oauthTokens) {
        return Response.ok().entity("magic!").build();
    }
}

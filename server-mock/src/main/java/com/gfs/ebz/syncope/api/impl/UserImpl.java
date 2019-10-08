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

import io.swagger.api.UserApi;
import io.swagger.model.ChangePasswordRequest;
import io.swagger.model.Group;
import io.swagger.model.PasswordCredential;
import io.swagger.model.Role;
import io.swagger.model.User;
import io.swagger.model.UserCredentials;
import io.swagger.model.UserStatus;
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

public class UserImpl extends AbstractApi<User> implements UserApi {

    @Override
    public Response activateUser(final String userId, final Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findAny();
        if (found.isPresent() && found.get().getStatus() != UserStatus.ACTIVE) {
            found.get().setStatus(UserStatus.ACTIVE);
            found.get().setActivated(Date.from(Instant.now()));
            found.get().setLastUpdated(Date.from(Instant.now()));
            found.get().setStatusChanged(Date.from(Instant.now()));
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response addGroupTargetToRole(final String userId, final String roleId, final String groupId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response addRoleToUser(final Role role, final String userId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response changePassword(
            final ChangePasswordRequest changePasswordRequest,
            final String userId,
            final Boolean strict) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findAny();
        if (found.isPresent() && (found.get().getStatus().equals(UserStatus.ACTIVE)
                || found.get().getStatus().equals(UserStatus.PASSWORD_EXPIRED)
                || found.get().getStatus().equals(UserStatus.STAGED)
                || found.get().getStatus().equals(UserStatus.RECOVERY))
                && changePasswordRequest.getOldPassword().getValue().equals(USER_PASSWORD_REPOSITORY.
                        get(userId).get(USER_PASSWORD_REPOSITORY.get(userId).size() - 1))
                && !USER_PASSWORD_REPOSITORY.get(userId).contains(changePasswordRequest.
                        getNewPassword().getValue())) {
            USER_PASSWORD_REPOSITORY.get(userId).add(changePasswordRequest.getNewPassword().getValue());
            found.get().setLastUpdated(Date.from(Instant.now()));
            found.get().setPasswordChanged(Date.from(Instant.now()));
            return Response.ok().entity(found.get().getCredentials()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response changeRecoveryQuestion(final UserCredentials userCredentials, final String userId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response createUser(
            final User body,
            final Boolean activate,
            final Boolean provider,
            final String nextLogin) {
        if (body.getId() == null) {
            if (Boolean.TRUE.equals(activate)) {
                body.setStatus(UserStatus.ACTIVE);
                body.setActivated(Date.from(Instant.now()));
                if (!StringUtils.isEmpty(nextLogin) && StringUtils.equals(nextLogin, "changePassword")) {
                    PasswordCredential expired = new PasswordCredential();
                    expired.setValue("EXPIRED");
                    body.getCredentials().setPassword(expired);
                }
            } else {
                body.setStatus(UserStatus.SUSPENDED);
            }
            body.setId(UUID.randomUUID().toString());
            body.setCreated(Date.from(Instant.now()));
            body.setLastUpdated(Date.from(Instant.now()));
            body.setStatusChanged(Date.from(Instant.now()));
            if (body.getCredentials() != null) {
                body.setPasswordChanged(Date.from(Instant.now()));
                if (body.getCredentials().getPassword().getHash() != null) {
                    body.getCredentials().getPassword().
                            setValue(body.getCredentials().getPassword().getHash().getValue());
                    body.getCredentials().getPassword().setHash(null);
                }
                List<String> passwords = new ArrayList<>();
                passwords.add(body.getCredentials().getPassword().getValue());
                body.getCredentials().setPassword(null);
                USER_PASSWORD_REPOSITORY.put(body.getId(), passwords);
            }

            USER_REPOSITORY.add(body);
            return Response.status(Response.Status.CREATED).entity(body).build();
        } else {
            return updateUser(body, body.getId(), false);
        }
    }

    @Override
    public Response deactivateOrDeleteUser(final String userId, final Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findAny();
        if (!found.isPresent()) {
            return Response.status(Response.Status.NOT_FOUND).build();
        } else if (found.get().getStatus() == UserStatus.DEPROVISIONED) {
            USER_REPOSITORY.remove(found.get());
            USER_PASSWORD_REPOSITORY.remove(userId);
            return Response.noContent().build();
        } else {
            found.get().setStatus(UserStatus.DEPROVISIONED);
            found.get().setLastUpdated(Date.from(Instant.now()));
            found.get().setStatusChanged(Date.from(Instant.now()));
            return Response.ok().entity(found.get()).build();
        }
    }

    @Override
    public Response deactivateUser(final String userId, final Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findAny();
        if (found.isPresent() && found.get().getStatus() != UserStatus.DEPROVISIONED) {
            found.get().setStatus(UserStatus.DEPROVISIONED);
            found.get().setLastUpdated(Date.from(Instant.now()));
            found.get().setStatusChanged(Date.from(Instant.now()));
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response endAllUserSessions(final String userId, final Boolean oauthTokens) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response expirePassword(final String userId, final Boolean tempPassword) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response forgotPassword(
            final String userId,
            final UserCredentials userCredentials,
            final Boolean sendEmail) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response getUser(final String userId) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId())
                || StringUtils.equals(userId, user.getProfile().getLogin()))
                .findAny();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response listAppLinks(final String userId, final Boolean showAll) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response listAssignedRoles(final String userId, final String expand) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response listGroupTargetsForRole(
            final String userId,
            final String roleId,
            final String after,
            final Integer limit) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response listUserGroups(final String userId, final String after, final Integer limit) {
        List<Pair<String, String>> foundUserGroups = GROUP_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(userId, pair.getRight())).
                collect(Collectors.toList());
        List<Group> groups = new ArrayList<>();
        foundUserGroups.forEach(pair -> groups.addAll(GROUP_REPOSITORY.stream().
                filter(group -> StringUtils.equals(group.getId(), pair.getLeft())).
                collect(Collectors.toList())));
        return Response.ok().entity(groups.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                collect(Collectors.toList())).build();
    }

    @Override
    public Response listUsers(
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String format,
            final String search,
            final String expand) {

        if (filter != null) {
            return Response.ok().entity(searchUsers(USER_REPOSITORY, filter)).build();
        }

        if (after != null) {
            Optional<User> found = USER_REPOSITORY.stream()
                    .filter(group -> StringUtils.equals(after, group.getId()))
                    .findAny();
            if (found.isPresent()) {
                int lastIndexOf = USER_REPOSITORY.lastIndexOf(found.get());
                return Response.ok().entity(USER_REPOSITORY.stream().
                        skip(lastIndexOf).
                        limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                        filter(q == null ? user -> true : user -> user.getProfile().getFirstName().contains(q)
                        || user.getProfile().getLastName().contains(q)
                        || user.getProfile().getEmail().contains(q)).
                        collect(Collectors.toList())).header("link", getNextPage(limit, lastIndexOf, USER_REPOSITORY)).
                        build();
            }
        }
        return Response.ok().entity(USER_REPOSITORY.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                filter(q == null ? user -> true : user -> user.getProfile().getFirstName().contains(q)
                || user.getProfile().getLastName().contains(q)
                || user.getProfile().getEmail().contains(q)).
                collect(Collectors.toList())).header("link", getNextPage(limit, 0, USER_REPOSITORY)).
                build();
    }

    @Override
    public Response removeGroupTargetFromRole(final String userId, final String roleId, final String groupId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response removeRoleFromUser(final String userId, final String roleId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response resetAllFactors(final String userId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response resetPassword(final String userId, final String provider, final Boolean sendEmail) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response suspendUser(final String userId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response unlockUser(final String userId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response unsuspendUser(final String userId) {
        throw new UnsupportedOperationException(ERROR_MESSAGE);
    }

    @Override
    public Response updateUser(final User user, final String userId, final Boolean strict) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(u -> StringUtils.equals(userId, u.getId()))
                .findAny();
        if (found.isPresent()) {
            user.setId(found.get().getId());
            user.setCreated(found.get().getCreated());
            user.setLastLogin(found.get().getLastLogin());
            user.setPasswordChanged(found.get().getPasswordChanged());
            user.setStatusChanged(found.get().getStatusChanged());

            if (user.getCredentials() != null && user.getCredentials().getPassword() != null) {
                if (user.getCredentials().getPassword().getValue() != null && !USER_PASSWORD_REPOSITORY.
                        get(userId).contains(user.getCredentials().getPassword().getValue())) {
                    USER_PASSWORD_REPOSITORY.get(userId).add(user.getCredentials().getPassword().getValue());
                } else if (user.getCredentials().getPassword().getHash() != null && !USER_PASSWORD_REPOSITORY.
                        get(userId).contains(user.getCredentials().getPassword().getHash().getValue())) {
                    USER_PASSWORD_REPOSITORY.get(userId).add(user.getCredentials().getPassword().
                            getHash().getValue());
                } else {
                    return Response.status(Response.Status.CONFLICT).build();
                }
                user.getCredentials().setPassword(null);
            }

            USER_REPOSITORY.remove(found.get());
            USER_REPOSITORY.add(user);
            user.setLastUpdated(Date.from(Instant.now()));
            return Response.ok().entity(user).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    public List<User> searchUsers(final List<User> users, final String filter) {
        String[] split = filter.split(" ");

        return users.stream().
                filter(user -> {
                    try {
                        return StringUtils.equals(StringUtils.remove(split[2], "\""),
                                BeanUtils.getProperty(user, split[0]));
                    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                        return false;
                    }
                }).
                collect(Collectors.toList());
    }

    @Override
    protected String getNextPage(Integer limit, int after, List<User> repository) {
        if (limit != null && limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/users?after=" + repository.get(limit + after).getId()
                    + "&limit=" + limit + ">; rel=\"next\"";
        } else {
            return null;
        }
    }
}

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
import io.swagger.model.CreateUserRequest;
import io.swagger.model.PasswordCredential;
import io.swagger.model.UpdateUserRequest;
import io.swagger.model.User;
import io.swagger.model.UserGetSingleton;
import io.swagger.model.UserNextLogin;
import io.swagger.model.UserProfile;
import io.swagger.model.UserStatus;
import io.swagger.model.UserType;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Predicate;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.tuple.Pair;

public class UserApiImpl extends AbstractApiImpl implements UserApi {

    @Override
    public Response createUser(
            final CreateUserRequest req,
            final Boolean activate,
            final Boolean provider,
            final UserNextLogin nextLogin) {

        User user = new User();
        user.setCredentials(req.getCredentials());
        user.setProfile(Optional.ofNullable(req.getProfile()).orElseGet(() -> new UserProfile()));
        if (req.getType() != null) {
            user.setType(new UserType().id(req.getType().getId()));
        }

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
    public Response deleteUser(final String userId, final Boolean sendEmail, final String prefer) {
        User found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst()
                .orElse(null);
        if (found == null) {
            return Response.status(Response.Status.NOT_FOUND).build();
        } else if (found.getStatus() == UserStatus.DEPROVISIONED) {
            USER_REPOSITORY.remove(found);
            USER_PASSWORD_REPOSITORY.remove(userId);
            createLogEvent("user.lifecycle.delete", userId);
            return Response.noContent().build();
        }

        found.setStatus(UserStatus.DEPROVISIONED);
        found.setLastUpdated(new Date());
        found.setStatusChanged(new Date());
        createLogEvent("user.lifecycle.deactivate", userId);
        return Response.ok().entity(found).build();
    }

    @Override
    public Response getUser(final String userId, final String contentType, final String expand) {
        return USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId())
                || StringUtils.equals(userId, user.getProfile().getLogin()))
                .findFirst()
                .map(found -> {
                    UserGetSingleton ugs = new UserGetSingleton();
                    ugs.setActivated(found.getActivated());
                    ugs.setCreated(found.getCreated());
                    ugs.setCredentials(found.getCredentials());
                    ugs.setEmbedded(found.getEmbedded());
                    ugs.setId(found.getId());
                    ugs.setProfile(found.getProfile());
                    ugs.setStatus(found.getStatus());
                    ugs.setStatusChanged(found.getStatusChanged());
                    ugs.setLastUpdated(found.getLastUpdated());
                    ugs.setType(found.getType());
                    ugs.setRealmId(found.getRealmId());

                    return Response.ok().entity(ugs).build();
                })
                .orElseGet(() -> Response.status(Response.Status.NOT_FOUND).build());
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
            final String contentType,
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
            User found = USER_REPOSITORY.stream().
                    filter(group -> StringUtils.equals(after, group.getId())).
                    findFirst().
                    orElse(null);
            if (found != null) {
                int lastIndexOf = USER_REPOSITORY.lastIndexOf(found);
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
    public Response updateUser(final UpdateUserRequest req, final String userId, final Boolean strict) {
        User user = USER_REPOSITORY.stream()
                .filter(u -> StringUtils.equals(userId, u.getId()))
                .findFirst()
                .orElse(null);
        if (user != null) {
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
    public Response replaceUser(final UpdateUserRequest body, final String id, final Boolean strict) {
        return Response.ok().entity("magic!").build();
    }

    public List<User> searchUsers(final List<User> users, final String filter) {
        String[] split = filter.split(" ");
        return users.stream().filter(user -> {
            try {
                return user.getStatus() != UserStatus.DEPROVISIONED
                        && StringUtils.equals(
                                StringUtils.remove(split[2], "\""),
                                BeanUtils.getProperty(user, split[0]));
            } catch (Exception e) {
                return false;
            }
        }).collect(Collectors.toList());
    }

    @Override
    public Response listUserBlocks(final String userId) {
        return Response.ok().entity("magic!").build();
    }
}

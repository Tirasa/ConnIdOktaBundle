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
import io.swagger.model.AssignRoleRequest;
import io.swagger.model.ChangePasswordRequest;
import io.swagger.model.Group;
import io.swagger.model.IdentityProvider;
import io.swagger.model.PasswordCredential;
import io.swagger.model.User;
import io.swagger.model.UserCredentials;
import io.swagger.model.UserProfile;
import io.swagger.model.UserStatus;
import java.lang.reflect.InvocationTargetException;
import java.time.Instant;
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

/**
 * Okta API
 *
 * <p>
 * Allows customers to easily access the Okta API
 *
 */
public class UserApiServiceImpl extends AbstractServiceImpl implements UserApi {

    /**
     * Activate User
     *
     * Activates a user. This operation can only be performed on users with a &#x60;STAGED&#x60; status. Activation of a
     * user is an asynchronous operation. The user will have the &#x60;transitioningToStatus&#x60; property with a value
     * of &#x60;ACTIVE&#x60; during activation to indicate that the user hasn&#x27;t completed the asynchronous
     * operation. The user will have a status of &#x60;ACTIVE&#x60; when the activation process is complete.
     *
     */
    @Override
    public Response activateUser(String userId, Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && found.get().getStatus() != UserStatus.ACTIVE) {
            found.get().setStatus(UserStatus.ACTIVE);
            found.get().setActivated(Date.from(Instant.now()));
            found.get().setLastUpdated(Date.from(Instant.now()));
            found.get().setStatusChanged(Date.from(Instant.now()));
            createLogEvent("user.lifecycle.activate", userId);
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response addAllAppsAsTargetToRole(String userId, String roleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response addApplicationTargetToAdminRoleForUser(String userId, String roleId, String appName) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add App Instance Target to App Administrator Role given to a User
     *
     * Add App Instance Target to App Administrator Role given to a User
     *
     */
    @Override
    public Response addApplicationTargetToAppAdminRoleForUser(String userId, String roleId, String appName,
            String applicationId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response addGroupTargetToRole(String userId, String roleId, String groupId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Forgot Password
     *
     */
    @Override
    public Response apiV1UsersUserIdCredentialsForgotPasswordPost(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response assignRoleToUser(AssignRoleRequest body, String userId, String disableNotifications) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Change Password
     *
     * Changes a user&#x27;s password by validating the user&#x27;s current password. This operation can only be
     * performed on users in &#x60;STAGED&#x60;, &#x60;ACTIVE&#x60;, &#x60;PASSWORD_EXPIRED&#x60;, or
     * &#x60;RECOVERY&#x60; status that have a valid password credential
     *
     */
    @Override
    public Response changePassword(ChangePasswordRequest changePasswordRequest, String userId, Boolean strict) {
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
                    found.get().setLastUpdated(Date.from(Instant.now()));
                    found.get().setPasswordChanged(Date.from(Instant.now()));
                    createLogEvent("user.account.update_password", userId);
                    return Response.ok().entity(found.get().getCredentials()).build();
                } else {
                    return Response.status(Response.Status.FORBIDDEN).
                            header("Okta-Request-Id", "E0000014").
                            entity(buildErrorResponse("000123",
                                    "Password requirements were not met. "
                                    + "Password requirements: at least 8 characters, a lowercase letter, "
                                    + "an uppercase letter, a number, "
                                    + "no parts of your username. "
                                    + "Your password cannot be any of your last 4 passwords.")).build();
                }
            } else {
                return Response.status(Response.Status.FORBIDDEN).
                        header("Okta-Request-Id", "E0000014").
                        entity(buildErrorResponse("000123", "Old Password is not correct")).build();
            }
        } else {
            return Response.status(Response.Status.NOT_FOUND).
                    header("Okta-Request-Id", "E0000014").
                    entity(buildErrorResponse("000123", "User not found or status not valid")).build();
        }
    }

    /**
     * Change Recovery Question
     *
     * Changes a user&#x27;s recovery question &amp; answer credential by validating the user&#x27;s current password.
     * This operation can only be performed on users in **STAGED**, **ACTIVE** or **RECOVERY** &#x60;status&#x60; that
     * have a valid password credential
     *
     */
    @Override
    public Response changeRecoveryQuestion(UserCredentials body, String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response clearUserSessions(String userId, Boolean oauthTokens) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    // workaround for https://github.com/swagger-api/swagger-codegen/issues/5187
    private void workaround(final UserProfile profile) {
        profile.setCity(profile.get("city"));
        profile.setCostCenter(profile.get("costCenter"));
        profile.setCountryCode(profile.get("country"));
        profile.setDepartment(profile.get("setDepartment"));
        profile.setDisplayName(profile.get("displayName"));
        profile.setDivision(profile.get("division"));
        profile.setEmail(profile.get("email"));
        profile.setEmployeeNumber(profile.get("employeeNumber"));
        profile.setFirstName(profile.get("firstName"));
        profile.setHonorificPrefix(profile.get("honorificPrefix"));
        profile.setHonorificSuffix(profile.get("honorificSuffix"));
        profile.setLastName(profile.get("lastName"));
        profile.setLocale(profile.get("locale"));
        profile.setLogin(profile.get("login"));
        profile.setManager(profile.get("manager"));
        profile.setManagerId(profile.get("managerId"));
        profile.setMiddleName(profile.get("middleName"));
        profile.setMobilePhone(profile.get("mobilePhone"));
        profile.setNickName(profile.get("nickName"));
        profile.setOrganization(profile.get("organization"));
        profile.setPostalAddress(profile.get("postalAddress"));
        profile.setPreferredLanguage(profile.get("preferredLanguage"));
        profile.setPrimaryPhone(profile.get("primaryPhone"));
        profile.setProfileUrl(profile.get("profileUrl"));
        profile.setSecondEmail(profile.get("secondEmail"));
        profile.setState(profile.get("state"));
        profile.setStreetAddress(profile.get("streetAddress"));
        profile.setTimezone(profile.get("timezone"));
        profile.setTitle(profile.get("title"));
        profile.setZipCode(profile.get("zipCode"));
    }

    @Override
    public Response createUser(
            final User body,
            final Boolean activate,
            final Boolean provider,
            final String nextLogin) {

        workaround(body.getProfile());

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
                body.setStatus(UserStatus.STAGED);
            }
            body.setId(UUID.randomUUID().toString());
            body.setCreated(Date.from(Instant.now()));
            body.setLastUpdated(Date.from(Instant.now()));
            body.setStatusChanged(Date.from(Instant.now()));
            List<String> passwords = new ArrayList<>();
            if (body.getCredentials() != null) {
                body.setPasswordChanged(Date.from(Instant.now()));
                if (body.getCredentials().getPassword().getHash() != null) {
                    body.getCredentials().getPassword().
                            setValue(body.getCredentials().getPassword().getHash().getValue());
                    body.getCredentials().getPassword().setHash(null);
                }
                passwords.add(body.getCredentials().getPassword().getValue());
                body.getCredentials().setPassword(null);
            }
            USER_PASSWORD_REPOSITORY.put(body.getId(), passwords);

            GROUP_USER_REPOSITORY.add(Pair.of(EVERYONE_ID, body.getId()));

            USER_IDP_REPOSITORY.put(body.getId(), new HashSet<>(Arrays.asList("6e77c44bf27d4750a10f1489ce4100df")));
            USER_REPOSITORY.add(body);
            createLogEvent("user.lifecycle.create", body.getId());
            return Response.status(Response.Status.CREATED).entity(body).build();
        } else {
            createLogEvent("user.lifecycle.update", body.getId());
            return updateUser(body, body.getId(), false);
        }
    }

    /**
     * Delete User
     *
     * Deletes a user permanently. This operation can only be performed on users that have a &#x60;DEPROVISIONED&#x60;
     * status. **This action cannot be recovered!**
     *
     */
    @Override
    public Response deactivateOrDeleteUser(String userId, Boolean sendEmail) {
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
        } else {
            found.get().setStatus(UserStatus.DEPROVISIONED);
            found.get().setLastUpdated(Date.from(Instant.now()));
            found.get().setStatusChanged(Date.from(Instant.now()));
            createLogEvent("user.lifecycle.deactivate", userId);
            return Response.ok().entity(found.get()).build();
        }
    }

    /**
     * Deactivate User
     *
     * Deactivates a user. This operation can only be performed on users that do not have a &#x60;DEPROVISIONED&#x60;
     * status. Deactivation of a user is an asynchronous operation. The user will have the
     * &#x60;transitioningToStatus&#x60; property with a value of &#x60;DEPROVISIONED&#x60; during deactivation to
     * indicate that the user hasn&#x27;t completed the asynchronous operation. The user will have a status of
     * &#x60;DEPROVISIONED&#x60; when the deactivation process is complete.
     *
     */
    @Override
    public Response deactivateUser(String userId, Boolean sendEmail) {
        return USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()) && user.getStatus() != UserStatus.DEPROVISIONED).
                map(user -> {
                    user.setStatus(UserStatus.DEPROVISIONED);
                    user.setLastUpdated(Date.from(Instant.now()));
                    user.setStatusChanged(Date.from(Instant.now()));
                    createLogEvent("user.lifecycle.deactivate", userId);
                    return Response.ok().entity(user).build();
                }).findFirst().
                orElse(Response.status(Response.Status.NOT_FOUND).build());
    }

    /**
     * Expire Password
     *
     * This operation transitions the user to the status of &#x60;PASSWORD_EXPIRED&#x60; so that the user is required to
     * change their password at their next login.
     *
     */
    @Override
    public Response expirePassword(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Expire Password
     *
     * This operation transitions the user to the status of &#x60;PASSWORD_EXPIRED&#x60; and the user&#x27;s password is
     * reset to a temporary password that is returned.
     *
     */
    @Override
    public Response expirePasswordAndGetTemporaryPassword(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getLinkedObjectsForUser(String userId, String relationshipName, String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getRefreshTokenForUserAndClient(String userId, String clientId, String tokenId, String expand,
            Integer limit, String after) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get User
     *
     * Fetches a user from your Okta organization.
     *
     */
    @Override
    public Response getUser(String userId) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId())
                || StringUtils.equals(userId, user.getProfile().getLogin()))
                .findFirst();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response getUserGrant(String userId, String grantId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Assigned App Links
     *
     * Fetches appLinks for all direct or indirect (via group membership) assigned applications.
     *
     */
    @Override
    public Response listAppLinks(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listApplicationTargetsForApplicationAdministratorRoleForUser(String userId, String roleId,
            String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listAssignedRolesForUser(String userId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGrantsForUserAndClient(String userId, String clientId, String expand, String after,
            Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listGroupTargetsForRole(String userId, String roleId, String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listRefreshTokensForUserAndClient(String userId, String clientId, String expand, String after,
            Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listUserClients(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listUserGrants(String userId, String scopeId, String expand, String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Member Groups
     *
     * Fetches the groups of which the user is a member.
     *
     */
    @Override
    public Response listUserGroups(String userId) {
        List<Pair<String, String>> foundUserGroups = GROUP_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(userId, pair.getRight())).
                collect(Collectors.toList());
        List<Group> groups = new ArrayList<>();
        foundUserGroups.forEach(pair -> groups.addAll(GROUP_REPOSITORY.stream().
                filter(group -> StringUtils.equals(group.getId(), pair.getLeft())).
                collect(Collectors.toList())));
        return Response.ok().entity(groups.stream().
                collect(Collectors.toList())).build();
    }

    /**
     * Listing IdPs associated with a user
     *
     * Lists the IdPs associated with the user.
     *
     */
    @Override
    public Response listUserIdentityProviders(String userId) {
        Set<String> userIdps = USER_IDP_REPOSITORY.get(userId);
        if (userIdps != null) {
            return Response.ok(
                    userIdps.isEmpty()
                    ? Collections.emptyList()
                    : userIdps.stream().map(item -> new IdentityProvider().
                    id("6e77c44bf27d4750a10f1489ce4100df").
                    type(IdentityProvider.TypeEnum.SAML2).
                    name("CAS 5 IDP")).collect(Collectors.toList())).build();
        }
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * List Users
     *
     * Lists users in your organization with pagination in most cases. A subset of users can be returned that match a
     * supported filter expression or search criteria.
     *
     */
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
            return Response.ok().entity(searchUsers(USER_REPOSITORY, search)).build();
        } else if (filter != null) {
            return Response.ok().entity(searchUsers(USER_REPOSITORY, filter)).build();
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
                        header("link", getNextPage(limit, lastIndexOf, USER_REPOSITORY)).
                        build();
            }
        }
        return Response.ok().entity(USER_REPOSITORY.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                filter(predicate).
                filter(user -> user.getStatus() != UserStatus.DEPROVISIONED).
                collect(Collectors.toList())).header("link", getNextPage(limit, 0, USER_REPOSITORY)).
                build();
    }

    @Override
    public Response partialUpdateUser(User body, String userId, Boolean strict) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Reactivate User
     *
     * Reactivates a user. This operation can only be performed on users with a &#x60;PROVISIONED&#x60; status. This
     * operation restarts the activation workflow if for some reason the user activation was not completed when using
     * the activationToken from [Activate User](#activate-user).
     *
     */
    @Override
    public Response reactivateUser(String userId, Boolean sendEmail) {
        return USER_REPOSITORY.stream().
                filter(user -> StringUtils.equals(userId, user.getId())).
                findFirst().
                map(user -> {
                    if (user.getStatus() == UserStatus.PROVISIONED) {
                        user.setStatus(UserStatus.RECOVERY);
                        user.setStatusChanged(Date.from(Instant.now()));
                        createLogEvent("user.lifecycle.reactivate", userId);
                        return Response.ok().entity("{}").build();
                    } else {
                        return Response.status(Response.Status.FORBIDDEN).build();
                    }
                }).
                orElseGet(() -> Response.status(Response.Status.NOT_FOUND).build());
    }

    /**
     * Remove App Instance Target to App Administrator Role given to a User
     *
     * Remove App Instance Target to App Administrator Role given to a User
     *
     */
    @Override
    public Response removeApplicationTargetFromAdministratorRoleForUser(String userId, String roleId, String appName,
            String applicationId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeApplicationTargetFromApplicationAdministratorRoleForUser(String userId, String roleId,
            String appName) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeGroupTargetFromRole(String userId, String roleId, String groupId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeLinkedObjectForUser(String userId, String relationshipName) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response removeRoleFromUser(String userId, String roleId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Reset Factors
     *
     * This operation resets all factors for the specified user. All MFA factor enrollments returned to the unenrolled
     * state. The user&#x27;s status remains ACTIVE. This link is present only if the user is currently enrolled in one
     * or more MFA factors.
     *
     */
    @Override
    public Response resetFactors(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Reset Password
     *
     * Generates a one-time token (OTT) that can be used to reset a user&#x27;s password. The OTT link can be
     * automatically emailed to the user or returned to the API caller and distributed using a custom flow.
     *
     */
    @Override
    public Response resetPassword(String userId, Boolean sendEmail) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent()) {
            User user = found.get();
            if (user.getStatus() == UserStatus.ACTIVE) {
                found.get().setStatus(UserStatus.RECOVERY);
                found.get().setStatusChanged(Date.from(Instant.now()));
                createLogEvent("user.lifecycle.reset_password", userId);
                return Response.ok().entity("{}").build();
            } else {
                return Response.status(Response.Status.FORBIDDEN).build();
            }
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response revokeGrantsForUserAndClient(String userId, String clientId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeTokenForUserAndClient(String userId, String clientId, String tokenId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeTokensForUserAndClient(String userId, String clientId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeUserGrant(String userId, String grantId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeUserGrants(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response setLinkedObjectForUser(String associatedUserId, String primaryRelationshipName, String primaryUserId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Suspend User
     *
     * Suspends a user. This operation can only be performed on users with an &#x60;ACTIVE&#x60; status. The user will
     * have a status of &#x60;SUSPENDED&#x60; when the process is complete.
     *
     */
    @Override
    public Response suspendUser(String userId) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && found.get().getStatus() == UserStatus.ACTIVE) {
            found.get().setStatus(UserStatus.SUSPENDED);
            found.get().setStatusChanged(Date.from(Instant.now()));
            createLogEvent("user.lifecycle.suspend", userId);
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Unlock User
     *
     * Unlocks a user with a &#x60;LOCKED_OUT&#x60; status and returns them to &#x60;ACTIVE&#x60; status. Users will be
     * able to login with their current password.
     *
     */
    @Override
    public Response unlockUser(String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Unsuspend User
     *
     * Unsuspends a user and returns them to the &#x60;ACTIVE&#x60; state. This operation can only be performed on users
     * that have a &#x60;SUSPENDED&#x60; status.
     *
     */
    @Override
    public Response unsuspendUser(String userId) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst();
        if (found.isPresent() && found.get().getStatus() == UserStatus.SUSPENDED) {
            found.get().setStatus(UserStatus.ACTIVE);
            found.get().setStatusChanged(Date.from(Instant.now()));
            createLogEvent("user.lifecycle.unsuspend", userId);
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Update User
     *
     * Update a user&#x27;s profile and/or credentials using strict-update semantics.
     *
     */
    @Override
    public Response updateUser(User user, String userId, Boolean strict) {
        Optional<User> found = USER_REPOSITORY.stream()
                .filter(u -> StringUtils.equals(userId, u.getId()))
                .findFirst();
        if (found.isPresent()) {
            workaround(user.getProfile());

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
            createLogEvent("user.lifecycle.update", userId);
            return Response.ok().entity(user).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
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

    private String getNextPage(Integer limit, int after, List<User> repository) {
        if (limit != null && limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/users?after=" + repository.get(limit + after).getId()
                    + "&limit=" + limit + ">; rel=\"next\"";
        } else {
            return null;
        }
    }
}

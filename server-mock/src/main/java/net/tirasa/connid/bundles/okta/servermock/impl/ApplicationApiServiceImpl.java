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

import io.swagger.api.ApplicationApi;
import io.swagger.model.AppUser;
import io.swagger.model.Application;
import io.swagger.model.ApplicationGroupAssignment;
import io.swagger.model.CapabilitiesObject;
import io.swagger.model.CsrMetadata;
import io.swagger.model.OAuth2ScopeConsentGrant;
import io.swagger.model.ProvisioningConnectionRequest;
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
import org.apache.cxf.jaxrs.ext.multipart.Attachment;

/**
 * Okta API
 *
 * <p>
 * Allows customers to easily access the Okta API
 *
 */
public class ApplicationApiServiceImpl extends AbstractServiceImpl implements ApplicationApi {

    /**
     * Activate Application
     *
     * Activates an inactive application.
     *
     */
    @Override
    public Response activateApplication(String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response apiV1AppsAppIdCredentialsCsrsCsrIdLifecyclePublishPost(String appId, String csrId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Assign User to Application for SSO &amp; Provisioning
     *
     * Assigns an user to an application with [credentials](#application-user-credentials-object) and an app-specific
     * [profile](#application-user-profile-object). Profile mappings defined for the application are first applied
     * before applying any profile properties specified in the request.
     *
     */
    @Override
    public Response assignUserToApplication(AppUser body, String appId) {
        if (APPLICATION_REPOSITORY.stream().anyMatch(app -> StringUtils.equals(appId, app.getId()))
                && USER_REPOSITORY.stream().anyMatch(user -> StringUtils.equals(body.getId(), user.getId()))) {

            APPLICATION_USER_REPOSITORY.add(Pair.of(appId, body.getId()));
            createLogEvent("application.user_membership.add", body.getId());
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    /**
     * Clone Application Key Credential
     *
     * Clones a X.509 certificate for an application key credential from a source application to target application.
     *
     */
    @Override
    public Response cloneApplicationKey(String appId, String keyId, String targetAid) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add Application
     *
     * Adds a new application to your Okta organization.
     *
     */
    @Override
    public Response createApplication(Application body, String oktaAccessGatewayAgent, Boolean activate) {
        if (body.getId() == null) {
            if (Boolean.TRUE.equals(activate)) {
                body.setStatus(Application.StatusEnum.ACTIVE);
            }
            body.setId(UUID.randomUUID().toString());
            body.setCreated(Date.from(Instant.now()));
            body.setLastUpdated(Date.from(Instant.now()));
            APPLICATION_REPOSITORY.add(body);
            createLogEvent("application.lifecycle.create", body.getId());
            return Response.status(Response.Status.CREATED).entity(body).build();
        } else {
            return updateApplication(body, body.getId());
        }
    }

    /**
     * Assign Group to Application
     *
     * Assigns a group to an application
     *
     */
    @Override
    public Response createApplicationGroupAssignment(String appId, String groupId, ApplicationGroupAssignment body) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Deactivate Application
     *
     * Deactivates an active application.
     *
     */
    @Override
    public Response deactivateApplication(String appId) {
        APPLICATION_REPOSITORY.stream()
                .filter(app -> StringUtils.equals(appId, app.getId()))
                .findFirst().map(item -> {
                    item.setStatus(Application.StatusEnum.INACTIVE);
                    item.setLastUpdated(Date.from(Instant.now()));
                    createLogEvent("application.lifecycle.deactivate", appId);
                    return Response.ok().entity(item).build();
                });
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * Delete Application
     *
     * Removes an inactive application.
     *
     */
    @Override
    public Response deleteApplication(String appId) {
        createLogEvent("application.lifecycle.delete", appId);
        return APPLICATION_REPOSITORY.removeIf(app -> StringUtils.equals(appId, app.getId())) ? Response.
                noContent().build() : Response.status(Response.Status.NOT_FOUND).build();
    }

    /**
     * Remove Group from Application
     *
     * Removes a group assignment from an application.
     *
     */
    @Override
    public Response deleteApplicationGroupAssignment(String appId, String groupId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Remove User from Application
     *
     * Removes an assignment for a user from an application.
     *
     */
    @Override
    public Response deleteApplicationUser(String appId, String userId, Boolean sendEmail) {
        createLogEvent("application.user_membership.remove", appId);
        return APPLICATION_USER_REPOSITORY.removeIf(pair -> StringUtils.equals(pair.getLeft(), appId)
                && StringUtils.equals(pair.getRight(), userId)) ? Response.noContent().build() : Response.status(
                Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response generateApplicationKey(String appId, Integer validityYears) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Generate Certificate Signing Request for Application
     *
     * Generates a new key pair and returns the Certificate Signing Request for it.
     *
     */
    @Override
    public Response generateCsrForApplication(CsrMetadata body, String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Application
     *
     * Fetches an application from your Okta organization by &#x60;id&#x60;.
     *
     */
    @Override
    public Response getApplication(String appId, String expand) {
        Optional<Application> found = APPLICATION_REPOSITORY.stream()
                .filter(app -> StringUtils.equals(appId, app.getId()))
                .findAny();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Get Assigned Group for Application
     *
     * Fetches an application group assignment
     *
     */
    @Override
    public Response getApplicationGroupAssignment(String appId, String groupId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Key Credential for Application
     *
     * Gets a specific application key credential by kid
     *
     */
    @Override
    public Response getApplicationKey(String appId, String keyId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Assigned User for Application
     *
     * Fetches a specific user assignment for application by &#x60;id&#x60;.
     *
     */
    @Override
    public Response getApplicationUser(String appId, String userId, String expand) {
        Optional<Pair<String, String>> found = APPLICATION_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(appId, pair.getLeft())
                && StringUtils.equals(userId, pair.getRight())).
                findFirst();
        if (found.isPresent()) {
            return Response.ok().
                    entity(new UserApiServiceImpl().getUser(found.get().getRight()).readEntity(User.class)).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    public Response getCsrForApplication(String appId, String csrId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getOAuth2TokenForApplication(String appId, String tokenId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getScopeConsentGrant(String appId, String grantId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response grantConsentToScope(OAuth2ScopeConsentGrant body, String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Groups Assigned to Application
     *
     * Enumerates group assignments for an application.
     *
     */
    @Override
    public Response listApplicationGroupAssignments(String appId, String q, String after, Integer limit, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Key Credentials for Application
     *
     * Enumerates key credentials for an application
     *
     */
    @Override
    public Response listApplicationKeys(String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Users Assigned to Application
     *
     * Enumerates all assigned [application users](#application-user-model) for an application.
     *
     */
    @Override
    public Response listApplicationUsers(
            final String appId,
            final String q,
            final String queryScope,
            final String after,
            final Integer limit,
            final String filter,
            final String expand) {

        List<Pair<String, String>> foundAppUsers = APPLICATION_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(appId, pair.getLeft())).
                collect(Collectors.toList());
        List<User> users = new ArrayList<>();
        foundAppUsers.forEach(pair -> users.addAll(USER_REPOSITORY.stream().
                filter(user -> StringUtils.equals(user.getId(), pair.getRight())).
                collect(Collectors.toList())));

        if (filter != null) {
            return Response.ok().entity(new UserApiServiceImpl().searchUsers(users, filter)).build();
        }
        return Response.ok().entity(USER_REPOSITORY.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                filter(q == null ? user -> true : user -> user.getProfile().getFirstName().contains(q)
                || user.getProfile().getLastName().contains(q)
                || user.getProfile().getEmail().contains(q)).
                collect(Collectors.toList())).
                build();
    }

    /**
     * List Applications
     *
     * Enumerates apps added to your organization with pagination. A subset of apps can be returned that match a
     * supported filter expression or query.
     *
     */
    @Override
    public Response listApplications(
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String expand,
            final Boolean includeNonDeleted) {

        if (filter != null) {
            List<Application> applications = searchApplication(filter);
            return Response.ok().entity(applications).build();
        }

        if (after != null) {
            Optional<Application> found = APPLICATION_REPOSITORY.stream()
                    .filter(group -> StringUtils.equals(after, group.getId()))
                    .findAny();
            if (found.isPresent()) {
                int lastIndexOf = APPLICATION_REPOSITORY.lastIndexOf(found.get());
                return Response.ok().entity(APPLICATION_REPOSITORY.stream().
                        skip(lastIndexOf).
                        limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                        filter(q == null ? application -> true : application -> application.getName().contains(q)).
                        collect(Collectors.toList())).
                        header("link", getNextPage(limit, lastIndexOf, APPLICATION_REPOSITORY)).build();
            }
        }
        long actualLimit = limit == null || limit < 0 ? DEFAULT_LIMIT : limit.longValue();
        return Response.ok().entity(APPLICATION_REPOSITORY.stream().
                limit(actualLimit).
                filter(q == null ? application -> true : application -> application.getName().contains(q)).
                collect(Collectors.toList())).header("link", getNextPage(actualLimit, 0, APPLICATION_REPOSITORY)).
                build();
    }

    /**
     * List Certificate Signing Requests for Application
     *
     * Enumerates Certificate Signing Requests for an application
     *
     */
    @Override
    public Response listCsrsForApplication(String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listOAuth2TokensForApplication(String appId, String expand, String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listScopeConsentGrants(String appId, String expand) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeCsrFromApplication(String appId, String csrId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeOAuth2TokenForApplication(String appId, String tokenId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeOAuth2TokensForApplication(String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeScopeConsentGrant(String appId, String grantId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Update Application
     *
     * Updates an application in your organization.
     *
     */
    @Override
    public Response updateApplication(Application body, String appId) {
        Optional<Application> found = APPLICATION_REPOSITORY.stream()
                .filter(app -> StringUtils.equals(appId, app.getId()))
                .findAny();
        if (found.isPresent()) {
            body.setId(found.get().getId());
            body.setCreated(found.get().getCreated());
            APPLICATION_REPOSITORY.remove(found.get());
            APPLICATION_REPOSITORY.add(body);
            body.setLastUpdated(Date.from(Instant.now()));
            createLogEvent("application.lifecycle.update", appId);
            return Response.ok().entity(body).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Update Application Profile for Assigned User
     *
     * Updates a user&#x27;s profile for an application
     *
     */
    @Override
    public Response updateApplicationUser(AppUser body, String appId, String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response activateDefaultProvisioningConnectionForApplication(final String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deactivateDefaultProvisioningConnectionForApplication(final String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getDefaultProvisioningConnectionForApplication(final String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getFeatureForApplication(final String appId, final String name) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listFeaturesForApplication(final String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response setDefaultProvisioningConnectionForApplication(
            final ProvisioningConnectionRequest body, final String appId, final Boolean activate) {

        // TODO: Implement...
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response updateFeatureForApplication(
            final CapabilitiesObject body, final String appId, final String name) {

        // TODO: Implement...
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response uploadApplicationLogo(final Attachment fileDetail, final String appId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    private List<Application> searchApplication(final String filter) {
        String[] split = filter.split(" ");

        return APPLICATION_REPOSITORY.stream().
                filter(app -> {
                    try {
                        return StringUtils.equals(StringUtils.remove(split[2], "\""),
                                BeanUtils.getProperty(app, split[0]));
                    } catch (IllegalAccessException | InvocationTargetException | NoSuchMethodException ex) {
                        return false;
                    }
                }).
                collect(Collectors.toList());
    }

    private String getNextPage(long limit, int after, List<Application> repository) {
        if (limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/apps?after="
                    + repository.get((int) (limit + after)).getId()
                    + "&limit=" + limit + ">; rel=\"next\"";
        } else {
            return null;
        }
    }
}

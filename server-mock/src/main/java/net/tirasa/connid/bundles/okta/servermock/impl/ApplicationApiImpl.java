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
import io.swagger.model.ApplicationLifecycleStatus;
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

public class ApplicationApiImpl extends AbstractApiImpl implements ApplicationApi {

    @Override
    public Response activateApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response assignUserToApplication(final AppUser body, final String appId) {
        if (APPLICATION_REPOSITORY.stream().anyMatch(app -> StringUtils.equals(appId, app.getId()))
                && USER_REPOSITORY.stream().anyMatch(user -> StringUtils.equals(body.getId(), user.getId()))) {

            APPLICATION_USER_REPOSITORY.add(Pair.of(appId, body.getId()));
            createLogEvent("application.user_membership.add", body.getId());
            return Response.ok().build();
        } else {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }
    }

    @Override
    public Response cloneApplicationKey(final String appId, final String keyId, final String targetAid) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response createApplication(
            final Application body,
            final String oktaAccessGatewayAgent,
            final Boolean activate) {

        if (body.getId() == null) {
            if (Boolean.TRUE.equals(activate)) {
                body.setStatus(ApplicationLifecycleStatus.ACTIVE);
            }
            body.setId(UUID.randomUUID().toString());
            body.setCreated(Date.from(Instant.now()));
            body.setLastUpdated(Date.from(Instant.now()));
            APPLICATION_REPOSITORY.add(body);
            createLogEvent("application.lifecycle.create", body.getId());
            return Response.status(Response.Status.CREATED).entity(body).build();
        } else {
            return replaceApplication(body, body.getId());
        }
    }

    @Override
    public Response deactivateApplication(final String appId) {
        APPLICATION_REPOSITORY.stream()
                .filter(app -> StringUtils.equals(appId, app.getId()))
                .findFirst().map(item -> {
                    item.setStatus(ApplicationLifecycleStatus.INACTIVE);
                    item.setLastUpdated(Date.from(Instant.now()));
                    createLogEvent("application.lifecycle.deactivate", appId);
                    return Response.ok().entity(item).build();
                });
        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response deleteApplication(final String appId) {
        createLogEvent("application.lifecycle.delete", appId);
        return APPLICATION_REPOSITORY.removeIf(app -> StringUtils.equals(appId, app.getId())) ? Response.
                noContent().build() : Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response unassignUserFromApplication(final String appId, final String userId, final Boolean sendEmail) {
        createLogEvent("application.user_membership.remove", appId);
        return APPLICATION_USER_REPOSITORY.removeIf(pair -> StringUtils.equals(pair.getLeft(), appId)
                && StringUtils.equals(pair.getRight(), userId)) ? Response.noContent().build() : Response.status(
                Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response generateApplicationKey(final String appId, final Integer validityYears) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response generateCsrForApplication(final CsrMetadata body, final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getApplication(final String appId, final String expand) {
        Optional<Application> found = APPLICATION_REPOSITORY.stream()
                .filter(app -> StringUtils.equals(appId, app.getId()))
                .findAny();
        if (found.isPresent()) {
            return Response.ok().entity(found.get()).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response getApplicationGroupAssignment(final String appId, final String groupId, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getApplicationKey(final String appId, final String keyId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getApplicationUser(final String appId, final String userId, final String expand) {
        Optional<Pair<String, String>> found = APPLICATION_USER_REPOSITORY.stream().
                filter(pair -> StringUtils.equals(appId, pair.getLeft())
                && StringUtils.equals(userId, pair.getRight())).
                findFirst();
        if (found.isPresent()) {
            return Response.ok().
                    entity(new UserApiImpl().getUser(found.get().getRight()).readEntity(User.class)).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response getCsrForApplication(final String appId, final String csrId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getOAuth2TokenForApplication(final String appId, final String tokenId, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getScopeConsentGrant(final String appId, final String grantId, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response grantConsentToScope(final OAuth2ScopeConsentGrant body, final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listApplicationGroupAssignments(
            final String appId, final String q, final String after, final Integer limit, final String expand) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listApplicationKeys(final String appId) {
        return Response.ok().entity("magic!").build();
    }

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
            return Response.ok().entity(new UserApiImpl().searchUsers(users, filter)).build();
        }

        return Response.ok().entity(USER_REPOSITORY.stream().
                limit(limit == null ? DEFAULT_LIMIT : limit.longValue()).
                filter(q == null ? user -> true : user -> user.getProfile().getFirstName().contains(q)
                || user.getProfile().getLastName().contains(q)
                || user.getProfile().getEmail().contains(q)).
                collect(Collectors.toList())).
                build();
    }

    private String nextPage(final long limit, final int after, final List<Application> repository) {
        if (limit + after < repository.size()) {
            return "<" + uriInfo.getBaseUri().toString() + "api/v1/apps?after="
                    + repository.get((int) (limit + after)).getId()
                    + "&limit=" + limit + ">; rel=\"next\"";
        }

        return "<" + uriInfo.getBaseUri().toString() + "api/v1/apps?after="
                + repository.get(repository.size() - 1).getId()
                + "&limit=" + limit + ">; rel=\"self\"";
    }

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
            return Response.ok().entity(applications).
                    header("link", nextPage(limit, 0, APPLICATION_REPOSITORY)).build();
        }

        if (after != null) {
            Optional<Application> found = APPLICATION_REPOSITORY.stream()
                    .filter(group -> StringUtils.equals(after, group.getId()))
                    .findAny();
            if (found.isPresent()) {
                int lastIndexOf = APPLICATION_REPOSITORY.lastIndexOf(found.get());
                return Response.ok().entity(APPLICATION_REPOSITORY.stream().
                        skip(lastIndexOf).
                        limit(limit).
                        filter(q == null ? application -> true : application -> application.getLabel().contains(q)).
                        collect(Collectors.toList())).
                        header("link", nextPage(limit, lastIndexOf, APPLICATION_REPOSITORY)).build();
            }
        }

        long actualLimit = limit == null || limit < 0 ? DEFAULT_LIMIT : limit.longValue();
        return Response.ok().entity(APPLICATION_REPOSITORY.stream().
                limit(actualLimit).
                filter(q == null ? application -> true : application -> application.getLabel().contains(q)).
                collect(Collectors.toList())).header("link", nextPage(actualLimit, 0, APPLICATION_REPOSITORY)).
                build();
    }

    @Override
    public Response listCsrsForApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listOAuth2TokensForApplication(
            final String appId, final String expand, final String after, final Integer limit) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listScopeConsentGrants(final String appId, final String expand) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeCsrFromApplication(final String appId, final String csrId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeOAuth2TokenForApplication(final String appId, final String tokenId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeOAuth2TokensForApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeScopeConsentGrant(final String appId, final String grantId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response uploadApplicationLogo(final String appId, final Attachment fileDetail) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response replaceApplication(final Application body, final String appId) {
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
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response updateApplicationUser(final AppUser body, final String appId, final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response activateDefaultProvisioningConnectionForApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deactivateDefaultProvisioningConnectionForApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getDefaultProvisioningConnectionForApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getFeatureForApplication(final String appId, final String name) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listFeaturesForApplication(final String appId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response updateFeatureForApplication(
            final CapabilitiesObject body, final String appId, final String name) {

        return Response.status(Response.Status.NOT_FOUND).build();
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

    @Override
    public Response assignApplicationPolicy(final String appId, final String policyId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response assignGroupToApplication(
            final String appId, final String groupId, final ApplicationGroupAssignment body) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response unassignApplicationFromGroup(final String appId, final String groupId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response updateDefaultProvisioningConnectionForApplication(
            final ProvisioningConnectionRequest body, final String appId, final Boolean activate) {

        return Response.ok().entity("magic!").build();
    }
}

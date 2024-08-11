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

import io.swagger.api.IdentityProviderApi;
import io.swagger.model.CsrMetadata;
import io.swagger.model.IdentityProvider;
import io.swagger.model.JsonWebKey;
import io.swagger.model.User;
import io.swagger.model.UserIdentityProviderLinkRequest;
import java.util.Optional;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;

public class IdentityProviderApiImpl extends AbstractApiImpl implements IdentityProviderApi {

    @Override
    public Response activateIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response cloneIdentityProviderKey(final String idpId, final String keyId, final String targetIdpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response createIdentityProvider(final IdentityProvider body) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response createIdentityProviderKey(final JsonWebKey body) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deactivateIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deleteIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response deleteIdentityProviderKey(final String keyId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response generateCsrForIdentityProvider(final CsrMetadata body, final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response generateIdentityProviderSigningKey(final String idpId, final Integer validityYears) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getCsrForIdentityProvider(final String idpId, final String csrId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getIdentityProviderApplicationUser(final String idpId, final String userId) {
        if (USER_IDP_REPOSITORY.containsKey(userId) && USER_IDP_REPOSITORY.get(userId).contains(idpId)) {
            return Response.status(Response.Status.OK).entity(new IdentityProvider().id(idpId)).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response getIdentityProviderKey(final String keyId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getIdentityProviderSigningKey(final String idpId, final String keyId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response linkUserToIdentityProvider(
            final UserIdentityProviderLinkRequest body, final String idpId, final String userId) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listCsrsForIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listIdentityProviderKeys(final String after, final Integer limit) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listIdentityProviderSigningKeys(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listIdentityProviders(final String q, final String after, final Integer limit, final String type) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listSocialAuthTokens(final String idpId, final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeCsrForIdentityProvider(final String idpId, final String csrId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response unlinkUserFromIdentityProvider(final String idpId, final String userId) {
        Optional<User> user = USER_REPOSITORY.stream()
                .filter(item -> StringUtils.equals(userId, item.getId()))
                .findFirst();
        if (user.isPresent()
                && USER_IDP_REPOSITORY.containsKey(userId)
                && USER_IDP_REPOSITORY.get(userId).contains(idpId)) {

            USER_IDP_REPOSITORY.get(userId).remove(idpId);
            return Response.noContent().build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response replaceIdentityProvider(final IdentityProvider body, final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response publishCsrForIdentityProvider(final Object body, final String idpId, final String idpCsrId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listIdentityProviderApplicationUsers(
            final String idpId,
            final String q,
            final String after,
            final Integer limit,
            final String expand) {

        return Response.ok().entity("magic!").build();
    }
}

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

/**
 * Okta API
 *
 * <p>
 * Allows customers to easily access the Okta API
 *
 */
public class IdentityProviderApiServiceImpl extends AbstractServiceImpl implements IdentityProviderApi {

    /**
     * Activate Identity Provider
     *
     * Activates an inactive IdP.
     *
     */
    @Override
    public Response activateIdentityProvider(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response apiV1IdpsIdpIdCredentialsCsrsCsrIdLifecyclePublishPost(String idpId, String csrId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Clone Signing Key Credential for IdP
     *
     * Clones a X.509 certificate for an IdP signing key credential from a source IdP to target IdP
     *
     */
    @Override
    public Response cloneIdentityProviderKey(String idpId, String keyId, String targetIdpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add Identity Provider
     *
     * Adds a new IdP to your organization.
     *
     */
    @Override
    public Response createIdentityProvider(IdentityProvider body) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Add X.509 Certificate Public Key
     *
     * Adds a new X.509 certificate credential to the IdP key store.
     *
     */
    @Override
    public Response createIdentityProviderKey(JsonWebKey body) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Deactivate Identity Provider
     *
     * Deactivates an active IdP.
     *
     */
    @Override
    public Response deactivateIdentityProvider(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Delete Identity Provider
     *
     * Removes an IdP from your organization.
     *
     */
    @Override
    public Response deleteIdentityProvider(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Delete Key
     *
     * Deletes a specific IdP Key Credential by &#x60;kid&#x60; if it is not currently being used by an Active or
     * Inactive IdP.
     *
     */
    @Override
    public Response deleteIdentityProviderKey(String keyId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Generate Certificate Signing Request for IdP
     *
     * Generates a new key pair and returns a Certificate Signing Request for it.
     *
     */
    @Override
    public Response generateCsrForIdentityProvider(CsrMetadata body, String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Generate New IdP Signing Key Credential
     *
     * Generates a new X.509 certificate for an IdP signing key credential to be used for signing assertions sent to the
     * IdP
     *
     */
    @Override
    public Response generateIdentityProviderSigningKey(String idpId, Integer validityYears) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getCsrForIdentityProvider(String idpId, String csrId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Identity Provider
     *
     * Fetches an IdP by &#x60;id&#x60;.
     *
     */
    @Override
    public Response getIdentityProvider(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getIdentityProviderApplicationUser(String idpId, String userId) {
        if (USER_IDP_REPOSITORY.containsKey(userId) && USER_IDP_REPOSITORY.get(userId).contains(idpId)) {
            return Response.status(Response.Status.OK).entity(new IdentityProvider().id(idpId)).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Get Key
     *
     * Gets a specific IdP Key Credential by &#x60;kid&#x60;
     *
     */
    @Override
    public Response getIdentityProviderKey(String keyId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Get Signing Key Credential for IdP
     *
     * Gets a specific IdP Key Credential by &#x60;kid&#x60;
     *
     */
    @Override
    public Response getIdentityProviderSigningKey(String idpId, String keyId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Link a user to a Social IdP without a transaction
     *
     * Links an Okta user to an existing Social Identity Provider. This does not support the SAML2 Identity Provider
     * Type
     *
     */
    @Override
    public Response linkUserToIdentityProvider(UserIdentityProviderLinkRequest body, String idpId, String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Certificate Signing Requests for IdP
     *
     * Enumerates Certificate Signing Requests for an IdP
     *
     */
    @Override
    public Response listCsrsForIdentityProvider(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Find Users
     *
     * Find all the users linked to an identity provider
     *
     */
    @Override
    public Response listIdentityProviderApplicationUsers(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Keys
     *
     * Enumerates IdP key credentials.
     *
     */
    @Override
    public Response listIdentityProviderKeys(String after, Integer limit) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Signing Key Credentials for IdP
     *
     * Enumerates signing key credentials for an IdP
     *
     */
    @Override
    public Response listIdentityProviderSigningKeys(String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * List Identity Providers
     *
     * Enumerates IdPs in your organization with pagination. A subset of IdPs can be returned that match a supported
     * filter expression or query.
     *
     */
    @Override
    public Response listIdentityProviders(String q, String after, Integer limit, String type) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Social Authentication Token Operation
     *
     * Fetches the tokens minted by the Social Authentication Provider when the user authenticates with Okta via Social
     * Auth.
     *
     */
    @Override
    public Response listSocialAuthTokens(String idpId, String userId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response revokeCsrForIdentityProvider(String idpId, String csrId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Unlink User from IdP
     *
     * Removes the link between the Okta user and the IdP user.
     *
     */
    @Override
    public Response unlinkUserFromIdentityProvider(String idpId, String userId) {
        Optional<User> user = USER_REPOSITORY.stream()
                .filter(item -> StringUtils.equals(userId, item.getId()))
                .findFirst();
        if (user.isPresent()) {
            if (USER_IDP_REPOSITORY.containsKey(userId) && USER_IDP_REPOSITORY.get(userId).contains(idpId)) {
                USER_IDP_REPOSITORY.get(userId).remove(idpId);
                return Response.noContent().build();
            } else {
                return Response.status(Response.Status.NOT_FOUND).build();
            }
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    /**
     * Update Identity Provider
     *
     * Updates the configuration for an IdP.
     *
     */
    @Override
    public Response updateIdentityProvider(IdentityProvider body, String idpId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

}

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
import io.swagger.model.IdentityProvider;
import io.swagger.model.IdentityProviderType;
import javax.ws.rs.core.Response;
import org.springframework.stereotype.Service;

@Service
public class IdentityProviderApiImpl extends AbstractApiImpl implements IdentityProviderApi {

    @Override
    public Response activateIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response createIdentityProvider(final IdentityProvider body) {
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
    public Response getIdentityProvider(final String idpId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listIdentityProviders(
            final String q,
            final String after,
            final Integer limit,
            final IdentityProviderType type) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response replaceIdentityProvider(final IdentityProvider body, final String idpId) {
        return Response.ok().entity("magic!").build();
    }
}

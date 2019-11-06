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

import static com.gfs.ebz.syncope.api.impl.AbstractApi.USER_REPOSITORY;

import io.swagger.api.IdpApi;
import io.swagger.model.User;
import io.swagger.model.Idp;
import java.util.List;
import java.util.Optional;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;

public class IdpImpl extends AbstractApi<Idp> implements IdpApi {

    public Response unlinkUserFromIdp(final String idpId, final String userId) {
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

    @Override
    public Response getIdpUser(final String idpId, final String userId) {
        if (USER_IDP_REPOSITORY.containsKey(userId) && USER_IDP_REPOSITORY.get(userId).contains(idpId)) {
            return Response.status(Response.Status.OK).entity(new Idp().id(idpId)).build();
        } else {
            return Response.status(Response.Status.NOT_FOUND).build();
        }
    }

    @Override
    protected String getNextPage(Integer limit, int after, List<Idp> repository) {
        throw new UnsupportedOperationException("Not supported yet.");
    }

}

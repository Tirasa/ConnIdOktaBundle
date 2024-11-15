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

import io.swagger.api.UserLifecycleApi;
import io.swagger.model.User;
import io.swagger.model.UserStatus;
import java.util.Date;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.StringUtils;

public class UserLifecycleApiImpl extends AbstractApiImpl implements UserLifecycleApi {

    @Override
    public Response activateUser(final String userId, final Boolean sendEmail) {
        User found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst()
                .orElse(null);
        if (found != null && found.getStatus() != UserStatus.ACTIVE) {
            found.setStatus(UserStatus.ACTIVE);
            found.setActivated(new Date());
            found.setLastUpdated(new Date());
            found.setStatusChanged(new Date());
            createLogEvent("user.lifecycle.activate", userId);
            return Response.ok().entity(found).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response deactivateUser(final String userId, final Boolean sendEmail, final String prefer) {
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
    public Response suspendUser(final String userId) {
        User found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst()
                .orElse(null);
        if (found != null && found.getStatus() == UserStatus.ACTIVE) {
            found.setStatus(UserStatus.SUSPENDED);
            found.setStatusChanged(new Date());
            createLogEvent("user.lifecycle.suspend", userId);
            return Response.ok().entity(found).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }

    @Override
    public Response unlockUser(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response unsuspendUser(final String userId) {
        User found = USER_REPOSITORY.stream()
                .filter(user -> StringUtils.equals(userId, user.getId()))
                .findFirst()
                .orElse(null);
        if (found != null && found.getStatus() == UserStatus.SUSPENDED) {
            found.setStatus(UserStatus.ACTIVE);
            found.setStatusChanged(new Date());
            createLogEvent("user.lifecycle.unsuspend", userId);
            return Response.ok().entity(found).build();
        }

        return Response.status(Response.Status.NOT_FOUND).build();
    }
}

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

import io.swagger.api.UserCredApi;
import io.swagger.model.ChangePasswordRequest;
import io.swagger.model.User;
import io.swagger.model.UserCredentials;
import io.swagger.model.UserStatus;
import java.util.Collections;
import java.util.Date;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import javax.ws.rs.core.Response;
import org.apache.commons.lang3.Strings;
import org.springframework.stereotype.Service;

@Service
public class UserCredApiImpl extends AbstractApi implements UserCredApi {

    private Map<String, Object> buildErrorResponse(final String errorId, final String message) {
        Map<String, Object> error = new LinkedHashMap<>();
        error.put("errorCode", "E0000014");
        error.put("errorSummary", "Update of credentials failed");
        error.put("errorLink", "E0000014");
        error.put("errorId", errorId);
        error.put("errorCauses", Collections.singletonList(Collections.singletonMap("errorSummary", message)));
        return error;
    }

    @Override
    public Response changePassword(
            final ChangePasswordRequest changePasswordRequest,
            final String userId,
            final Boolean strict) {

        User found = USER_REPOSITORY.stream()
                .filter(user -> Strings.CS.equals(userId, user.getId()))
                .findFirst()
                .orElse(null);
        if (found != null
                && (found.getStatus().equals(UserStatus.ACTIVE)
                || found.getStatus().equals(UserStatus.PASSWORD_EXPIRED)
                || found.getStatus().equals(UserStatus.STAGED)
                || found.getStatus().equals(UserStatus.RECOVERY))) {

            List<String> pwds = USER_PASSWORD_REPOSITORY.get(userId);
            if (pwds.isEmpty() || changePasswordRequest.getOldPassword().getValue().equals(pwds.get(pwds.size() - 1))) {
                if (!pwds.contains(changePasswordRequest.getNewPassword().getValue())) {
                    pwds.add(changePasswordRequest.getNewPassword().getValue());
                    found.setLastUpdated(new Date());
                    found.setPasswordChanged(new Date());
                    createLogEvent("user.account.update_password", userId);
                    return Response.ok().entity(found.getCredentials()).build();
                }

                return Response.status(Response.Status.FORBIDDEN).
                        header("Okta-Request-Id", "E0000014").
                        entity(buildErrorResponse("000123",
                                "Password requirements were not met. "
                                + "Password requirements: at least 8 characters, a lowercase letter, "
                                + "an uppercase letter, a number, "
                                + "no parts of your username. "
                                + "Your password cannot be any of your last 4 passwords.")).build();
            }

            return Response.status(Response.Status.FORBIDDEN).
                    header("Okta-Request-Id", "E0000014").
                    entity(buildErrorResponse("000123", "Old Password is not correct")).build();
        }

        return Response.status(Response.Status.NOT_FOUND).
                header("Okta-Request-Id", "E0000014").
                entity(buildErrorResponse("000123", "User not found or status not valid")).build();
    }

    @Override
    public Response changeRecoveryQuestion(final UserCredentials body, final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response expirePassword(final String userId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response expirePasswordWithTempPassword(final String userId, final Boolean revokeSessions) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response forgotPassword(final String userId, final Boolean sendEmail) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response forgotPasswordSetNewPassword(
            final UserCredentials body, final String userId, final Boolean sendEmail) {

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response resetPassword(final String userId, final Boolean sendEmail, final Boolean revokeSessions) {
        return Response.ok().entity("magic!").build();
    }
}

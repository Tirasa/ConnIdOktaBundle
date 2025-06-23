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
import io.swagger.model.Application;
import io.swagger.model.ApplicationLifecycleStatus;
import java.lang.reflect.InvocationTargetException;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.UUID;
import java.util.stream.Collectors;
import javax.ws.rs.core.Response;
import org.apache.commons.beanutils.BeanUtils;
import org.apache.commons.lang3.StringUtils;
import org.springframework.stereotype.Service;

@Service
public class ApplicationApiImpl extends AbstractApi implements ApplicationApi {

    @Override
    public Response activateApplication(final String appId) {
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
            return Response.ok(body).build();
        }

        return replaceApplication(body, body.getId());
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
    public Response getApplication(final String appId, final String expand) {
        return APPLICATION_REPOSITORY.stream().
                filter(app -> StringUtils.equals(appId, app.getId())).
                findAny().
                map(entity -> Response.ok().entity(entity).build()).
                orElseGet(() -> Response.status(Response.Status.NOT_FOUND).build());
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
            final Boolean useOptimization,
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
            Application found = APPLICATION_REPOSITORY.stream()
                    .filter(group -> StringUtils.equals(after, group.getId()))
                    .findAny()
                    .orElse(null);
            if (found != null) {
                int lastIndexOf = APPLICATION_REPOSITORY.lastIndexOf(found);
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
    public Response replaceApplication(final Application body, final String appId) {
        Application found = APPLICATION_REPOSITORY.stream()
                .filter(app -> StringUtils.equals(appId, app.getId()))
                .findAny()
                .orElse(null);
        if (found != null) {
            body.setId(found.getId());
            body.setCreated(found.getCreated());
            APPLICATION_REPOSITORY.remove(found);
            APPLICATION_REPOSITORY.add(body);
            body.setLastUpdated(Date.from(Instant.now()));
            createLogEvent("application.lifecycle.update", appId);
            return Response.ok().entity(body).build();
        }

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
}

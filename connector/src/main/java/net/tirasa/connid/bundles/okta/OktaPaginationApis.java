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
package net.tirasa.connid.bundles.okta;

import com.okta.sdk.resource.common.PagedList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;
import org.openapitools.client.api.ApplicationApi;
import org.openapitools.client.api.GroupApi;
import org.openapitools.client.api.UserApi;
import org.openapitools.client.model.Application;
import org.openapitools.client.model.Group;
import org.openapitools.client.model.User;
import org.springframework.http.ResponseEntity;
import org.springframework.web.client.RestClientException;

public class OktaPaginationApis {

    private static <T> PagedList<T> constructPagedList(final ResponseEntity<List<T>> responseEntity) {
        PagedList<T> pagedList = new PagedList<>();

        pagedList.addItems(responseEntity.getBody());

        for (String link : Optional.ofNullable(responseEntity.getHeaders().get("link")).
                orElse(Collections.emptyList())) {

            String[] parts = link.split("; *");
            String url = parts[0]
                    .replaceAll("<", "")
                    .replaceAll(">", "");
            String rel = parts[1];
            if (rel.equals("rel=\"next\"")) {
                pagedList.setNextPage(url);
            } else if (rel.equals("rel=\"self\"")) {
                pagedList.setSelf(url);
            }
        }

        return pagedList;
    }

    public static PagedList<User> listUsers(
            final UserApi userApi,
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String search,
            final String sortBy,
            final String sortOrder) throws RestClientException {

        ResponseEntity<List<User>> responseEntity =
                userApi.listUsersWithHttpInfo(q, after, limit, filter, search, sortBy, sortOrder);
        return constructPagedList(responseEntity);
    }

    public static PagedList<Application> listApplications(
            final ApplicationApi applicationApi,
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String expand,
            final Boolean includeNonDeleted) throws RestClientException {

        ResponseEntity<List<Application>> responseEntity =
                applicationApi.listApplicationsWithHttpInfo(q, after, limit, filter, expand, includeNonDeleted);
        return constructPagedList(responseEntity);
    }

    public static PagedList<Group> listGroups(
            final GroupApi groupApi,
            final String q,
            final String filter,
            final String after,
            final Integer limit,
            final String expand,
            final String search) throws RestClientException {

        ResponseEntity<List<Group>> responseEntity =
                groupApi.listGroupsWithHttpInfo(q, filter, after, limit, expand, search);
        return constructPagedList(responseEntity);
    }
}

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
import org.openapitools.client.api.ApplicationApi;
import org.openapitools.client.api.GroupApi;
import org.openapitools.client.api.UserApi;
import org.openapitools.client.model.Application;
import org.openapitools.client.model.Group;
import org.openapitools.client.model.User;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpMethod;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;
import org.springframework.web.client.RestClientException;

public class OktaPaginationApis {

    @SuppressWarnings("rawtypes")
    public static PagedList listUsers(
            final UserApi userApi,
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String search,
            final String sortBy,
            final String sortOrder) throws RestClientException {

        Object localVarPostBody = null;

        final MultiValueMap<String, String> localVarQueryParams = new LinkedMultiValueMap<>();
        final HttpHeaders localVarHeaderParams = new HttpHeaders();
        final MultiValueMap<String, String> localVarCookieParams = new LinkedMultiValueMap<>();
        final MultiValueMap<String, Object> localVarFormParams = new LinkedMultiValueMap<>();

        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "q", q));
        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "after", after));
        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "limit", limit));
        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "filter", filter));
        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "search", search));
        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "sortBy", sortBy));
        localVarQueryParams.putAll(userApi.getApiClient().parameterToMultiValueMap(null, "sortOrder", sortOrder));

        final String[] localVarAccepts = { "application/json" };
        final List<MediaType> localVarAccept = userApi.getApiClient().selectHeaderAccept(localVarAccepts);
        final String[] localVarContentTypes = {};
        final MediaType localVarContentType = userApi.getApiClient().selectHeaderContentType(localVarContentTypes);

        String[] localVarAuthNames = new String[] { "apiToken", "oauth2" };

        ParameterizedTypeReference<List<User>> localReturnType = new ParameterizedTypeReference<List<User>>() {
        };
        ResponseEntity<List<User>> responseEntity = userApi.getApiClient().invokeAPI(
                "/api/v1/users",
                HttpMethod.GET,
                Collections.<String, Object>emptyMap(),
                localVarQueryParams,
                localVarPostBody,
                localVarHeaderParams,
                localVarCookieParams,
                localVarFormParams,
                localVarAccept,
                localVarContentType,
                localVarAuthNames,
                localReturnType);
        return PagedList.constructPagedList(responseEntity);
    }

    @SuppressWarnings("rawtypes")
    public static PagedList listApplications(
            final ApplicationApi apApi,
            final String q,
            final String after,
            final Integer limit,
            final String filter,
            final String expand,
            final Boolean includeNonDeleted) throws RestClientException {

        Object localVarPostBody = null;

        final MultiValueMap<String, String> localVarQueryParams = new LinkedMultiValueMap<>();
        final HttpHeaders localVarHeaderParams = new HttpHeaders();
        final MultiValueMap<String, String> localVarCookieParams = new LinkedMultiValueMap<>();
        final MultiValueMap<String, Object> localVarFormParams = new LinkedMultiValueMap<>();

        localVarQueryParams.putAll(apApi.getApiClient().parameterToMultiValueMap(null, "q", q));
        localVarQueryParams.putAll(apApi.getApiClient().parameterToMultiValueMap(null, "after", after));
        localVarQueryParams.putAll(apApi.getApiClient().parameterToMultiValueMap(null, "limit", limit));
        localVarQueryParams.putAll(apApi.getApiClient().parameterToMultiValueMap(null, "filter", filter));
        localVarQueryParams.putAll(apApi.getApiClient().parameterToMultiValueMap(null, "expand", expand));
        localVarQueryParams.putAll(apApi.getApiClient().
                parameterToMultiValueMap(null, "includeNonDeleted", includeNonDeleted));

        final String[] localVarAccepts = { "application/json" };
        final List<MediaType> localVarAccept = apApi.getApiClient().selectHeaderAccept(localVarAccepts);
        final String[] localVarContentTypes = {};
        final MediaType localVarContentType = apApi.getApiClient().selectHeaderContentType(localVarContentTypes);

        String[] localVarAuthNames = new String[] { "apiToken", "oauth2" };

        ParameterizedTypeReference<List<Application>> localReturnType =
                new ParameterizedTypeReference<List<Application>>() {
        };
        ResponseEntity<List<Application>> responseEntity = apApi.getApiClient().invokeAPI(
                "/api/v1/apps",
                HttpMethod.GET,
                Collections.<String, Object>emptyMap(),
                localVarQueryParams,
                localVarPostBody,
                localVarHeaderParams,
                localVarCookieParams,
                localVarFormParams,
                localVarAccept,
                localVarContentType,
                localVarAuthNames,
                localReturnType);
        return PagedList.constructPagedList(responseEntity);
    }

    @SuppressWarnings("rawtypes")
    public static PagedList listGroups(
            final GroupApi groupApi,
            final String q,
            final String filter,
            final String after,
            final Integer limit,
            final String expand,
            final String search) throws RestClientException {

        Object localVarPostBody = null;

        final MultiValueMap<String, String> localVarQueryParams = new LinkedMultiValueMap<>();
        final HttpHeaders localVarHeaderParams = new HttpHeaders();
        final MultiValueMap<String, String> localVarCookieParams = new LinkedMultiValueMap<>();
        final MultiValueMap<String, Object> localVarFormParams = new LinkedMultiValueMap<>();

        localVarQueryParams.putAll(groupApi.getApiClient().parameterToMultiValueMap(null, "q", q));
        localVarQueryParams.putAll(groupApi.getApiClient().parameterToMultiValueMap(null, "filter", filter));
        localVarQueryParams.putAll(groupApi.getApiClient().parameterToMultiValueMap(null, "after", after));
        localVarQueryParams.putAll(groupApi.getApiClient().parameterToMultiValueMap(null, "limit", limit));
        localVarQueryParams.putAll(groupApi.getApiClient().parameterToMultiValueMap(null, "expand", expand));
        localVarQueryParams.putAll(groupApi.getApiClient().parameterToMultiValueMap(null, "search", search));

        final String[] localVarAccepts = { "application/json" };
        final List<MediaType> localVarAccept = groupApi.getApiClient().selectHeaderAccept(localVarAccepts);
        final String[] localVarContentTypes = {};
        final MediaType localVarContentType = groupApi.getApiClient().selectHeaderContentType(localVarContentTypes);

        String[] localVarAuthNames = new String[] { "apiToken", "oauth2" };

        ParameterizedTypeReference<List<Group>> localReturnType = new ParameterizedTypeReference<List<Group>>() {
        };
        ResponseEntity<List<Group>> responseEntity = groupApi.getApiClient().invokeAPI(
                "/api/v1/groups",
                HttpMethod.GET,
                Collections.<String, Object>emptyMap(),
                localVarQueryParams,
                localVarPostBody,
                localVarHeaderParams,
                localVarCookieParams,
                localVarFormParams,
                localVarAccept,
                localVarContentType,
                localVarAuthNames,
                localReturnType);
        return PagedList.constructPagedList(responseEntity);
    }
}

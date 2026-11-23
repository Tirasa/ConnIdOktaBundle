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

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;

import io.swagger.model.Application;
import io.swagger.model.ApplicationSignOnMode;
import io.swagger.model.BasicAuthApplication;
import io.swagger.model.Group;
import io.swagger.model.OktaUserGroupProfile;
import io.swagger.model.User;
import io.swagger.model.UserProfile;
import io.swagger.model.UserStatus;
import java.io.IOException;
import java.net.URI;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.UnaryOperator;
import java.util.stream.Collectors;
import java.util.stream.IntStream;
import java.util.stream.Stream;
import net.tirasa.connid.bundles.okta.servermock.impl.AbstractApi;
import net.tirasa.connid.bundles.okta.utils.OktaFilter;
import net.tirasa.connid.bundles.okta.utils.OktaFilterOp;
import org.apache.hc.client5.http.impl.classic.CloseableHttpClient;
import org.apache.hc.client5.http.impl.classic.CloseableHttpResponse;
import org.apache.hc.core5.http.ClassicHttpRequest;
import org.apache.hc.core5.http.HttpHost;
import org.apache.hc.core5.http.protocol.HttpContext;
import org.apache.hc.core5.io.CloseMode;
import org.identityconnectors.framework.common.exceptions.ConnectorException;
import org.identityconnectors.framework.common.exceptions.PermissionDeniedException;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.junit.jupiter.params.provider.ValueSource;

public class UnpagedSearchTests extends AbstractConnectorTests {

    private MockData data;

    private CloseableHttpClient originalHttpClient;

    private TrackingHttpClient transport;

    @BeforeEach
    public void saveData() {
        data = new MockData();
        originalHttpClient = CONN.getUserApi().getApiClient().getHttpClient();
        transport = new TrackingHttpClient(originalHttpClient);
        CONN.getUserApi().getApiClient().setHttpClient(transport);
    }

    @AfterEach
    public void restoreData() {
        data.restore();
        CONN.getUserApi().getApiClient().setHttpClient(originalHttpClient);
    }

    private static Stream<Arguments> searchCases() {
        return Stream.of(ObjectClass.ACCOUNT, ObjectClass.GROUP, OktaConnector.APPLICATION)
                .flatMap(objectClass -> Stream.of(0, 1, 200, 201, 400, 401)
                        .map(count -> Arguments.of(objectClass, count)));
    }

    @ParameterizedTest
    @MethodSource("searchCases")
    public void retrievesAllResultsWithoutPaging(final ObjectClass objectClass, final int count) {
        data.populate(count);
        ToListResultsHandler handler = new ToListResultsHandler();
        SearchResult result = FACADE.search(objectClass, null, handler, new OperationOptionsBuilder()
                .setAttributesToGet(Name.NAME, Uid.NAME).build());
        assertEquals(ids(count), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    @Test
    public void preservesFilterAcrossPages() {
        data.populate(401);
        MockData.excludeFirstUserFromFilter();
        ToListResultsHandler handler = new ToListResultsHandler();
        FACADE.search(ObjectClass.ACCOUNT,
                FilterBuilder.equalTo(AttributeBuilder.build("firstName", "Test")), handler,
                new OperationOptionsBuilder().setAttributesToGet("firstName").build());
        assertEquals(ids(401).subList(1, 401), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
    }

    @ParameterizedTest
    @ValueSource(ints = { 100, 400 })
    public void followsNextLinkAfterShortOrEmptyPage(final int deactivated) {
        data.populate(401);
        MockData.deactivateFirstUsers(deactivated);
        ToListResultsHandler handler = new ToListResultsHandler();
        FACADE.search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertEquals(ids(401).subList(deactivated, 401), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
    }

    @ParameterizedTest
    @ValueSource(ints = { 1, 200, 201 })
    public void stopsFetchingWhenHandlerStops(final int stopAt) {
        data.populate(401);
        AtomicInteger handled = new AtomicInteger();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, object -> {
            return handled.incrementAndGet() < stopAt;
        }, new OperationOptionsBuilder().build());
        assertEquals(stopAt, handled.get());
        assertEquals((stopAt + 199) / 200, transport.requests.size());
    }

    @Test
    public void retainsNextLinkWhenHandlerMakesAnotherRequest() {
        data.populate(201);
        List<String> found = new ArrayList<>();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, object -> {
            found.add(object.getUid().getUidValue());
            CONN.getUserApi().getUser(object.getUid().getUidValue(), null, null);
            return true;
        }, new OperationOptionsBuilder().build());
        assertEquals(ids(201), found);
    }

    @Test
    public void propagatesFailureOnLaterPage() {
        data.populate(201);
        transport.failAfterFirstPage = true;
        ToListResultsHandler handler = new ToListResultsHandler();
        assertThrows(PermissionDeniedException.class, () -> CONN.executeQuery(
                ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build()));
        assertEquals(200, handler.getObjects().size());
        assertEquals(2, transport.requests.size());
    }

    @Test
    public void preservesApplicationFilterAcrossPages() {
        data.populate(401);
        MockData.prepareApplicationFilter();
        ToListResultsHandler handler = new ToListResultsHandler();
        CONN.executeQuery(OktaConnector.APPLICATION,
                new OktaFilter(OktaFilterOp.EQUALS, "label", "Test", true, null),
                handler, new OperationOptionsBuilder().build());
        assertEquals(ids(401).subList(1, 401), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
    }

    @Test
    public void acceptsCombinedLinkHeaders() {
        data.populate(201);
        transport.combineLinks = true;
        ToListResultsHandler handler = new ToListResultsHandler();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertEquals(201, handler.getObjects().size());
        assertEquals(2, transport.requests.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "; rel=next",
        "; type=\"application/json\"; rel=\"next\"",
        "; title=\"page, ; rel=prev\"; rel=next",
        "; title=\"page \\\"two\\\", next\"; rel=next",
        "; rel=\"prev next\"",
        "; REL = NEXT"
    })
    public void acceptsNextLinkParameters(final String parameters) {
        data.populate(201);
        transport.transformLink = link -> link.replace("; rel=\"next\"", parameters);
        ToListResultsHandler handler = new ToListResultsHandler();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertEquals(ids(201), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
        assertEquals(2, transport.requests.size());
    }

    @Test
    public void followsCompleteNextUrl() {
        data.populate(203);
        transport.transformLink = link -> link.replace("after=id-200&limit=200",
                "after=id%2D200&limit=1&opaque=a%2Bb%2Fc");
        ToListResultsHandler handler = new ToListResultsHandler();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertEquals(ids(203), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
        assertEquals(4, transport.requests.size());
        assertEquals("after=id%2D200&limit=1&opaque=a%2Bb%2Fc",
                URI.create(transport.requests.get(1)).getRawQuery());
    }

    @ParameterizedTest
    @ValueSource(strings = { "/okta/api/v1/users", "users", "" })
    public void followsRelativeNextUrl(final String path) {
        data.populate(201);
        transport.transformLink = link -> link.replace("https://localhost:8443/okta/api/v1/users", path);
        ToListResultsHandler handler = new ToListResultsHandler();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertEquals(ids(201), handler.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
        assertEquals(2, transport.requests.size());
    }

    @ParameterizedTest
    @ValueSource(strings = {
        "https://example.invalid/okta/api/v1/users?after=id-200",
        "http://localhost:8443/okta/api/v1/users?after=id-200",
        "https://localhost:9443/okta/api/v1/users?after=id-200",
        "https://user@localhost:8443/okta/api/v1/users?after=id-200",
        "https://localhost:8443/okta/api/v1/users?after=id-200#fragment"
    })
    public void rejectsInvalidNextUrl(final String url) {
        data.populate(201);
        transport.transformLink = link -> "<" + url + ">; rel=next";
        assertThrows(ConnectorException.class, () -> CONN.executeQuery(ObjectClass.ACCOUNT, null,
                new ToListResultsHandler(), new OperationOptionsBuilder().build()));
        assertEquals(1, transport.requests.size());
    }

    @Test
    public void acceptsLastPageWithoutLinkHeader() {
        data.populate(1);
        transport.omitLinks = true;
        ToListResultsHandler handler = new ToListResultsHandler();
        CONN.executeQuery(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertEquals(1, handler.getObjects().size());
        assertEquals(1, transport.requests.size());
    }

    @Test
    public void rejectsRepeatedLink() {
        data.populate(401);
        transport.repeatLink = true;
        assertThrows(ConnectorException.class, () -> CONN.executeQuery(ObjectClass.ACCOUNT, null,
                new ToListResultsHandler(), new OperationOptionsBuilder().build()));
        assertEquals(2, transport.requests.size());
    }

    @Test
    public void preservesExplicitCookiePaging() {
        data.populate(201);
        ToListResultsHandler first = new ToListResultsHandler();
        SearchResult result = FACADE.search(ObjectClass.ACCOUNT, null, first,
                new OperationOptionsBuilder().setPageSize(200).build());
        assertEquals(200, first.getObjects().size());
        assertNotNull(result.getPagedResultsCookie());
        ToListResultsHandler last = new ToListResultsHandler();
        FACADE.search(ObjectClass.ACCOUNT, null, last, new OperationOptionsBuilder()
                .setPageSize(200).setPagedResultsCookie(result.getPagedResultsCookie()).build());
        assertEquals(List.of("id-200"), last.getObjects().stream()
                .map(object -> object.getUid().getUidValue()).collect(Collectors.toList()));
    }

    private static List<String> ids(final int count) {
        return IntStream.range(0, count).mapToObj(i -> "id-" + i).collect(Collectors.toList());
    }

    private static class TrackingHttpClient extends CloseableHttpClient {

        private final CloseableHttpClient delegate;

        private final List<String> requests = new ArrayList<>();

        private boolean failAfterFirstPage;

        private boolean combineLinks;

        private boolean omitLinks;

        private boolean repeatLink;

        private String firstLink;

        private UnaryOperator<String> transformLink = UnaryOperator.identity();

        TrackingHttpClient(final CloseableHttpClient delegate) {
            this.delegate = delegate;
        }

        @SuppressWarnings("deprecation")
        @Override
        protected CloseableHttpResponse doExecute(
                final HttpHost target, final ClassicHttpRequest request, final HttpContext context)
                throws IOException {

            // Keep all test requests on the project's mock server, including invalid-link cases.
            assertEquals("https", target.getSchemeName());
            assertEquals("localhost", target.getHostName());
            assertEquals(8443, target.getPort());
            boolean users = URI.create(request.getRequestUri()).getPath().endsWith("/api/v1/users");
            if (users) {
                requests.add(request.getRequestUri());
            }
            CloseableHttpResponse response = delegate.execute(target, request, context);
            if (users) {
                String link = response.getFirstHeader("link").getValue();
                if (requests.size() == 1) {
                    firstLink = link;
                }
                if (failAfterFirstPage && requests.size() > 1) {
                    response.setCode(403);
                }
                response.removeHeaders("link");
                if (combineLinks) {
                    response.addHeader("LiNk", "<https://localhost/okta/api/v1/users>; rel=\"self\", " + link);
                } else if (!omitLinks) {
                    response.addHeader("link", transformLink.apply(repeatLink ? firstLink : link));
                }
            }
            return response;
        }

        @Override
        public void close() {
            // The connector owns the underlying client.
        }

        @Override
        public void close(final CloseMode closeMode) {
            // The connector owns the underlying client.
        }
    }

    private static class MockData extends AbstractApi {

        private final List<User> users = new ArrayList<>(USER_REPOSITORY);

        private final List<Group> groups = new ArrayList<>(GROUP_REPOSITORY);

        private final List<Application> applications = new ArrayList<>(APPLICATION_REPOSITORY);

        void populate(final int count) {
            USER_REPOSITORY.clear();
            GROUP_REPOSITORY.clear();
            APPLICATION_REPOSITORY.clear();
            for (String id : ids(count)) {
                UserProfile profile = new UserProfile();
                profile.put("login", id + "@example.test");
                profile.put("firstName", "Test");
                USER_REPOSITORY.add(new User().id(id).status(UserStatus.ACTIVE).profile(profile));
                GROUP_REPOSITORY.add(new Group().id(id).profile(new OktaUserGroupProfile().name(id)));
                APPLICATION_REPOSITORY.add(new BasicAuthApplication()
                        .name(BasicAuthApplication.NameEnum.TEMPLATE_BASIC_AUTH).id(id).label(id)
                        .signOnMode(ApplicationSignOnMode.BASIC_AUTH));
            }
        }

        static void prepareApplicationFilter() {
            APPLICATION_REPOSITORY.forEach(application -> application.setLabel("Test"));
            APPLICATION_REPOSITORY.get(0).setLabel("Other");
        }

        static void excludeFirstUserFromFilter() {
            USER_REPOSITORY.get(0).getProfile().put("firstName", "Other");
        }

        static void deactivateFirstUsers(final int count) {
            USER_REPOSITORY.subList(0, count).forEach(user -> user.setStatus(UserStatus.DEPROVISIONED));
        }

        void restore() {
            USER_REPOSITORY.clear();
            USER_REPOSITORY.addAll(users);
            GROUP_REPOSITORY.clear();
            GROUP_REPOSITORY.addAll(groups);
            APPLICATION_REPOSITORY.clear();
            APPLICATION_REPOSITORY.addAll(applications);
        }
    }
}

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

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

import java.util.Arrays;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.test.common.TestHelpers;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;
import org.openapitools.client.model.Group;
import org.openapitools.client.model.User;
import org.openapitools.client.model.UserStatus;

public class OktaConnectorTests extends AbstractConnectorTests {

    private static final Log LOG = Log.getLog(OktaConnectorTests.class);

    private static final String ENTITLEMENTS_ATTR = "entitlements";

    @BeforeClass
    public static void setupData() {
        createSearchTestData();
    }

    @AfterClass
    public static void cleanTestData() {
        USERS.stream().forEach(item -> cleanUserTestData(CONN.getUserApi(), item));
        GROUPS.stream().forEach(item -> cleanGroupTestData(CONN.getGroupApi(), item));
        APPLICATIONS.stream().forEach(item -> cleanApplicationTestData(CONN.getApplicationApi(), item));
    }

    protected static ConnectorFacade newFacade() {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(OktaConnector.class, CONF);
        impl.getResultsHandlerConfiguration().setFilteredResultsHandlerInValidationMode(true);
        return factory.newInstance(impl);
    }

    @Test
    public void schema() {
        Schema schema = newFacade().schema();
        assertEquals(3, schema.getObjectClassInfo().size());
        List<String> objs = Arrays.asList(
                ObjectClass.ACCOUNT_NAME, ObjectClass.GROUP_NAME, OktaConnector.APPLICATION_NAME);
        assertTrue(schema.getObjectClassInfo().stream().allMatch(item -> objs.contains(item.getType())));
    }

    @Test
    public void searchUser() {
        ToListResultsHandler handler = new ToListResultsHandler();

        SearchResult result = FACADE.search(
                ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = FACADE.search(
                ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    @Test
    public void crudUser() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption = new OperationOptionsBuilder().
                setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE, ENTITLEMENTS_ATTR).build();
        try {
            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Attribute mobilePhone = AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "123456789");

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(ENTITLEMENTS_ATTR, "{}"));
            userAttrs.add(mobilePhone);
            userAttrs.add(password);

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            USERS.add(created.getUidValue());
            assertNotNull(created);

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            Attribute entitlements = handler.getObjects().get(0).getAttributeByName(ENTITLEMENTS_ATTR);
            assertNotNull(entitlements);
            assertEquals(Collections.singletonList("{}"), entitlements.getValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            Attribute newMobilePhone = AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "987654321");
            userAttrs.remove(mobilePhone);
            userAttrs.remove(password);
            userAttrs.add(newMobilePhone);
            Uid updated = FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);

            // GET USER
            handler = new ToListResultsHandler();
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            assertEquals(
                    AttributeUtil.getAsStringValue(newMobilePhone),
                    AttributeUtil.getAsStringValue(
                            handler.getObjects().get(0).getAttributeByName(OktaAttribute.MOBILEPHONE)));

            // DELETE USER
            FACADE.delete(ObjectClass.ACCOUNT, updated, operationOption);

            // CHECK IF USER EXISTS
            handler = new ToListResultsHandler();
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertTrue(handler.getObjects().isEmpty());
        } catch (Exception e) {
            LOG.error(e, "While running test");
            fail(e.getMessage());
        }
    }

    @Test
    public void changeUserPassword() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption = new OperationOptionsBuilder().
                setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        try {
            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Federico123".toCharArray()));
            Attribute newPassword = AttributeBuilder.buildPassword(new GuardedString("123Federico".toCharArray()));

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(password);

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            userAttrs.remove(password);
            userAttrs.add(newPassword);
            Uid updated = FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);
        } catch (Exception e) {
            fail();
            LOG.error(e, "While running test");
        }
    }

    @Test
    public void assignUserToGroup() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(OktaAttribute.EMAIL,
                        OktaAttribute.MOBILEPHONE,
                        OktaAttribute.OKTA_GROUPS).build();
        try {
            Group groupCreate = createGroup(CONN.getGroupApi());
            assertNotNull(groupCreate.getId());
            GROUPS.add(groupCreate.getId());

            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(password);
            userAttrs.add(AttributeBuilder.build(OktaAttribute.OKTA_GROUPS, groupCreate.getId()));

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            Set<String> assignedGroups = getUserGroups(CONN.getUserApi(), created.getUidValue());
            assertTrue(assignedGroups.contains(groupCreate.getId()));

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            Group groupUpdate = createGroup(CONN.getGroupApi());
            assertNotNull(groupUpdate.getId());
            GROUPS.add(groupUpdate.getId());

            // UPDATE USER
            userAttrs.remove(password);
            userAttrs.add(AttributeBuilder.build(OktaAttribute.OKTA_GROUPS, groupUpdate.getId()));

            Uid updated = FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);

            assignedGroups = getUserGroups(CONN.getUserApi(), updated.getUidValue());
            assertTrue(assignedGroups.contains(groupUpdate.getId()));
        } catch (Exception e) {
            LOG.error(e, "While running test");
            throw e;
            //fail();
        }
    }

    @Test
    public void removeUserFromGroup() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption = new OperationOptionsBuilder().
                setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        try {
            Group groupOne = createGroup(CONN.getGroupApi());
            Group groupTwo = createGroup(CONN.getGroupApi());
            assertNotNull(groupOne.getId());
            assertNotNull(groupTwo.getId());
            GROUPS.add(groupOne.getId());
            GROUPS.add(groupTwo.getId());

            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(password);
            userAttrs.add(AttributeBuilder.build(OktaAttribute.OKTA_GROUPS, groupOne.getId(), groupTwo.getId()));

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            Set<String> assignedGroups = getUserGroups(CONN.getUserApi(), created.getUidValue());
            assertTrue(assignedGroups.contains(groupOne.getId()));
            assertTrue(assignedGroups.contains(groupTwo.getId()));

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            userAttrs.remove(password);
            userAttrs.add(AttributeBuilder.build(OktaAttribute.OKTA_GROUPS));

            Uid updated = FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);

            assignedGroups = getUserGroups(CONN.getUserApi(), updated.getUidValue());
            assertFalse(assignedGroups.contains(groupOne.getId()));
            assertFalse(assignedGroups.contains(groupTwo.getId()));
        } catch (Exception e) {
            fail(e.getMessage());
            LOG.error(e, "While running test");
        }
    }

    @Test
    public void searchApplication() {
        ToListResultsHandler handler = new ToListResultsHandler();

        SearchResult result = FACADE.
                search(OktaConnector.APPLICATION, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = FACADE.
                search(OktaConnector.APPLICATION, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    @Test
    public void searchGroup() {
        ToListResultsHandler handler = new ToListResultsHandler();

        SearchResult result = FACADE.
                search(ObjectClass.GROUP, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = FACADE.
                search(ObjectClass.GROUP, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    @Test
    public void searchUserDifferentAttribute() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption = new OperationOptionsBuilder().setAttributesToGet(
                OktaAttribute.EMAIL, OktaAttribute.LOGIN, OktaAttribute.MOBILEPHONE).build();
        // CREATE USER
        String username = UUID.randomUUID().toString();
        Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
        Set<Attribute> userAttrs = new HashSet<>();
        userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.LOGIN, username + "@tirasa.net"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
        userAttrs.add(password);

        Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
        assertNotNull(created);
        USERS.add(created.getUidValue());

        // GET USER
        Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("login", username + "@tirasa.net"));
        FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
        assertNotNull(handler.getObjects());
        assertFalse(handler.getObjects().isEmpty());
        assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());

        handler.getObjects().clear();

        // SEARCH USER
        filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
        FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
        assertNotNull(handler.getObjects());
        assertFalse(handler.getObjects().isEmpty());
        assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
    }

    @Test
    public void sync() {
        TestSyncResultsHandler handler = new TestSyncResultsHandler();

        OperationOptionsBuilder operationOptionBuilder = new OperationOptionsBuilder().
                setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE, OktaAttribute.OKTA_GROUPS);

        SyncToken token = FACADE.getLatestSyncToken(ObjectClass.ACCOUNT);
        FACADE.sync(ObjectClass.ACCOUNT, token, handler, operationOptionBuilder.build());

        assertTrue(handler.getDeleted().isEmpty());
        assertTrue(handler.getUpdated().isEmpty());

        handler.clear();

        // user added sync
        Uid newUser = FACADE.create(
                ObjectClass.ACCOUNT, createUserAttrs("Password123"), operationOptionBuilder.build());
        FACADE.sync(ObjectClass.ACCOUNT, token, handler, operationOptionBuilder.build());
        assertFalse(token.equals(handler.getLatestReceivedToken()));

        token = handler.getLatestReceivedToken();

        assertFalse(handler.getUpdated().isEmpty());
        assertTrue(handler.getDeleted().isEmpty());

        handler.getUpdated().forEach(usr -> {
            ConnectorObject obj = usr.getObject();
            assertEquals(newUser.getUidValue(), obj.getUid().getValue().get(0));
            assertNotNull(obj.getAttributeByName(OktaAttribute.EMAIL));
            assertNotNull(obj.getAttributeByName(OktaAttribute.MOBILEPHONE));
            assertNotNull(obj.getName());
            assertNotNull(obj.getUid());
        });

        handler.clear();

        // check with updated token and without any modification
        FACADE.sync(ObjectClass.ACCOUNT, token, handler, operationOptionBuilder.build());
        assertEquals(token, handler.getLatestReceivedToken());

        token = handler.getLatestReceivedToken();

        assertTrue(handler.getDeleted().isEmpty());
        assertTrue(handler.getUpdated().isEmpty());

        // created a new user without memberships
        Uid created = FACADE.create(ObjectClass.ACCOUNT,
                createUserAttrs("Password123"), operationOptionBuilder.build());
        handler.clear();

        FACADE.sync(ObjectClass.ACCOUNT, token, handler, operationOptionBuilder.build());
        assertFalse(token.equals(handler.getLatestReceivedToken()));

        token = handler.getLatestReceivedToken();

        assertTrue(handler.getDeleted().isEmpty());
        assertFalse(handler.getUpdated().isEmpty());

        // add membership to existing user
        Group group = createGroup(CONN.getGroupApi());
        CONN.getGroupApi().assignUserToGroup(group.getId(), created.getUidValue());
        handler.clear();

        FACADE.sync(ObjectClass.ACCOUNT, token, handler, operationOptionBuilder.build());
        assertFalse(token.equals(handler.getLatestReceivedToken()));

        token = handler.getLatestReceivedToken();

        assertTrue(handler.getDeleted().isEmpty());
        assertFalse(handler.getUpdated().isEmpty());

        handler.clear();

        // sync user delete
        assertTrue(Arrays.asList(CONF.getUserEvents()).contains("user.lifecycle.delete"));

        FACADE.delete(ObjectClass.ACCOUNT, created, operationOptionBuilder.build());

        FACADE.sync(ObjectClass.ACCOUNT, token, handler, operationOptionBuilder.build());
        token = handler.getLatestReceivedToken();
        assertNotNull(token);

        assertTrue(handler.getUpdated().isEmpty());
        assertEquals(1, handler.getDeleted().size());
    }

    @Test
    public void suspendUnsuspend() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(
                        OktaAttribute.EMAIL,
                        OktaAttribute.MOBILEPHONE,
                        OperationalAttributes.ENABLE_NAME).build();
        try {
            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Attribute mobilePhone = AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "123456789");

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OperationalAttributes.ENABLE_NAME, true));
            userAttrs.add(mobilePhone);
            userAttrs.add(password);

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            USERS.add(created.getUidValue());
            assertNotNull(created);

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());

            assertTrue(AttributeUtil.isEnabled(handler.getObjects().get(0)));
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            userAttrs.remove(mobilePhone);
            userAttrs.remove(password);
            Attribute enable = AttributeBuilder.build(OperationalAttributes.ENABLE_NAME, false);
            userAttrs.add(enable);
            Uid updated = FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);

            assertNotNull(updated);
            assertTrue(AttributeUtil.isEnabled(handler.getObjects().get(0)));

            //GET USER
            handler = new ToListResultsHandler();
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertFalse(AttributeUtil.isEnabled(handler.getObjects().get(0)));

            userAttrs.remove(enable);
            userAttrs.add(AttributeBuilder.build(OperationalAttributes.ENABLE_NAME, true));
            FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);

            //GET USER
            handler = new ToListResultsHandler();
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertTrue(AttributeUtil.isEnabled(handler.getObjects().get(0)));
        } catch (Exception e) {
            LOG.error(e, "While running test");
            fail(e.getMessage());
        }
    }

    @Test
    public void createUserWithStatusStaged() {
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(
                        OktaAttribute.EMAIL,
                        OktaAttribute.MOBILEPHONE,
                        OperationalAttributes.ENABLE_NAME).build();

        // CREATE USER
        String username = UUID.randomUUID().toString();
        Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
        Attribute mobilePhone = AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "123456789");

        Set<Attribute> userAttrs = new HashSet<>();
        userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
        userAttrs.add(AttributeBuilder.build(OperationalAttributes.ENABLE_NAME, false));
        userAttrs.add(mobilePhone);
        userAttrs.add(password);

        Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
        USERS.add(created.getUidValue());
        assertNotNull(created);

        User user = CONN.getUserApi().getUser(created.getUidValue());
        assertEquals(UserStatus.STAGED, user.getStatus());
    }

    @Test
    public void changePasswordWithOldValidation() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions oo = new OperationOptionsBuilder().
                setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        try {
            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Federico123".toCharArray()));
            Attribute newPassword = AttributeBuilder.buildPassword(new GuardedString("123Federico".toCharArray()));

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(password);

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, oo);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, oo);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            Attribute currentPassword = AttributeBuilder.build(OperationalAttributes.CURRENT_PASSWORD_NAME,
                    new GuardedString("Federico123".toCharArray()));
            userAttrs.remove(password);

            userAttrs.add(currentPassword);
            userAttrs.add(newPassword);

            Uid updated = FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, oo);
            assertNotNull(updated);
        } catch (Exception e) {
            fail();
            LOG.error(e, "While running test");
        }
    }

    @Test
    public void oldPasswordNotValid() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions oo = new OperationOptionsBuilder().
                setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        try {
            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Federico123".toCharArray()));
            Attribute newPassword = AttributeBuilder.buildPassword(new GuardedString("123Federico".toCharArray()));

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(password);

            Uid created = FACADE.create(ObjectClass.ACCOUNT, userAttrs, oo);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            // GET USER
            Filter filter = FilterBuilder.equalTo(AttributeBuilder.build("email", username + "@tirasa.net"));
            FACADE.search(ObjectClass.ACCOUNT, filter, handler, oo);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            Attribute currentPassword = AttributeBuilder.build(
                    OperationalAttributes.CURRENT_PASSWORD_NAME, new GuardedString("Federico".toCharArray()));
            userAttrs.remove(password);

            userAttrs.add(currentPassword);
            userAttrs.add(newPassword);

            FACADE.update(ObjectClass.ACCOUNT, created, userAttrs, oo);
            fail();
        } catch (Exception e) {
            LOG.error(e, "While running test");
        }
    }
}

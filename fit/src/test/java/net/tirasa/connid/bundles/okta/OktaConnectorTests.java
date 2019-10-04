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

import com.okta.sdk.resource.group.Group;
import java.io.IOException;
import java.io.InputStream;
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
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.FilterBuilder;
import org.identityconnectors.test.common.TestHelpers;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.junit.AfterClass;
import org.junit.BeforeClass;
import org.junit.Test;

public class OktaConnectorTests extends AbstractConnectorTests {

    private static final Log LOG = Log.getLog(OktaConnectorTests.class);

    private static OktaConfiguration conf;

    @BeforeClass
    public static void setUpConf() {
        try {
            InputStream propStream =
                    OktaConnectorTests.class.getResourceAsStream("/okta.properties");
            PROPS.load(propStream);
        } catch (IOException e) {
            fail("Could not load okta.properties: " + e.getMessage());
        }

        conf = new OktaConfiguration();
        conf.setDomain(PROPS.getProperty("domain"));
        conf.setOktaApiToken(PROPS.getProperty("oktaApiToken"));
        conf.setPasswordHashAlgorithm(PROPS.getProperty("passwordHashAlgorithm"));

        try {
            conf.validate();
            conn = new OktaConnector();
            conn.init(conf);
            conn.test();

        } catch (Exception e) {
            LOG.error(e, "While testing connector");
        }
        conn.schema();
        connector = newFacade();

        assertNotNull(conf);
        assertNotNull(conf.getDomain());
        assertNotNull(conf.getOktaApiToken());
        assertNotNull(conf.getPasswordHashAlgorithm());

        createSearchTestData();
    }

    protected static ConnectorFacade newFacade() {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(OktaConnector.class, conf);
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

        SearchResult result = connector.
                search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = connector.
                search(ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    @Test
    public void crudUser() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        try {
            // CREATE USER
            String username = UUID.randomUUID().toString();
            Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
            Attribute mobilePhone = AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "123456789");

            Set<Attribute> userAttrs = new HashSet<>();
            userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
            userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
            userAttrs.add(mobilePhone);
            userAttrs.add(password);

            Uid created = connector.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            USERS.add(created.getUidValue());
            assertNotNull(created);

            // GET USER
            EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(
                    AttributeBuilder.build("email", username + "@tirasa.net"));
            connector.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            Attribute newMobilePhone = AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "987654321");
            userAttrs.remove(mobilePhone);
            userAttrs.remove(password);
            userAttrs.add(newMobilePhone);
            Uid updated = connector.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);

            //GET USER
            handler = new ToListResultsHandler();
            connector.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            assertEquals(
                    AttributeUtil.getAsStringValue(newMobilePhone),
                    AttributeUtil.getAsStringValue(
                            handler.getObjects().get(0).getAttributeByName(OktaAttribute.MOBILEPHONE)));
            //DELETE USER
            connector.delete(ObjectClass.ACCOUNT, updated, operationOption);
            handler = new ToListResultsHandler();
            //CHECK IF USER EXISTS
            connector.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertTrue(handler.getObjects().isEmpty());
        } catch (Exception e) {
            LOG.error(e, "While running test");
            fail(e.getMessage());
        }
    }

    @Test
    public void changeUserPassword() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
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

            Uid created = connector.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            // GET USER
            EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(
                    AttributeBuilder.build("email", username + "@tirasa.net"));
            connector.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            userAttrs.remove(password);
            userAttrs.add(newPassword);
            Uid updated = connector.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
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
                        ObjectClass.GROUP_NAME).build();
        try {
            Group groupCreate = createGroup(conn.getClient());
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
            userAttrs.add(AttributeBuilder.build(ObjectClass.GROUP_NAME, groupCreate.getId()));

            Uid created = connector.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            Set<String> assignedGroups = getUserGroups(conn.getClient(), created.getUidValue());
            assertTrue(assignedGroups.contains(groupCreate.getId()));

            // GET USER
            EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(
                    AttributeBuilder.build("email", username + "@tirasa.net"));
            connector.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            Group groupUpdate = createGroup(conn.getClient());
            assertNotNull(groupUpdate.getId());
            GROUPS.add(groupUpdate.getId());

            // UPDATE USER
            userAttrs.remove(password);
            userAttrs.add(AttributeBuilder.build(ObjectClass.GROUP_NAME, groupUpdate.getId()));

            Uid updated = connector.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);

            assignedGroups = getUserGroups(conn.getClient(), updated.getUidValue());
            assertTrue(assignedGroups.contains(groupUpdate.getId()));
        } catch (Exception e) {
            fail();
            LOG.error(e, "While running test");
        }
    }

    @Test
    public void removeUserFromGroup() {
        ToListResultsHandler handler = new ToListResultsHandler();
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        try {
            Group groupOne = createGroup(conn.getClient());
            Group groupTwo = createGroup(conn.getClient());
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
            userAttrs.add(AttributeBuilder.build(ObjectClass.GROUP_NAME, groupOne.getId(), groupTwo.getId()));

            Uid created = connector.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
            assertNotNull(created);
            USERS.add(created.getUidValue());

            Set<String> assignedGroups = getUserGroups(conn.getClient(), created.getUidValue());
            assertTrue(assignedGroups.contains(groupOne.getId()));
            assertTrue(assignedGroups.contains(groupTwo.getId()));

            // GET USER
            EqualsFilter filter = (EqualsFilter) FilterBuilder.equalTo(
                    AttributeBuilder.build("email", username + "@tirasa.net"));
            connector.search(ObjectClass.ACCOUNT, filter, handler, operationOption);
            assertNotNull(handler.getObjects());
            assertFalse(handler.getObjects().isEmpty());
            assertEquals(handler.getObjects().get(0).getUid().getUidValue(), created.getUidValue());
            LOG.info("Created User with id {0} on Okta", handler.getObjects().get(0).getUid());

            // UPDATE USER
            userAttrs.remove(password);
            userAttrs.add(AttributeBuilder.build(ObjectClass.GROUP_NAME, Collections.emptyList()));

            Uid updated = connector.update(ObjectClass.ACCOUNT, created, userAttrs, operationOption);
            assertNotNull(updated);

            assignedGroups = getUserGroups(conn.getClient(), updated.getUidValue());
            assertFalse(assignedGroups.contains(groupOne.getId()));
            assertFalse(assignedGroups.contains(groupTwo.getId()));

        } catch (Exception e) {
            fail();
            LOG.error(e, "While running test");
        }
    }

    @Test
    public void searchApplication() {
        ToListResultsHandler handler = new ToListResultsHandler();

        SearchResult result = connector.
                search(OktaConnector.APPLICATION, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = connector.
                search(OktaConnector.APPLICATION, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    @Test
    public void searchGroup() {
        ToListResultsHandler handler = new ToListResultsHandler();

        SearchResult result = connector.
                search(ObjectClass.GROUP, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);
        assertNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());

        assertFalse(handler.getObjects().isEmpty());

        result = connector.
                search(ObjectClass.GROUP, null, handler, new OperationOptionsBuilder().setPageSize(1).build());

        assertNotNull(result);
        assertNotNull(result.getPagedResultsCookie());
        assertEquals(-1, result.getRemainingPagedResults());
    }

    public void syncFromTheBeginningWithNullToken() {
        TestSyncResultsHandler handler = new TestSyncResultsHandler();
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(OktaAttribute.EMAIL,
                        OktaAttribute.MOBILEPHONE,
                        OktaAttribute.FIRSTNAME,
                        OktaAttribute.LASTNAME).build();

        SyncToken previous = connector.sync(ObjectClass.ACCOUNT, null, handler, operationOption);

        assertNull(previous);

        SyncToken newly = connector.sync(ObjectClass.ACCOUNT, previous, handler, operationOption);
        assertNotNull(newly);
        assertNotNull(newly.getValue());
        assertTrue(((byte[]) newly.getValue()).length > 0);

        assertFalse(Arrays.equals((byte[]) previous.getValue(), (byte[]) newly.getValue()));
    }

//    @Test
//    public void testPullFull() throws Exception {
//        final String ERR1 = "Could not find new object.";
//        OperationOptions operationOption =
//                new OperationOptionsBuilder().setAttributesToGet(
//                        OktaAttribute.EMAIL,
//                        OktaAttribute.PHONE,
//                        OktaAttribute.FIRSTNAME,
//                        OktaAttribute.LASTNAME).build();
//
//        String username = UUID.randomUUID().toString();
//        Attribute password = AttributeBuilder.buildPassword(new GuardedString("Password123".toCharArray()));
//        Attribute mobilePhone = AttributeBuilder.build(OktaAttribute.PHONE, "123456789");
//
//        Set<Attribute> userAttrs = new HashSet<>();
//        userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
//        userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Pull"));
//        userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Pull"));
//        userAttrs.add(mobilePhone);
//        userAttrs.add(password);
//
//        Uid created = connector.create(ObjectClass.ACCOUNT, userAttrs, operationOption);
//        USERS.add(created.getUidValue());
//        assertNotNull(created);
//
//        try {
//            FindUidSyncHandler handler = new FindUidSyncHandler(uid);
//            // attempt to find the newly created object..
//            con.sync(ObjectClass.ACCOUNT, null, handler, null);
//            assertTrue(ERR1, handler.found);
//            assertEquals(0L, handler.token.getValue());
//            //Test the created attributes are equal the searched
//            assertNotNull(handler.attributes);
//            // ------------------------
//            // https://connid.atlassian.net/browse/DB-10
//            // ------------------------
//            final Attribute clAttr = AttributeUtil.find(CHANGELOG, handler.attributes);
//            assertNotNull(clAttr);
//            final Set<Attribute> res = new HashSet<Attribute>(handler.attributes);
//            res.remove(clAttr);
//            // ------------------------
//            attributeSetsEquals(con.schema(), expected, res);
//            // --------------------------------------------
//            // Verify password synchronization
//            // --------------------------------------------
//            final Attribute pwd = AttributeUtil.find(OperationalAttributes.PASSWORD_NAME, handler.attributes);
//            assertNotNull(pwd);
//            assertNotNull(pwd.getValue());
//            assertEquals(1, pwd.getValue().size());
//            final GuardedString guarded = (GuardedString) pwd.getValue().get(0);
//            guarded.access(new GuardedString.Accessor() {
//
//                @Override
//                public void access(char[] clearChars) {
//                    assertEquals("password", new String(clearChars));
//                }
//            });
//            // --------------------------------------------
//        } finally {
//            // attempt to delete the object..
//            con.delete(ObjectClass.ACCOUNT, uid, null);
//            // attempt to find it again to make sure
//            // attempt to find the newly created object..
//            List<ConnectorObject> results = TestHelpers.searchToList(con, ObjectClass.ACCOUNT, FilterBuilder.
//                    equalTo(uid));
//            assertFalse("expect 1 connector object", results.size() == 1);
//            try {
//                // now attempt to delete an object that is not there..
//                con.delete(ObjectClass.ACCOUNT, uid, null);
//                fail("Should have thrown an execption.");
//            } catch (UnknownUidException exp) {
//                // should get here..
//            }
//        }
//    }
    @AfterClass
    public static void cleanTestData() {
//        USERS.stream().forEach(item -> cleanUserTestData(conn.getClient(), item));
//        GROUPS.stream().forEach(item -> cleanGroupTestData(conn.getClient(), item));
//        APPLICATIONS.stream().forEach(item -> cleanGroupTestData(conn.getClient(), item));
    }
}

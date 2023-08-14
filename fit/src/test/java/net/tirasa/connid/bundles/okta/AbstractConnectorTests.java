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

import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.okta.sdk.resource.api.ApplicationApi;
import com.okta.sdk.resource.api.GroupApi;
import com.okta.sdk.resource.api.UserApi;
import com.okta.sdk.resource.group.GroupBuilder;
import com.okta.sdk.resource.model.Application;
import com.okta.sdk.resource.model.Group;
import com.okta.sdk.resource.model.GroupProfile;
import com.okta.sdk.resource.model.GroupType;
import java.io.IOException;
import java.io.InputStream;
import java.lang.reflect.Field;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
import net.tirasa.connid.bundles.okta.servermock.impl.AbstractApiImpl;
import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.junit.BeforeClass;
import org.springframework.util.ReflectionUtils;

public abstract class AbstractConnectorTests {

    private static final Log LOG = Log.getLog(AbstractConnectorTests.class);

    protected static OktaConfiguration CONF;

    protected static OktaConnector CONN;

    protected static ConnectorFacade FACADE;

    protected static final Properties PROPS = new Properties();

    protected static final Set<String> USERS = new HashSet<>();

    protected static final Set<String> GROUPS = new HashSet<>();

    protected static final Set<String> APPLICATIONS = new HashSet<>();

    @BeforeClass
    public static void setUpConf() {
        try {
            InputStream propStream = OktaConnectorTests.class.getResourceAsStream("/okta.properties");
            PROPS.load(propStream);
        } catch (IOException e) {
            fail("Could not load okta.properties: " + e.getMessage());
        }

        CONF = new OktaConfiguration();
        CONF.setDomain(PROPS.getProperty("domain"));
        CONF.setOktaApiToken(PROPS.getProperty("oktaApiToken"));
        CONF.setUserEvents(
                "user.lifecycle.create",
                "user.lifecycle.update",
                "user.lifecycle.delete",
                "group.user_membership.add",
                "group.user_membership.remove");

        try {
            CONF.validate();
            CONN = new OktaConnector();
            CONN.init(CONF);
            CONN.test();
        } catch (Exception e) {
            LOG.error(e, "During connector initialization");
            fail("Cannot initialize the connector");
        }

        CONN.schema();

        FACADE = OktaConnectorTests.newFacade();

        assertNotNull(CONF);
        assertNotNull(CONF.getDomain());
        assertNotNull(CONF.getOktaApiToken());

        Field groupId = ReflectionUtils.findField(Group.class, "id");
        ReflectionUtils.makeAccessible(groupId);

        GroupProfile profile = new GroupProfile();
        profile.setName(AbstractApiImpl.EVERYONE);

        Group group = new Group();
        ReflectionUtils.setField(groupId, group, AbstractApiImpl.EVERYONE_ID);
        group.setType(GroupType.BUILT_IN);
        group.setProfile(profile);
        CONN.getGroupApi().createGroup(group);
    }

    protected static void cleanUserTestData(final UserApi client, final String userId) {
        try {
            if (!StringUtil.isEmpty(userId)) {
                client.deactivateUser(userId, Boolean.FALSE);
                client.deleteUser(userId, Boolean.FALSE);
            }
        } catch (Exception e) {
            LOG.error("Could not clean test data", e);
        }
    }

    protected static void cleanGroupTestData(final GroupApi client, final String groupId) {
        try {
            if (!StringUtil.isEmpty(groupId)) {
                client.deleteGroup(groupId);
            }
        } catch (Exception e) {
            LOG.error("Could not clean test data", e);
        }
    }

    protected static void cleanApplicationTestData(final ApplicationApi client, final String applicationId) {
        try {
            if (!StringUtil.isEmpty(applicationId)) {
                client.deactivateApplication(applicationId);
                client.deleteApplication(applicationId);
            }
        } catch (Exception e) {
            LOG.error("Could not clean test data", e);
        }
    }

    protected Set<String> getUserGroups(final UserApi client, final String userId) {
        Set<String> assignedGroups = new HashSet<>();
        try {
            for (Group grpItem : client.listUserGroups(userId)) {
                assignedGroups.add(grpItem.getId());
            }
        } catch (Exception ex) {
            fail();
            LOG.error(ex, "Could not list groups for User {0}", userId);
        }
        return assignedGroups;
    }

    protected static Set<Attribute> createUserAttrs(final String passwordValue) {
        String username = UUID.randomUUID().toString();
        Attribute password = AttributeBuilder.buildPassword(new GuardedString(passwordValue.toCharArray()));

        Set<Attribute> userAttrs = new HashSet<>();
        userAttrs.add(AttributeBuilder.build(OktaAttribute.EMAIL, username + "@tirasa.net"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.FIRSTNAME, "Test"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.LASTNAME, "Test"));
        userAttrs.add(AttributeBuilder.build(OktaAttribute.MOBILEPHONE, "123456789"));
        userAttrs.add(password);
        return userAttrs;
    }

    protected static Group createGroup(final GroupApi client) {
        String groupName = UUID.randomUUID().toString();
        return GroupBuilder.instance()
                .setName("connid-" + groupName)
                .setDescription("connid-" + groupName).buildAndCreate(client);
    }

    protected static Application createApplication(final ApplicationApi client) {
        Application app = new Application().label(UUID.randomUUID().toString());
        return client.createApplication(app, Boolean.TRUE, null);
    }

    public static void createSearchTestData() {
        OperationOptions oo = new OperationOptionsBuilder()
                .setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        Uid user = FACADE.create(ObjectClass.ACCOUNT, createUserAttrs("Password123"), oo);
        USERS.add(user.getUidValue());

        user = FACADE.create(ObjectClass.ACCOUNT, createUserAttrs("Password123"), oo);
        USERS.add(user.getUidValue());

        Group groupTest = createGroup(CONN.getGroupApi());
        assertNotNull(groupTest);
        GROUPS.add(groupTest.getId());

        groupTest = createGroup(CONN.getGroupApi());
        assertNotNull(groupTest);
        GROUPS.add(groupTest.getId());

        Application app = createApplication(CONN.getApplicationApi());
        assertNotNull(app);
        APPLICATIONS.add(app.getId());

        app = createApplication(CONN.getApplicationApi());
        assertNotNull(app);
        APPLICATIONS.add(app.getId());
    }

    public static class TestSyncResultsHandler implements SyncResultsHandler {

        private final List<SyncDelta> updated = new ArrayList<>();

        private final List<SyncDelta> deleted = new ArrayList<>();

        private SyncToken latestReceivedToken = null;

        @Override
        public boolean handle(final SyncDelta sd) {
            latestReceivedToken = sd.getToken();
            if (sd.getDeltaType() == SyncDeltaType.DELETE) {
                return deleted.add(sd);
            }

            return updated.add(sd);
        }

        public SyncToken getLatestReceivedToken() {
            return latestReceivedToken;
        }

        public List<SyncDelta> getUpdated() {
            return updated;
        }

        public List<SyncDelta> getDeleted() {
            return deleted;
        }

        public void clear() {
            updated.clear();
            deleted.clear();
        }
    };
}

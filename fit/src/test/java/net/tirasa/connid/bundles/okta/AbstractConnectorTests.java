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

import static net.tirasa.connid.bundles.okta.OktaConnectorTests.newFacade;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.fail;

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.application.Application;
import com.okta.sdk.resource.application.WsFederationApplication;
import com.okta.sdk.resource.application.WsFederationApplicationSettings;
import com.okta.sdk.resource.application.WsFederationApplicationSettingsApplication;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.group.GroupBuilder;
import com.okta.sdk.resource.user.User;
import java.io.IOException;
import java.io.InputStream;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Properties;
import java.util.Set;
import java.util.UUID;
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

public abstract class AbstractConnectorTests {

    private static final Log LOG = Log.getLog(AbstractConnectorTests.class);

    protected static OktaConfiguration conf;

    protected static OktaConnector conn;

    protected static ConnectorFacade connector;

    protected static final Properties PROPS = new Properties();

    protected static final Set<String> USERS = new HashSet<>();

    protected static final Set<String> GROUPS = new HashSet<>();

    protected static final Set<String> APPLICATIONS = new HashSet<>();

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
        conf.setUserEvents("user.lifecycle.create",
                "user.lifecycle.update",
                "user.lifecycle.delete",
                "group.user_membership.add",
                "group.user_membership.remove");

        conf.setRateLimitMaxRetries(0);
        conf.setRetryMaxElapsed(0);

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
    }

    protected static void cleanUserTestData(final Client client, final String userId) {
        try {
            if (!StringUtil.isEmpty(userId)) {
                User user = client.getUser(userId);
                user.deactivate();
                user.delete();
            }
        } catch (Exception ex) {
            LOG.error("Could not clean test data");
        }
    }

    protected static void cleanGroupTestData(final Client client, final String groupId) {
        try {
            if (!StringUtil.isEmpty(groupId)) {
                Group group = client.getGroup(groupId);
                group.delete();
            }
        } catch (Exception ex) {
            LOG.error("Could not clean test data");
        }
    }

    protected static void cleanApplicationTestData(final Client client, final String applicationId) {
        try {
            if (!StringUtil.isEmpty(applicationId)) {
                Application app = client.getApplication(applicationId);
                app.deactivate();
                app.delete();
            }
        } catch (Exception ex) {
            LOG.error("Could not clean test data");
        }
    }

    protected Set<String> getUserGroups(final Client client, final String userId) {
        Set<String> assignedGroups = new HashSet<>();
        try {
            for (Group grpItem : client.getUser(userId).listGroups()) {
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

    protected static Group createGroup(final Client client) {
        String groupName = UUID.randomUUID().toString();
        return GroupBuilder.instance()
                .setName("connid-" + groupName)
                .setDescription("connid-" + groupName).buildAndCreate(client);
    }

    protected static Application createApplication(final Client client) {

        WsFederationApplication app =
                client.instantiate(WsFederationApplication.class)
                        .setSettings(client.instantiate(WsFederationApplicationSettings.class)
                                .setApp(client.instantiate(WsFederationApplicationSettingsApplication.class)
                                        .setAudienceRestriction("urn:example:app")
                                        .setGroupName(null)
                                        .setGroupValueFormat("windowsDomainQualifiedName")
                                        .setRealm("urn:example:app")
                                        .setWReplyURL("https://example.com/")
                                        .setAttributeStatements(null)
                                        .setNameIDFormat("urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified")
                                        .setAuthnContextClassRef(
                                                "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport")
                                        .setSiteURL("https://example.com")
                                        .setWReplyOverride(false)
                                        .setGroupFilter(null)
                                        .setUsernameAttribute("username")));
        app.setLabel(UUID.randomUUID().toString());
        return client.createApplication(app);
    }

    public static void createSearchTestData() {
        OperationOptions operationOption =
                new OperationOptionsBuilder().setAttributesToGet(OktaAttribute.EMAIL, OktaAttribute.MOBILEPHONE).build();
        Uid user = connector.create(ObjectClass.ACCOUNT, createUserAttrs("Password123"), operationOption);
        USERS.add(user.getUidValue());

        user = connector.create(ObjectClass.ACCOUNT, createUserAttrs("Password123"), operationOption);
        USERS.add(user.getUidValue());

        Group groupTest = createGroup(conn.getClient());
        assertNotNull(groupTest);
        GROUPS.add(groupTest.getId());

        groupTest = createGroup(conn.getClient());
        assertNotNull(groupTest);
        GROUPS.add(groupTest.getId());

        Application app = createApplication(conn.getClient());
        assertNotNull(app);
        APPLICATIONS.add(app.getId());

        app = createApplication(conn.getClient());
        assertNotNull(app);
        APPLICATIONS.add(app.getId());
    }

    public static class TestSyncResultsHandler implements SyncResultsHandler {

        SyncToken latestReceivedToken = null;

        final List<SyncDelta> updated = new ArrayList<>();

        final List<SyncDelta> deleted = new ArrayList<>();

        @Override
        public boolean handle(final SyncDelta sd) {
            latestReceivedToken = sd.getToken();
            if (sd.getDeltaType() == SyncDeltaType.DELETE) {
                return deleted.add(sd);
            } else {
                return updated.add(sd);
            }
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

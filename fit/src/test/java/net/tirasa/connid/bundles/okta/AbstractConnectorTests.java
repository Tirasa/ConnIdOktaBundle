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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import com.okta.sdk.resource.model.AddGroupRequest;
import com.okta.sdk.resource.model.OktaUserGroupProfile;
import java.io.IOException;
import java.io.InputStream;
import java.util.Optional;
import java.util.Properties;
import net.tirasa.connid.bundles.okta.servermock.OktaServerMockApplication;
import net.tirasa.connid.bundles.okta.servermock.impl.AbstractApi;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.api.APIConfiguration;
import org.identityconnectors.framework.api.ConnectorFacade;
import org.identityconnectors.framework.api.ConnectorFacadeFactory;
import org.identityconnectors.test.common.TestHelpers;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;

public abstract class AbstractConnectorTests {

    private static final Log LOG = Log.getLog(AbstractConnectorTests.class);

    private static ConfigurableApplicationContext CTX;

    protected static OktaConfiguration CONF;

    protected static OktaConnector CONN;

    protected static ConnectorFacade FACADE;

    protected static ConnectorFacade newFacade() {
        ConnectorFacadeFactory factory = ConnectorFacadeFactory.getInstance();
        APIConfiguration impl = TestHelpers.createTestConfiguration(OktaConnector.class, CONF);
        impl.getResultsHandlerConfiguration().setFilteredResultsHandlerInValidationMode(true);
        return factory.newInstance(impl);
    }

    @BeforeAll
    public static void startServerMock() {
        CTX = new SpringApplicationBuilder(OktaServerMockApplication.class).run();
    }

    @AfterAll
    public static void stopServerMock() {
        Optional.ofNullable(CTX).ifPresent(ConfigurableApplicationContext::close);
    }

    @BeforeAll
    public static void setUpConf() {
        Properties props = new Properties();
        try {
            InputStream propStream = OktaConnectorTests.class.getResourceAsStream("/okta.properties");
            props.load(propStream);
        } catch (IOException e) {
            fail("Could not load okta.properties: " + e.getMessage());
        }

        CONF = new OktaConfiguration();
        CONF.setDomain(props.getProperty("domain"));
        CONF.setOktaApiToken(props.getProperty("oktaApiToken"));
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

        OktaUserGroupProfile profile = new OktaUserGroupProfile();
        profile.setName(AbstractApi.EVERYONE);
        CONN.getGroupApi().addGroup(new AddGroupRequest().profile(profile));
    }
}

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

import static org.junit.Assert.fail;

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.group.GroupBuilder;
import com.okta.sdk.resource.user.User;
import java.util.HashSet;
import java.util.Set;
import java.util.UUID;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;

public abstract class AbstractConnectorTests {

    private static final Log LOG = Log.getLog(AbstractConnectorTests.class);

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

    protected Group createGroup(final Client client) {
        String groupName = UUID.randomUUID().toString();
        return GroupBuilder.instance()
                .setName("connid-" + groupName)
                .setDescription("connid-" + groupName).buildAndCreate(client);
    }
}

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
package net.tirasa.connid.bundles.okta.servermock;

import com.fasterxml.jackson.core.type.TypeReference;
import com.fasterxml.jackson.databind.json.JsonMapper;
import io.swagger.api.GroupApi;
import io.swagger.model.OktaUserGroupProfile;
import io.swagger.model.V1GroupsBody;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import net.tirasa.connid.bundles.okta.servermock.impl.AbstractApi;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.beans.factory.annotation.Autowired;

public class ContentBootstrap implements InitializingBean {

    private static final Logger LOG = LoggerFactory.getLogger(ContentBootstrap.class);

    private static final JsonMapper MAPPER = JsonMapper.builder().findAndAddModules().build();

    @Autowired
    private GroupApi groupApi;

    private void bootstrapGroups() throws IOException {
        LOG.info("Bootstrapping groups");

        OktaUserGroupProfile everyoneProfile = new OktaUserGroupProfile();
        everyoneProfile.setName(AbstractApi.EVERYONE);

        V1GroupsBody everyoneGroup = new V1GroupsBody();
        everyoneGroup.setProfile(everyoneProfile);

        groupApi.addGroup(everyoneGroup);

        Map<String, String> groups = Map.of();
        InputStream groupsStream = getClass().getResourceAsStream("/groups.json");
        if (groupsStream == null) {
            LOG.debug("No groups.json found");
        } else {
            try (groupsStream) {
                groups = MAPPER.readValue(groupsStream, new TypeReference<HashMap<String, String>>() {
                });
            } catch (IOException e) {
                LOG.error("While attempting to read and parse groups.json", e);
            }
        }

        groups.forEach((id, name) -> {
            OktaUserGroupProfile profile = new OktaUserGroupProfile();
            profile.setName(id);
            profile.setDescription(name);

            V1GroupsBody group = new V1GroupsBody();
            group.setProfile(profile);

            groupApi.addGroup(group);
            LOG.info("Group {} created", name);
        });
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        LOG.info("Bootstrapping server mock content");

        bootstrapGroups();
    }
}

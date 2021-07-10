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
package net.tirasa.connid.bundles.okta.servermock.impl;

import io.swagger.api.UserSchemaApi;
import io.swagger.model.UserSchema;
import io.swagger.model.UserSchemaBase;
import io.swagger.model.UserSchemaDefinition;
import io.swagger.model.UserSchemaPermission;
import io.swagger.model.UserSchemaProperty;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import javax.ws.rs.core.Response;

public class UserSchemaApiServiceImpl implements UserSchemaApi {

    @Override
    public Response getUserSchema() {
        return Response.ok().entity(initializeUserSchema()).build();
    }

    private UserSchema initializeUserSchema() {
        UserSchema schema = new UserSchema();
        schema.setId("/meta/schemas/user/default");
        schema.set$Schema("http://json-schema.org/draft-04/schema#");
        schema.setName("user");
        schema.setTitle("User");
        schema.setDescription("Okta user profile template with default permission settings");
        schema.setCreated(Date.from(Instant.now()));
        schema.setLastUpdated(Date.from(Instant.now()));
        schema.setType("object");
        schema.setProperties(Arrays.asList("base", "custom"));

        UserSchemaDefinition definition = new UserSchemaDefinition();

        UserSchemaBase custom = new UserSchemaBase();
        custom.setId("#custom");
        custom.setType("object");
        custom.setRequired(new ArrayList<>());

        HashMap<String, UserSchemaProperty> customProperty = new HashMap<>();
        custom.setProperties(customProperty);

        UserSchemaBase base = new UserSchemaBase();
        base.setId("#base");
        base.setType("object");
        base.setRequired(Arrays.asList("Username", "Email"));

        HashMap<String, UserSchemaProperty> baseProperty = new HashMap<>();

        UserSchemaPermission permissions = new UserSchemaPermission();
        permissions.setPrincipal("SELF");
        permissions.setAction("READ_WRITE");

        baseProperty.put("login",
                initializeUserSchemaProperty("Username", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("email",
                initializeUserSchemaProperty("Email", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("secondEmail",
                initializeUserSchemaProperty("Second Email", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        customProperty.put("guid",
                initializeUserSchemaProperty("guid", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        customProperty.put("contactID",
                initializeUserSchemaProperty("Contact ID", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("firstName",
                initializeUserSchemaProperty("First Name", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("lastName",
                initializeUserSchemaProperty("Last Name", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("displayName",
                initializeUserSchemaProperty("Display Name", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("mobilePhone",
                initializeUserSchemaProperty("Mobile Phone", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        customProperty.put("primaryPhone",
                initializeUserSchemaProperty("Primary Phone", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        baseProperty.put("preferredLanguage", initializeUserSchemaProperty(
                "Preferred Language", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        customProperty.put("entitlements",
                initializeUserSchemaProperty("Entitlements", "string", "NONE", "READ_WRITE", true, 0, 0, permissions));
        base.setProperties(baseProperty);

        definition.setCustom(custom);
        definition.setBase(base);
        schema.setDefinitions(definition);

        return schema;
    }

    private UserSchemaProperty initializeUserSchemaProperty(
            final String title,
            final String type,
            final String scope,
            final String mutability,
            final boolean required,
            final int minLength,
            final int maxLength,
            final UserSchemaPermission permissions) {

        UserSchemaProperty property = new UserSchemaProperty();
        property.setTitle(title);
        property.setType(type);
        property.setScope(scope);
        property.setMutability(mutability);
        property.setRequired(required);
        property.setMinLength(minLength != 0 ? minLength : null);
        property.setMaxLength(maxLength != 0 ? maxLength : null);
        property.setPermissions(permissions);

        return property;
    }
}

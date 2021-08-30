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
import io.swagger.model.UserSchemaAttribute;
import io.swagger.model.UserSchemaAttributePermission;
import io.swagger.model.UserSchemaAttributeScope;
import io.swagger.model.UserSchemaAttributeType;
import io.swagger.model.UserSchemaBase;
import io.swagger.model.UserSchemaBaseProperties;
import io.swagger.model.UserSchemaDefinitions;
import io.swagger.model.UserSchemaProperties;
import io.swagger.model.UserSchemaPropertiesProfile;
import io.swagger.model.UserSchemaPropertiesProfileItem;
import io.swagger.model.UserSchemaPublic;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import javax.ws.rs.core.Response;
import net.tirasa.connid.bundles.okta.servermock.OktaObjectMapper;

public class UserSchemaApiServiceImpl implements UserSchemaApi {

    /**
     * Fetches the Schema for an App User
     *
     * Fetches the Schema for an App User
     *
     */
    @Override
    public Response getApplicationUserSchema(String appInstanceId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    /**
     * Fetches the schema for a Schema Id.
     *
     * Fetches the schema for a Schema Id.
     *
     */
    @Override
    public Response getUserSchema(final String schemaId) {
        return Response.ok().entity(initializeUserSchema(schemaId)).build();
    }

    /**
     * Partial updates on the User Profile properties of the Application User Schema.
     *
     * Partial updates on the User Profile properties of the Application User Schema.
     *
     */
    @Override
    public Response updateApplicationUserProfile(String appInstanceId, UserSchema body) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response updateUserProfile(UserSchema body, String schemaId) {
        // TODO: Implement...

        return Response.ok().entity("magic!").build();
    }

    private UserSchema initializeUserSchema(final String schemaId) {
        UserSchema schema = new UserSchema();
        schema.setId("/meta/schemas/user/" + schemaId);
        schema.set$Schema("http://json-schema.org/draft-04/schema#");
        schema.setName("user");
        schema.setTitle("User");
        schema.setCreated(OktaObjectMapper.DATE_FORMAT.get().format(new Date()));
        schema.setLastUpdated(schema.getCreated());
        schema.setType("object");

        schema.setProperties(new UserSchemaProperties());
        schema.getProperties().setProfile(new UserSchemaPropertiesProfile());
        schema.getProperties().getProfile().setAllOf(Arrays.asList(
                new UserSchemaPropertiesProfileItem().$ref("#/definitions/base"),
                new UserSchemaPropertiesProfileItem().$ref("#/definitions/custom")));

        UserSchemaBase base = new UserSchemaBase();
        base.setId("#base");
        base.setType("object");
        base.setRequired(Arrays.asList("Username", "Email"));

        UserSchemaAttributePermission permission = new UserSchemaAttributePermission();
        permission.setPrincipal("SELF");
        permission.setAction("READ_WRITE");

        UserSchemaBaseProperties baseProperty = new UserSchemaBaseProperties();
        baseProperty.setLogin(userSchemaAttribute("Username",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", true, 0, 0, permission));
        baseProperty.setEmail(userSchemaAttribute("Email",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", true, 0, 0, permission));
        baseProperty.setSecondEmail(userSchemaAttribute("Second Email",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        baseProperty.setFirstName(userSchemaAttribute("First Name",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        baseProperty.setLastName(userSchemaAttribute("Last Name",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        baseProperty.setDisplayName(userSchemaAttribute("Display Name",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        baseProperty.setMobilePhone(userSchemaAttribute("Mobile Phone",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        baseProperty.setPreferredLanguage(userSchemaAttribute("Preferred Language",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        base.setProperties(baseProperty);

        UserSchemaPublic custom = new UserSchemaPublic();
        custom.setProperties(new HashMap<>());
        custom.putPropertiesItem("guid", userSchemaAttribute("guid",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", true, 0, 0, permission));
        custom.putPropertiesItem("contactID", userSchemaAttribute("Contact ID",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        custom.putPropertiesItem("primaryPhone", userSchemaAttribute("Primary Phone",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));
        custom.putPropertiesItem("entitlements", userSchemaAttribute("Entitlements",
                UserSchemaAttributeType.STRING, UserSchemaAttributeScope.NONE, "READ_WRITE", false, 0, 0, permission));

        UserSchemaDefinitions definitions = new UserSchemaDefinitions();
        definitions.setBase(base);
        definitions.setCustom(custom);
        schema.setDefinitions(definitions);

        return schema;
    }

    private UserSchemaAttribute userSchemaAttribute(
            final String title,
            final UserSchemaAttributeType type,
            final UserSchemaAttributeScope scope,
            final String mutability,
            final boolean required,
            final int minLength,
            final int maxLength,
            final UserSchemaAttributePermission permission) {

        UserSchemaAttribute property = new UserSchemaAttribute();
        property.setTitle(title);
        property.setType(type);
        property.setScope(scope);
        property.setMutability(mutability);
        property.setRequired(required);
        property.setMinLength(minLength != 0 ? minLength : null);
        property.setMaxLength(maxLength != 0 ? maxLength : null);
        property.setPermissions(Collections.singletonList(permission));

        return property;
    }
}

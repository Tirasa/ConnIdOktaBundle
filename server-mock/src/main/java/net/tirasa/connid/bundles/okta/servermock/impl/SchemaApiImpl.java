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

import io.swagger.api.SchemaApi;
import io.swagger.model.AllOfUserSchemaDefinitions;
import io.swagger.model.AllOfUserSchemaProperties;
import io.swagger.model.GroupSchema;
import io.swagger.model.LogStreamType;
import io.swagger.model.UserSchema;
import io.swagger.model.UserSchemaAttribute;
import io.swagger.model.UserSchemaAttributeMutabilityString;
import io.swagger.model.UserSchemaAttributePermission;
import io.swagger.model.UserSchemaAttributeScope;
import io.swagger.model.UserSchemaAttributeType;
import io.swagger.model.UserSchemaBase;
import io.swagger.model.UserSchemaBaseProperties;
import io.swagger.model.UserSchemaPropertiesProfile;
import io.swagger.model.UserSchemaPropertiesProfileItem;
import io.swagger.model.UserSchemaPublic;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import javax.ws.rs.core.Response;
import net.tirasa.connid.bundles.okta.servermock.OktaObjectMapper;
import org.springframework.stereotype.Service;

@Service
public class SchemaApiImpl extends AbstractApi implements SchemaApi {

    @Override
    public Response getApplicationUserSchema(final String appInstanceId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getUserSchema(final String schemaId) {
        return Response.ok().entity(initializeUserSchema(schemaId)).build();
    }

    @Override
    public Response updateApplicationUserProfile(final String appInstanceId, final UserSchema body) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response updateUserProfile(final UserSchema body, final String schemaId) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getGroupSchema() {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response getLogStreamSchema(final LogStreamType logStreamType) {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response listLogStreamSchemas() {
        return Response.ok().entity("magic!").build();
    }

    @Override
    public Response updateGroupSchema(final GroupSchema body) {
        return Response.ok().entity("magic!").build();
    }

    private UserSchema initializeUserSchema(final String schemaId) {
        UserSchema schema = new UserSchema();
        schema.setId("/meta/schemas/user/" + schemaId);
        //schema.set$Schema("http://json-schema.org/draft-04/schema#");
        schema.setName("user");
        schema.setTitle("User");
        schema.setCreated(OktaObjectMapper.DATE_FORMAT.get().format(new Date()));
        schema.setLastUpdated(schema.getCreated());
        //schema.setType("object");

        schema.setProperties(new AllOfUserSchemaProperties());
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
        baseProperty.setLogin(userSchemaAttribute(
                "Username",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                true, 0, 0, permission));
        baseProperty.setEmail(userSchemaAttribute(
                "Email",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                true, 0, 0, permission));
        baseProperty.setSecondEmail(userSchemaAttribute(
                "Second Email",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        baseProperty.setFirstName(userSchemaAttribute(
                "First Name",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        baseProperty.setLastName(userSchemaAttribute(
                "Last Name",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        baseProperty.setDisplayName(userSchemaAttribute(
                "Display Name",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        baseProperty.setMobilePhone(userSchemaAttribute(
                "Mobile Phone",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        baseProperty.setPreferredLanguage(userSchemaAttribute(
                "Preferred Language",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        base.setProperties(baseProperty);

        UserSchemaPublic custom = new UserSchemaPublic();
        custom.setProperties(new HashMap<>());
        custom.putPropertiesItem("guid", userSchemaAttribute(
                "guid",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                true, 0, 0, permission));
        custom.putPropertiesItem("contactID", userSchemaAttribute(
                "Contact ID",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        custom.putPropertiesItem("primaryPhone", userSchemaAttribute(
                "Primary Phone",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));
        custom.putPropertiesItem("entitlements", userSchemaAttribute(
                "Entitlements",
                UserSchemaAttributeType.STRING,
                UserSchemaAttributeScope.NONE,
                UserSchemaAttributeMutabilityString.READ_WRITE,
                false, 0, 0, permission));

        AllOfUserSchemaDefinitions definitions = new AllOfUserSchemaDefinitions();
        definitions.setBase(base);
        definitions.setCustom(custom);
        schema.setDefinitions(definitions);

        return schema;
    }

    private UserSchemaAttribute userSchemaAttribute(
            final String title,
            final UserSchemaAttributeType type,
            final UserSchemaAttributeScope scope,
            final UserSchemaAttributeMutabilityString mutability,
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
        property.setMinLength(minLength);
        property.setMaxLength(maxLength);
        property.setPermissions(List.of(permission));

        return property;
    }
}

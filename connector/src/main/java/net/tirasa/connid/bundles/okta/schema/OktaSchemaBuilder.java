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
package net.tirasa.connid.bundles.okta.schema;

import java.util.ArrayList;
import java.util.Collection;
import java.util.Collections;
import java.util.EnumSet;
import java.util.List;
import java.util.Optional;
import net.tirasa.connid.bundles.okta.OktaConnector;
import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.AttributeInfo.Flags;
import org.identityconnectors.framework.common.objects.AttributeInfoBuilder;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfoBuilder;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SchemaBuilder;
import org.openapitools.client.api.SchemaApi;
import org.openapitools.client.model.UserSchemaAttribute;
import org.openapitools.client.model.UserSchemaDefinitions;

class OktaSchemaBuilder {

    private static final Log LOG = Log.getLog(OktaSchemaBuilder.class);

    private final SchemaApi schemaApi;

    private Schema schema;

    protected OktaSchemaBuilder(final SchemaApi schemaApi) {
        this.schemaApi = schemaApi;
    }

    public Schema getSchema() {
        if (schema == null) {
            buildSchema();
        }
        return schema;
    }

    private void buildSchema() {
        SchemaBuilder schemaBld = new SchemaBuilder(OktaConnector.class);

        schemaBld.defineObjectClass(build(ObjectClass.ACCOUNT_NAME).
                addAllAttributeInfo(buildAccountAttrInfos()).build());

        schemaBld.defineObjectClass(build(ObjectClass.GROUP_NAME).
                addAllAttributeInfo(buildGroupAttrInfos()).build());

        schemaBld.defineObjectClass(build(OktaConnector.APPLICATION_NAME).
                addAllAttributeInfo(buildApplicationAttrInfos()).build());

        schema = schemaBld.build();
    }

    private ObjectClassInfoBuilder build(final String objectClassName) {
        ObjectClassInfoBuilder objClassBld = new ObjectClassInfoBuilder();
        objClassBld.setType(objectClassName);
        objClassBld.setContainer(false);
        return objClassBld;
    }

    private Optional<AttributeInfo> map(
            final String key, final UserSchemaAttribute attr, final List<String> req) {

        return Optional.ofNullable(attr).map(prop -> {
            AttributeInfoBuilder attributeInfo = new AttributeInfoBuilder();
            attributeInfo.setRequired(req.contains(key));
            return AttributeInfoBuilder.build(key, OktaAttribute.getType(prop.getType().getValue()));
        });
    }

    @SuppressWarnings({ "unchecked" })
    private Collection<AttributeInfo> buildAccountAttrInfos() {
        LOG.ok("Retrieve User schema profile");
        List<AttributeInfo> attributeInfos = new ArrayList<>();

        UserSchemaDefinitions defs = schemaApi.getUserSchema("default").getDefinitions();

        List<String> reqBase = Optional.ofNullable(defs.getBase().getRequired()).orElse(Collections.emptyList());
        map("city", defs.getBase().getProperties().getCity(), reqBase).
                ifPresent(attributeInfos::add);
        map("costCenter", defs.getBase().getProperties().getCostCenter(), reqBase).
                ifPresent(attributeInfos::add);
        map("countryCode", defs.getBase().getProperties().getCountryCode(), reqBase).
                ifPresent(attributeInfos::add);
        map("department", defs.getBase().getProperties().getDepartment(), reqBase).
                ifPresent(attributeInfos::add);
        map("displayName", defs.getBase().getProperties().getDisplayName(), reqBase).
                ifPresent(attributeInfos::add);
        map("division", defs.getBase().getProperties().getDivision(), reqBase).
                ifPresent(attributeInfos::add);
        map("email", defs.getBase().getProperties().getEmail(), reqBase).
                ifPresent(attributeInfos::add);
        map("employeeNumber", defs.getBase().getProperties().getEmployeeNumber(), reqBase).
                ifPresent(attributeInfos::add);
        map("firstName", defs.getBase().getProperties().getFirstName(), reqBase).
                ifPresent(attributeInfos::add);
        map("honorificPrefix", defs.getBase().getProperties().getHonorificPrefix(), reqBase).
                ifPresent(attributeInfos::add);
        map("honorificSuffix", defs.getBase().getProperties().getHonorificSuffix(), reqBase).
                ifPresent(attributeInfos::add);
        map("lastName", defs.getBase().getProperties().getLastName(), reqBase).ifPresent(attributeInfos::add);
        map("locale", defs.getBase().getProperties().getLocale(), reqBase).ifPresent(attributeInfos::add);
        map("login", defs.getBase().getProperties().getLogin(), reqBase).ifPresent(attributeInfos::add);
        map("manager", defs.getBase().getProperties().getManager(), reqBase).ifPresent(attributeInfos::add);
        map("managerId", defs.getBase().getProperties().getManagerId(), reqBase).ifPresent(attributeInfos::add);
        map("middleName", defs.getBase().getProperties().getMiddleName(), reqBase).ifPresent(attributeInfos::add);
        map("mobilePhone", defs.getBase().getProperties().getMobilePhone(), reqBase).ifPresent(attributeInfos::add);
        map("nickName", defs.getBase().getProperties().getNickName(), reqBase).ifPresent(attributeInfos::add);
        map("organization", defs.getBase().getProperties().getOrganization(), reqBase).ifPresent(attributeInfos::add);
        map("postalAddress", defs.getBase().getProperties().getPostalAddress(), reqBase).ifPresent(attributeInfos::add);
        map("preferredLanguage", defs.getBase().getProperties().getPreferredLanguage(), reqBase).
                ifPresent(attributeInfos::add);
        map("primaryPhone", defs.getBase().getProperties().getPrimaryPhone(), reqBase).ifPresent(attributeInfos::add);
        map("profileUrl", defs.getBase().getProperties().getProfileUrl(), reqBase).ifPresent(attributeInfos::add);
        map("secondEmail", defs.getBase().getProperties().getSecondEmail(), reqBase).ifPresent(attributeInfos::add);
        map("state", defs.getBase().getProperties().getState(), reqBase).ifPresent(attributeInfos::add);
        map("streetAddress", defs.getBase().getProperties().getStreetAddress(), reqBase).ifPresent(attributeInfos::add);
        map("timezone", defs.getBase().getProperties().getTimezone(), reqBase).ifPresent(attributeInfos::add);
        map("title", defs.getBase().getProperties().getTitle(), reqBase).ifPresent(attributeInfos::add);
        map("userType", defs.getBase().getProperties().getUserType(), reqBase).ifPresent(attributeInfos::add);
        map("zipCode", defs.getBase().getProperties().getZipCode(), reqBase).ifPresent(attributeInfos::add);

        List<String> reqCustom = Optional.ofNullable(defs.getCustom().getRequired()).orElse(Collections.emptyList());
        defs.getCustom().getProperties().
                forEach((key, prop) -> map(key, prop, reqCustom).ifPresent(attributeInfos::add));

        AttributeInfoBuilder attributeInfo = new AttributeInfoBuilder();
        attributeInfo.setRequired(true);
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.ID, String.class));

        attributeInfos.add(AttributeInfoBuilder.define(OktaAttribute.OKTA_GROUPS, String.class)
                .setMultiValued(true)
                .setReturnedByDefault(false)
                .build());

        return attributeInfos;
    }

    private Collection<AttributeInfo> buildGroupAttrInfos() {
        LOG.ok("Retrieve Group schema profile");
        List<AttributeInfo> attributeInfos = new ArrayList<>();
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.ID, String.class));
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.NAME, String.class, EnumSet.of(Flags.REQUIRED)));
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.DESCRIPTION, String.class));
        return attributeInfos;
    }

    private Collection<AttributeInfo> buildApplicationAttrInfos() {
        LOG.ok("Retrieve Application schema profile");
        List<AttributeInfo> attributeInfos = new ArrayList<>();
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.ID, String.class));
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.NAME, String.class, EnumSet.of(Flags.REQUIRED)));
        attributeInfos.add(AttributeInfoBuilder.build(OktaAttribute.LABEL, String.class));
        return attributeInfos;
    }
}

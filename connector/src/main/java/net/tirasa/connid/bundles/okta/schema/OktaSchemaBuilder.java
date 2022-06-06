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

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.ExtensibleResource;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.EnumSet;
import java.util.List;
import java.util.Map;
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

class OktaSchemaBuilder {

    private static final Log LOG = Log.getLog(OktaSchemaBuilder.class);

    public static final String SCHEMA_DEFINITIONS = "definitions";

    public static final String SCHEMA_BASE = "base";

    public static final String SCHEMA_CUSTOM = "custom";

    public static final String TYPE = "type";

    public static final String REQUIRED = "required";

    private static final String PROPERTIES = "properties";

    public static final List<String> ATTRS_TYPE = Arrays.asList(SCHEMA_BASE, SCHEMA_CUSTOM);

    private final Client client;

    private Schema schema;

    public OktaSchemaBuilder(final Client client) {
        this.client = client;
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

    @SuppressWarnings({ "unchecked" })
    private Collection<AttributeInfo> buildAccountAttrInfos() {
        LOG.ok("Retrieve User schema profile");
        List<AttributeInfo> attributeInfos = new ArrayList<>();
        ExtensibleResource userSchema = client.getDataStore().http().
                get(OktaConnector.SCHEMA_USER_EDITOR_PROFILE_API_URL, ExtensibleResource.class);
        Map<String, Object> definitions = Map.class.cast(userSchema.get(SCHEMA_DEFINITIONS));
        ATTRS_TYPE.stream().forEach(item -> {
            List<String> requiredAttrs = ((Map<String, List<String>>) definitions.get(item)).get(REQUIRED);
            Map<String, Object> schemas = (Map<String, Object>) definitions.get(item);
            ((Map<String, Object>) schemas.get(PROPERTIES)).forEach((key, value) -> {
                AttributeInfoBuilder attributeInfo = new AttributeInfoBuilder();
                attributeInfo.setRequired(requiredAttrs != null && requiredAttrs.contains(key));
                attributeInfos.add(AttributeInfoBuilder.build(key,
                        OktaAttribute.getType(((Map<String, String>) value).get(TYPE))));
            });
        });

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

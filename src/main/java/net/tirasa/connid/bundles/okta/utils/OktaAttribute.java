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
package net.tirasa.connid.bundles.okta.utils;

import com.okta.sdk.client.Client;
import com.okta.sdk.resource.ExtensibleResource;
import com.okta.sdk.resource.application.Application;
import com.okta.sdk.resource.application.ApplicationList;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserProfile;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import net.tirasa.connid.bundles.okta.OktaConnector;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.AttributeInfo;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Schema;

public final class OktaAttribute {

    private static final Log LOG = Log.getLog(OktaAttribute.class);

    public static final String ID = "id";

    public static final String STATUS = "status";

    public static final String SCHEMA_PROPERTIES = "properties";

    public static final String EMAIL = "email";

    public static final String LOGIN = "login";

    public static final String SECOND_EMAIL = "secondEmail";

    public static final String LASTNAME = "lastName";

    public static final String FIRSTNAME = "firstName";

    public static final String MOBILEPHONE = "mobilePhone";

    public static final String NAME = "name";

    public static final String LABEL = "label";

    public static final String DESCRIPTION = "description";

    public static final List<String> BASIC_PROFILE_ATTRIBUTES = new ArrayList<String>() {

        private static final long serialVersionUID = 5636572627689425575L;

        {
            add(EMAIL);
            add(LOGIN);
            add(SECOND_EMAIL);
            add(LASTNAME);
            add(FIRSTNAME);
            add(MOBILEPHONE);
        }
    };

    public static Class<?> getType(final String type) {
        if (StringUtil.isBlank(type)) {
            return String.class;
        }
        Class<?> typeClass = String.class;
        switch (type) {
            case "String":
                typeClass = String.class;
                break;
            case "Boolean":
                typeClass = Boolean.class;
                break;
            case "Integer":
                typeClass = Integer.class;
                break;
            default:
                break;
        }
        return typeClass;
    }

    public static Set<Attribute> buildUserAttributes(
            final Client client,
            final User user,
            final Schema schema,
            final Set<String> attributesToGet) {

        Set<Attribute> attributes = new HashSet<>();
        ObjectClassInfo objectClassInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        UserProfile userProfile = user.getProfile();
        for (String attributeToGetName : attributesToGet) {
            AttributeBuilder attributeBuilder = new AttributeBuilder();
            if (OperationalAttributes.ENABLE_NAME.equals(attributeToGetName)
                    || STATUS.equals(attributeToGetName)) {
                attributeBuilder.setName(attributeToGetName);
                attributeBuilder.addValue(user.getStatus());
            } else if (ObjectClass.GROUP_NAME.equals(attributeToGetName)) {
                Set<String> assignedApplications = new HashSet<>();
                try {
                    ApplicationList applicationList = client.getDataStore().http()
                            .addQueryParameter(OktaConnector.FILTER, "user.id eq \"" + user.getId() + "\"")
                            .get(OktaConnector.APP_API_URL, ApplicationList.class);
                    for (Application appItem : applicationList) {
                        assignedApplications.add(appItem.getId());
                    }
                    attributeBuilder = buildAttribute(assignedApplications, attributeToGetName, List.class);
                } catch (Exception ex) {
                    LOG.error(ex, "Could not list applications for User {0}", user.getId());
                }
            } else {
                Optional<AttributeInfo> attributeInfo = objectClassInfo.getAttributeInfo().stream().
                        filter(attr -> attr.getName().equals(attributeToGetName)).findFirst();
                if (attributeInfo.isPresent()) {
                    Class<?> type = attributeInfo.get().getType();
                    attributeBuilder =
                            buildAttribute(
                                    userProfile.get(attributeToGetName), attributeToGetName, type);
                }
            }
            attributes.add(attributeBuilder.build());
        }
        return attributes;
    }

    public static Set<Attribute> buildExtResourceAttributes(
            final Client client,
            final ExtensibleResource resource,
            final Schema schema,
            final Set<String> attributesToGet,
            final String objName) {
        Set<Attribute> attributes = new HashSet<>();
        ObjectClassInfo objectClassInfo = schema.findObjectClassInfo(objName);
        for (String attributeToGetName
                : attributesToGet) {
            AttributeBuilder attributeBuilder = new AttributeBuilder();
            if (resource instanceof Application && (OperationalAttributes.ENABLE_NAME.equals(attributeToGetName)
                    || STATUS.equals(attributeToGetName))) {
                attributeBuilder.setName(attributeToGetName);
                if (resource instanceof Application) {
                    attributeBuilder.addValue(((Application) resource).getStatus());
                }
            } else {
                Optional<AttributeInfo> attributeInfo = objectClassInfo.getAttributeInfo().stream().
                        filter(attr -> attr.getName().equals(attributeToGetName)).findFirst();
                if (attributeInfo.isPresent()) {
                    Class<?> type = attributeInfo.get().getType();
                    attributeBuilder = buildAttribute(
                            resource.get(attributeToGetName), attributeToGetName, type);
                }
            }
            attributes.add(attributeBuilder.build());
        }
        return attributes;
    }

    public static AttributeBuilder buildAttribute(final Object value,
            final String name,
            final Class<?> clazz) {
        AttributeBuilder attributeBuilder = new AttributeBuilder();
        if (value != null) {
            if (clazz
                    == boolean.class
                    || clazz == Boolean.class) {
                attributeBuilder.addValue(Boolean.class
                        .cast(value));
            } else if (value instanceof List<?>) {
                ArrayList<?> list = new ArrayList<>((List<?>) value);
                if (list.size() > 1) {
                    for (Object elem : list) {
                        buildAttribute(elem, name, clazz);
                    }
                } else if (!list.isEmpty()) {
                    attributeBuilder.addValue(list.get(0).toString());
                }
            } else {
                attributeBuilder.addValue(value.toString());
            }
        }
        if (name != null) {
            attributeBuilder.setName(name);
        }
        return attributeBuilder;
    }
}

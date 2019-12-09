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
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserProfile;
import com.okta.sdk.resource.user.UserStatus;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.Uid;

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

    public static final String OKTA_GROUPS = "oktaGroups";

    public static final String NAME = "name";

    public static final String LABEL = "label";

    public static final String DESCRIPTION = "description";

    public static final String LASTUPDATE = "lastUpdated";

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
        attributesToGet.stream().forEach((String attributeToGetName) -> {
            if (Name.NAME.equals(attributeToGetName)
                    || Uid.NAME.equals(attributeToGetName)
                    || OktaAttribute.ID.equals(attributeToGetName)) {
                attributes.add(AttributeBuilder.build(attributeToGetName, user.getId()));
            } else if (STATUS.equals(attributeToGetName)) {
                attributes.add(buildAttribute(user.getStatus().toString(), attributeToGetName, String.class).build());
            } else if (OperationalAttributes.ENABLE_NAME.equals(attributeToGetName)) {
                attributes.add(buildAttribute(user.getStatus().equals(
                        UserStatus.ACTIVE), attributeToGetName, Boolean.class).build());
            } else if (OKTA_GROUPS.equals(attributeToGetName)) {
                try {
                    List<String> assignedGroups =
                            user.listGroups().stream().map(item -> item.getId()).collect(Collectors.toList());
                    attributes.add(buildAttribute(assignedGroups, attributeToGetName, Set.class).build());
                } catch (Exception ex) {
                    LOG.error(ex, "Could not list groups for User {0}", user.getId());
                }
            } else if (OktaAttribute.LASTUPDATE.equals(attributeToGetName)) {
                attributes.add(
                        buildAttribute(user.get(LASTUPDATE), attributeToGetName, String.class).build());
            } else {
                objectClassInfo.getAttributeInfo().stream().
                        filter(attr -> attr.getName().equals(attributeToGetName)).findFirst().ifPresent(
                        attributeInfo -> {
                            attributes.add(
                                    buildAttribute(userProfile.get(
                                            attributeToGetName), attributeToGetName, attributeInfo.getType()).build());
                        });
            }
        });
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
        attributesToGet.stream().forEach(attributeToGetName -> {
            if (Name.NAME.equals(attributeToGetName)
                    || Uid.NAME.equals(attributeToGetName)
                    || OktaAttribute.ID.equals(attributeToGetName)) {
                attributes.add(AttributeBuilder.build(attributeToGetName, resource.getString(ID)));
            } else if (STATUS.equals(attributeToGetName)) {
                AttributeBuilder attributeBuilder = new AttributeBuilder();
                attributeBuilder.setName(attributeToGetName);
                if (resource instanceof Application) {
                    attributeBuilder.
                            addValue(((Application) resource).getStatus());
                }
                attributes.add(attributeBuilder.build());
            } else if (OperationalAttributes.ENABLE_NAME.equals(attributeToGetName)) {
                AttributeBuilder attributeBuilder = new AttributeBuilder();
                attributeBuilder.setName(attributeToGetName);
                if (resource instanceof Application) {
                    attributeBuilder.
                            addValue(((Application) resource).getStatus().equals(Application.StatusEnum.ACTIVE));
                }
                attributes.add(attributeBuilder.build());
            } else if (OperationalAttributes.ENABLE_NAME.equals(attributeToGetName)
                    || STATUS.equals(attributeToGetName)) {
                AttributeBuilder attributeBuilder = new AttributeBuilder();
                attributeBuilder.setName(attributeToGetName);
                if (resource instanceof Application) {
                    attributeBuilder.
                            addValue(((Application) resource).getStatus().equals(Application.StatusEnum.ACTIVE));
                }
                attributes.add(attributeBuilder.build());
            } else if (OktaAttribute.LASTUPDATE.equals(attributeToGetName)) {
                attributes.add(
                        buildAttribute(resource.get(LASTUPDATE), attributeToGetName, String.class).build());
            } else {
                objectClassInfo.getAttributeInfo().stream().
                        filter(attr -> attr.getName().equals(attributeToGetName)).findFirst().ifPresent(
                        attributeInfo -> {
                            attributes.add(
                                    buildAttribute(resource instanceof Group
                                            ? ((Group) resource).getProfile().getString(attributeToGetName)
                                            : resource.getString(attributeToGetName),
                                            attributeToGetName, attributeInfo.getType()).build());
                        });
            }
        });
        return attributes;
    }

    public static AttributeBuilder buildAttribute(final Object value,
            final String name,
            final Class<?> clazz) {
        return buildAttribute(value, name, clazz, new AttributeBuilder());
    }

    public static AttributeBuilder buildAttribute(final Object value,
            final String name,
            final Class<?> clazz,
            final AttributeBuilder attributeBuilder) {
        if (value != null) {
            if (clazz == boolean.class || clazz == Boolean.class) {
                attributeBuilder.addValue(Boolean.class.cast(value));
            } else if (value instanceof List<?>) {
                ArrayList<?> list = new ArrayList<>((List<?>) value);
                if (list.size() > 1) {
                    for (Object elem : list) {
                        buildAttribute(elem, name, clazz, attributeBuilder);
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

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

import com.okta.sdk.resource.api.ApplicationApi;
import com.okta.sdk.resource.api.GroupApi;
import com.okta.sdk.resource.api.UserResourcesApi;
import com.okta.sdk.resource.model.Application;
import com.okta.sdk.resource.model.ApplicationLifecycleStatus;
import com.okta.sdk.resource.model.Group;
import com.okta.sdk.resource.model.GroupType;
import com.okta.sdk.resource.model.UserProfile;
import com.okta.sdk.resource.model.UserStatus;
import java.time.OffsetDateTime;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import net.tirasa.connid.bundles.okta.OktaConnector;
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

    public static final String LASTUPDATED = "lastUpdated";

    public static final String OKTA_SECURITY_QUESTION = "oktaSecurityQuestion";

    public static final String OKTA_SECURITY_ANSWER = "oktaSecurityAnswer";

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
            final UserResourcesApi userApi,
            final String userId,
            final UserStatus userStatus,
            final OffsetDateTime userLastUpdated,
            final UserProfile userProfile,
            final Schema schema,
            final Set<String> attributesToGet) {

        Set<Attribute> attributes = new HashSet<>();
        ObjectClassInfo objectClassInfo = schema.findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        attributesToGet.stream().filter(name -> !Name.NAME.equals(name) && !Uid.NAME.equals(name)).forEach(name -> {
            if (ID.equals(name)) {
                attributes.add(AttributeBuilder.build(name, userId));
            } else if (STATUS.equals(name)) {
                attributes.add(buildAttribute(userStatus.toString(), name, String.class).build());
            } else if (OperationalAttributes.ENABLE_NAME.equals(name)) {
                attributes.add(buildAttribute(userStatus == UserStatus.ACTIVE, name, Boolean.class).build());
            } else if (OKTA_GROUPS.equals(name)) {
                try {
                    List<String> assignedGroups = userApi.listUserGroups(userId).stream()
                            .filter(item -> !isDefaultEveryoneGroup(item))
                            .map(Group::getId)
                            .collect(Collectors.toList());
                    attributes.add(buildAttribute(assignedGroups, name, Set.class).build());
                } catch (Exception ex) {
                    LOG.error(ex, "Could not list groups for User {0}", userId);
                }
            } else if (LASTUPDATED.equals(name)) {
                attributes.add(buildAttribute(
                        Optional.ofNullable(userLastUpdated).map(u -> u.toInstant().toEpochMilli()).orElse(0L),
                        name, Long.class).build());
            } else {
                objectClassInfo.getAttributeInfo().stream().
                        filter(attr -> attr.getName().equals(name)).findFirst().ifPresent(
                        attributeInfo -> {
                            Object value;
                            switch (name) {
                                case UserProfile.JSON_PROPERTY_CITY:
                                    value = userProfile.getCity();
                                    break;

                                case UserProfile.JSON_PROPERTY_COST_CENTER:
                                    value = userProfile.getCostCenter();
                                    break;

                                case UserProfile.JSON_PROPERTY_COUNTRY_CODE:
                                    value = userProfile.getCountryCode();
                                    break;

                                case UserProfile.JSON_PROPERTY_DEPARTMENT:
                                    value = userProfile.getDepartment();
                                    break;

                                case UserProfile.JSON_PROPERTY_DISPLAY_NAME:
                                    value = userProfile.getDisplayName();
                                    break;

                                case UserProfile.JSON_PROPERTY_DIVISION:
                                    value = userProfile.getDivision();
                                    break;

                                case UserProfile.JSON_PROPERTY_EMAIL:
                                    value = userProfile.getEmail();
                                    break;

                                case UserProfile.JSON_PROPERTY_EMPLOYEE_NUMBER:
                                    value = userProfile.getEmployeeNumber();
                                    break;

                                case UserProfile.JSON_PROPERTY_FIRST_NAME:
                                    value = userProfile.getFirstName();
                                    break;

                                case UserProfile.JSON_PROPERTY_HONORIFIC_PREFIX:
                                    value = userProfile.getHonorificPrefix();
                                    break;

                                case UserProfile.JSON_PROPERTY_HONORIFIC_SUFFIX:
                                    value = userProfile.getHonorificSuffix();
                                    break;

                                case UserProfile.JSON_PROPERTY_LAST_NAME:
                                    value = userProfile.getLastName();
                                    break;

                                case UserProfile.JSON_PROPERTY_LOCALE:
                                    value = userProfile.getLocale();
                                    break;

                                case UserProfile.JSON_PROPERTY_LOGIN:
                                    value = userProfile.getLogin();
                                    break;

                                case UserProfile.JSON_PROPERTY_MANAGER:
                                    value = userProfile.getManager();
                                    break;

                                case UserProfile.JSON_PROPERTY_MANAGER_ID:
                                    value = userProfile.getManagerId();
                                    break;

                                case UserProfile.JSON_PROPERTY_MIDDLE_NAME:
                                    value = userProfile.getMiddleName();
                                    break;

                                case UserProfile.JSON_PROPERTY_MOBILE_PHONE:
                                    value = userProfile.getMobilePhone();
                                    break;

                                case UserProfile.JSON_PROPERTY_NICK_NAME:
                                    value = userProfile.getNickName();
                                    break;

                                case UserProfile.JSON_PROPERTY_ORGANIZATION:
                                    value = userProfile.getOrganization();
                                    break;

                                case UserProfile.JSON_PROPERTY_POSTAL_ADDRESS:
                                    value = userProfile.getPostalAddress();
                                    break;

                                case UserProfile.JSON_PROPERTY_PREFERRED_LANGUAGE:
                                    value = userProfile.getPreferredLanguage();
                                    break;

                                case UserProfile.JSON_PROPERTY_PRIMARY_PHONE:
                                    value = userProfile.getPrimaryPhone();
                                    break;

                                case UserProfile.JSON_PROPERTY_PROFILE_URL:
                                    value = userProfile.getProfileUrl();
                                    break;

                                case UserProfile.JSON_PROPERTY_SECOND_EMAIL:
                                    value = userProfile.getSecondEmail();
                                    break;

                                case UserProfile.JSON_PROPERTY_STATE:
                                    value = userProfile.getState();
                                    break;

                                case UserProfile.JSON_PROPERTY_STREET_ADDRESS:
                                    value = userProfile.getStreetAddress();
                                    break;

                                case UserProfile.JSON_PROPERTY_TIMEZONE:
                                    value = userProfile.getTimezone();
                                    break;

                                case UserProfile.JSON_PROPERTY_TITLE:
                                    value = userProfile.getTitle();
                                    break;

                                case UserProfile.JSON_PROPERTY_USER_TYPE:
                                    value = userProfile.getUserType();
                                    break;

                                case UserProfile.JSON_PROPERTY_ZIP_CODE:
                                    value = userProfile.getZipCode();
                                    break;

                                default:
                                    value = userProfile.getAdditionalProperties().get(name);
                            }

                            attributes.add(buildAttribute(value, name, attributeInfo.getType()).build());
                        });
            }
        });
        return attributes;
    }

    public static Set<Attribute> buildGroupAttributes(
            final GroupApi groupApi,
            final Group group,
            final Schema schema,
            final Set<String> attributesToGet) {

        Set<Attribute> attributes = new HashSet<>();
        attributesToGet.stream().filter(name -> !Name.NAME.equals(name) && !Uid.NAME.equals(name)).forEach(name -> {
            switch (name) {
                case ID:
                    attributes.add(AttributeBuilder.build(name, group.getId()));
                    break;

                case DESCRIPTION:
                    attributes.add(AttributeBuilder.build(name, group.getProfile().getDescription()));
                    break;

                case LASTUPDATED:
                    attributes.add(buildAttribute(
                            Optional.ofNullable(group.getLastUpdated()).
                                    map(t -> t.toInstant().toEpochMilli()).orElse(0L),
                            name, Long.class).build());
                    break;

                default:
            }
        });
        return attributes;
    }

    public static Set<Attribute> buildApplicationAttributes(
            final ApplicationApi applicationApi,
            final Application application,
            final Schema schema,
            final Set<String> attributesToGet) {

        Set<Attribute> attributes = new HashSet<>();
        ObjectClassInfo objectClassInfo = schema.findObjectClassInfo(OktaConnector.APPLICATION_NAME);
        attributesToGet.stream().filter(name -> !Name.NAME.equals(name) && !Uid.NAME.equals(name)).forEach(name -> {
            if (ID.equals(name)) {
                attributes.add(AttributeBuilder.build(name, application.getId()));
            } else if (STATUS.equals(name)) {
                AttributeBuilder attributeBuilder = new AttributeBuilder();
                attributeBuilder.setName(name);
                attributeBuilder.addValue(application.getStatus());
                attributes.add(attributeBuilder.build());
            } else if (OperationalAttributes.ENABLE_NAME.equals(name) || STATUS.equals(name)) {
                AttributeBuilder attributeBuilder = new AttributeBuilder();
                attributeBuilder.setName(name);
                attributeBuilder.addValue(application.getStatus() == ApplicationLifecycleStatus.ACTIVE);
                attributes.add(attributeBuilder.build());
            } else if (LASTUPDATED.equals(name)) {
                attributes.add(buildAttribute(
                        Optional.ofNullable(application.getLastUpdated()).
                                map(t -> t.toInstant().toEpochMilli()).orElse(0L),
                        name, Long.class).build());
            } else {
                objectClassInfo.getAttributeInfo().stream().
                        filter(attr -> attr.getName().equals(name)).findFirst().ifPresent(
                        attributeInfo -> attributes.add(buildAttribute(
                                application.getProfile().get(name),
                                name, attributeInfo.getType()).build()));
            }
        });
        return attributes;
    }

    public static AttributeBuilder buildAttribute(final Object value, final String name, final Class<?> clazz) {
        return buildAttribute(value, name, clazz, new AttributeBuilder());
    }

    public static AttributeBuilder buildAttribute(
            final Object value,
            final String name,
            final Class<?> clazz,
            final AttributeBuilder attributeBuilder) {

        if (value != null) {
            if (clazz == boolean.class || clazz == Boolean.class) {
                attributeBuilder.addValue(Boolean.class.cast(value));
            } else if (value instanceof List<?>) {
                List<?> list = new ArrayList<>((List<?>) value);
                if (list.size() > 1) {
                    list.forEach(elem -> buildAttribute(elem, name, clazz, attributeBuilder));
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

    public static String buildProfileAttrName(final String name) {
        return "profile." + name;
    }

    public static boolean isDefaultEveryoneGroup(final Group group) {
        return GroupType.BUILT_IN == group.getType() && "Everyone".equals(group.getProfile().getName());
    }

    private OktaAttribute() {
        // private constructor for static utility class
    }
}

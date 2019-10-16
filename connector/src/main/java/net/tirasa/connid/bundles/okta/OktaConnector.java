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

import com.okta.sdk.authc.credentials.TokenClientCredentials;
import com.okta.sdk.client.Client;
import com.okta.sdk.client.Clients;
import com.okta.sdk.impl.resource.AbstractCollectionResource;
import com.okta.sdk.impl.resource.application.DefaultApplicationList;
import com.okta.sdk.impl.resource.group.DefaultGroupList;
import com.okta.sdk.impl.resource.user.DefaultUserList;
import com.okta.sdk.resource.CollectionResource;
import com.okta.sdk.resource.application.Application;
import com.okta.sdk.resource.application.ApplicationList;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.group.GroupList;
import com.okta.sdk.resource.user.PasswordCredential;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserBuilder;
import com.okta.sdk.resource.user.UserCredentials;
import com.okta.sdk.resource.user.UserList;
import com.okta.sdk.resource.user.UserStatus;
import java.time.Instant;
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.tirasa.connid.bundles.okta.schema.OktaSchema;
import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import net.tirasa.connid.bundles.okta.utils.OktaUtils;
import org.identityconnectors.common.CollectionUtil;
import org.identityconnectors.common.StringUtil;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.common.security.GuardedString;
import org.identityconnectors.common.security.SecurityUtil;
import org.identityconnectors.framework.common.exceptions.InvalidAttributeValueException;
import org.identityconnectors.framework.common.objects.Attribute;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.AttributesAccessor;
import org.identityconnectors.framework.common.objects.ConnectorObject;
import org.identityconnectors.framework.common.objects.ConnectorObjectBuilder;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.ObjectClassInfo;
import org.identityconnectors.framework.common.objects.ObjectClassUtil;
import org.identityconnectors.framework.common.objects.OperationOptions;
import org.identityconnectors.framework.common.objects.OperationalAttributes;
import org.identityconnectors.framework.common.objects.ResultsHandler;
import org.identityconnectors.framework.common.objects.Schema;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.framework.common.objects.SyncDelta;
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.Filter;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.SearchResultsHandler;
import org.identityconnectors.framework.spi.operations.CreateOp;
import org.identityconnectors.framework.spi.operations.DeleteOp;
import org.identityconnectors.framework.spi.operations.SchemaOp;
import org.identityconnectors.framework.spi.operations.SearchOp;
import org.identityconnectors.framework.spi.operations.SyncOp;
import org.identityconnectors.framework.spi.operations.TestOp;
import org.identityconnectors.framework.spi.operations.UpdateOp;

/**
 * Main implementation of the Okta Connector.
 *
 */
@ConnectorClass(configurationClass = OktaConfiguration.class, displayNameKey = "okta.connector.display")
public class OktaConnector implements Connector,
        CreateOp, UpdateOp, DeleteOp,
        SchemaOp, SyncOp, TestOp, SearchOp<Filter> {

    private static final Log LOG = Log.getLog(OktaConnector.class);

    public static final String APPLICATION_NAME = ObjectClassUtil.createSpecialName("APPLICATION");

    public static final ObjectClass APPLICATION = new ObjectClass(APPLICATION_NAME);

    public static final String SCHEMA_USER_EDITOR_PROFILE_API_URL = "/api/v1/meta/schemas/user/default";

    public static final String USER_API_URL = "/api/v1/users";

    public static final String APP_API_URL = "/api/v1/apps";

    public static final String GROUP_API_URL = "/api/v1/groups";

    public static final String SHA_1 = "SHA-1";

    public static final String SHA_256 = "SHA-256";

    public static final String SHA_512 = "SHA-512";

    public static final String BCRYPT = "BCRYPT";

    public static final String LIMIT = "50";

    public static final String USER = "USER";

    public static final String FILTER = "filter";

    private OktaConfiguration configuration;

    private Client client;

    private OktaSchema schema;

    /**
     * Gets the Configuration context for this connector.
     *
     * @return The current {@link Configuration}
     */
    @Override
    public OktaConfiguration getConfiguration() {
        return configuration;
    }

    /**
     * Callback method to receive the {@link Configuration}.
     *
     * @param configuration
     * the new {@link Configuration}
     * @see org.identityconnectors.framework.spi.Connector#init(org.identityconnectors.framework.spi.Configuration)
     */
    @Override
    public void init(final Configuration configuration) {
        this.configuration = (OktaConfiguration) configuration;
        try {
            this.client = Clients.builder()
                    .setOrgUrl(this.configuration.getDomain())
                    .setClientCredentials(new TokenClientCredentials(this.configuration.getOktaApiToken()))
                    .build();
        } catch (Exception ex) {
            OktaUtils.wrapGeneralError("Could not create Okta client", ex);
        }

        this.schema = new OktaSchema(client);
        LOG.ok("Connector {0} successfully inited", getClass().getName());
    }

    /**
     * Disposes of the {@link OktaConnector}'s resources.
     *
     * @see org.identityconnectors.framework.spi.Connector#dispose()
     */
    @Override
    public void dispose() {
        configuration = null;
        client = null;
        schema = null;
    }

    @Override
    public Uid create(
            final ObjectClass objectClass,
            final Set<Attribute> createAttributes,
            final OperationOptions options) {
        LOG.ok("Connector CREATE");
        if (createAttributes == null || createAttributes.isEmpty()) {
            OktaUtils.handleGeneralError("Set of Attributes value is null or empty");
        }

        final AttributesAccessor accessor = new AttributesAccessor(createAttributes);

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            User result = null;
            String passwordHashAlgorithm = this.configuration.getPasswordHashAlgorithm();
            Attribute status = accessor.find(OperationalAttributes.ENABLE_NAME);
            Attribute email = accessor.find("email");
            try {
                final UserBuilder userBuilder = UserBuilder.instance();

                if (status == null
                        || status.getValue() == null
                        || status.getValue().isEmpty()) {
                    LOG.warn("{0} attribute value not correct or not found, won't handle User status",
                            OperationalAttributes.ENABLE_NAME);
                } else {
                    userBuilder.setActive(AttributeUtil.getBooleanValue(status));
                }

                GuardedString password = accessor.getPassword();
                if (password != null && StringUtil.isNotBlank(SecurityUtil.decrypt(password))) {
                    String passwordValue = SecurityUtil.decrypt(password);
                    if (configuration.isImportHashedPassword()) {
                        switch (passwordHashAlgorithm) {
                            case SHA_1:
                                userBuilder.setSha1PasswordHash(passwordValue,
                                        configuration.getSalt(), configuration.getSaltOrder());
                                break;
                            case SHA_256:
                                userBuilder.setSha256PasswordHash(passwordValue, null, null);
                                break;
                            case SHA_512:
                                userBuilder.setSha512PasswordHash(passwordValue, null, null);
                                break;
                            case BCRYPT:
                                userBuilder.setBcryptPasswordHash(passwordValue, null, 10);
                                break;
                            default:
                                OktaUtils.handleGeneralError(
                                        "Hash Algorithm not supported : " + passwordHashAlgorithm);
                        }
                    } else {
                        userBuilder.setPassword(passwordValue.toCharArray());
                    }
                }

                buildProfile(userBuilder, accessor, objectClass);
                result = userBuilder.buildAndCreate(client);

                //Assign User to Groups
                User user = result;
                Optional.ofNullable(accessor.findList(ObjectClass.GROUP_NAME)).map(Collection::stream)
                        .orElseGet(Stream::empty).map(Object::toString).forEach(item -> user.addToGroup(item));

            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not create User : " + AttributeUtil.getAsStringValue(email), e);
            }
            return new Uid(result != null ? result.getId() : null);
        } else {
            LOG.warn("Create of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Create of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    @Override
    public Uid update(
            final ObjectClass objectClass,
            final Uid uid,
            final Set<Attribute> replaceAttributes,
            final OperationOptions options) {

        LOG.ok("Connector UPDATE");
        if (replaceAttributes == null || replaceAttributes.isEmpty()) {
            OktaUtils.handleGeneralError("Set of Attributes value is null or empty");
        }

        final AttributesAccessor accessor = new AttributesAccessor(replaceAttributes);
        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            Uid returnUid = uid;
            User user = client.getUser(uid.getUidValue());

            try {
                GuardedString password = accessor.getPassword();
                if (password != null && StringUtil.isNotBlank(SecurityUtil.decrypt(password))) {
                    try {
                        UserCredentials userCredentials = client.instantiate(UserCredentials.class);
                        PasswordCredential passwordCredentials = client.instantiate(PasswordCredential.class);
                        passwordCredentials.setValue(SecurityUtil.decrypt(password).toCharArray());
                        userCredentials.setPassword(passwordCredentials);
                        user.setCredentials(userCredentials);
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("Could not update password for User " + uid.getUidValue(), e);
                    }
                }
                
                updateUserAttributes(user, replaceAttributes);
                User updatedUser = user.update(true);

                Attribute status = accessor.find(OperationalAttributes.ENABLE_NAME);
                if (status == null
                        || status.getValue() == null
                        || status.getValue().isEmpty()) {
                    LOG.warn("{0} attribute value not correct, can't handle User status update",
                            OperationalAttributes.ENABLE_NAME);
                } else {
                    if (Boolean.parseBoolean(status.getValue().get(0).toString())) {
                            updatedUser.activate(Boolean.FALSE);
                    } else {
                        if (!updatedUser.getStatus().equals(UserStatus.DEPROVISIONED)) {
                            updatedUser.deactivate();
                        } else {
                            OktaUtils.handleGeneralError("User cannot be deactivated");
                        }
                    }
                }

                returnUid = new Uid(updatedUser.getId());
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not update User " + uid.getUidValue() + " from attributes ", e);
            }

            if (accessor.findList(ObjectClass.GROUP_NAME) != null) {
                try {
                    //Assign User to Groups
                    final List<Object> groupsToAssign =
                            CollectionUtil.nullAsEmpty(accessor.findList(ObjectClass.GROUP_NAME));

                    final Set<String> assignedGroups = Optional.ofNullable(user.listGroups())
                            .map(GroupList::stream).orElseGet(Stream::empty).map(Group::getId).collect(Collectors.
                            toSet());

                    CollectionUtil.nullAsEmpty(groupsToAssign).stream().forEach(grp -> {
                        if (!assignedGroups.contains(grp.toString())) {
                            try {
                                user.addToGroup(grp.toString());
                                LOG.ok("User added to Group: {0} after update", grp);
                            } catch (Exception ex) {
                                LOG.error(ex, "Could not add User {0} to Group {1} ", uid.getUidValue(), grp);
                                OktaUtils.handleGeneralError("Could not add User to Group ", ex);
                            }
                        }

                    });

                    CollectionUtil.nullAsEmpty(assignedGroups).stream().forEach(grp -> {

                        if (!groupsToAssign.contains(grp)) {
                            try {
                                client.getGroup(grp).removeUser(uid.getUidValue());
                                LOG.ok("User removed from group: {0} after update", grp);
                            } catch (Exception ex) {
                                LOG.error(ex, "Could not remove Group {0} from User {1} ", grp, uid.getUidValue());
                                OktaUtils.handleGeneralError("Could not add User to Group ", ex);
                            }
                        }
                    });
                } catch (Exception ex) {
                    LOG.error(ex, "Could not list groups for User {0}", uid.getUidValue());
                    OktaUtils.handleGeneralError("Could not list groups for User", ex);
                }
            }
            return returnUid;
        } else {
            LOG.warn("Update of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Update of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    @Override
    public void delete(
            final ObjectClass objectClass,
            final Uid uid,
            final OperationOptions options) {
        LOG.ok("Connector DELETE");

        if (StringUtil.isBlank(uid.getUidValue())) {
            LOG.error("Uid not provided or empty ");
            throw new InvalidAttributeValueException("Uid value not provided or empty");
        }

        if (objectClass == null) {
            LOG.error("Object value not provided {0} ", objectClass);
            throw new InvalidAttributeValueException("Object value not provided");
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            try {
                User user = client.getUser(uid.getUidValue());
                user.deactivate();
                user.delete();
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not delete User " + uid.getUidValue(), e);
            }
        } else if (APPLICATION.equals(objectClass)) {
            try {
                Application application = client.getApplication(uid.getUidValue());
                application.deactivate();
                application.delete();
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not delete Application " + uid.getUidValue(), e);
            }
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            try {
                Group group = client.getGroup(uid.getUidValue());
                group.delete();
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not delete Group " + uid.getUidValue(), e);
            }
        } else {
            LOG.warn("Delete of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Delete of type"
                    + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    @Override
    public Schema schema() {
        LOG.ok("Building SCHEMA definition");
        return new OktaSchema(client).getSchema();
    }

    @Override
    public SyncToken getLatestSyncToken(final ObjectClass objectClass) {
        LOG.ok("check the ObjectClass");
        Date maxlastUpdate = null;
        try {
            UserList users = client.listUsers();
            maxlastUpdate = users.stream().map(User::getLastUpdated).max(Date::compareTo).get();
            LOG.ok("getLatestSyncToken on {0}", objectClass);
        } catch (Exception e) {
            OktaUtils.handleGeneralError("Error during retrieve SyncToken", e);
        }
        return new SyncToken(maxlastUpdate);
    }

    @Override
    public void sync(
            final ObjectClass objectClass,
            final SyncToken token,
            final SyncResultsHandler handler,
            final OperationOptions options) {

        if (handler == null) {
            OktaUtils.handleGeneralError("Result handler is null");
        }

        Set<String> attributesToGet = new HashSet<>();
        if (options.getAttributesToGet() != null) {
            attributesToGet.addAll(Arrays.asList(options.getAttributesToGet()));
            attributesToGet.add(OktaAttribute.LASTUPDATE);
        }

        // Se filtro è vuoto, niente condizione
        String tokenFilter = "";

        if (token != null && token.getValue() != null) {
            LOG.info("Sync token is {0}", token.getValue());
            Object tokenVal;
            try {
                tokenVal = Instant.parse(token.getValue().toString());
            } catch (Exception e) {
                tokenVal = token.getValue();
            }
            tokenFilter = OktaAttribute.LASTUPDATE + " gt \"" + tokenVal + "\"";
        }

        try {
            LOG.info("execute sync query {0} on {1}", tokenFilter, objectClass);
            CollectionResource<?> result;
            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                result = client.listUsers(null, tokenFilter, null, null, null);
            } else if (ObjectClass.GROUP.equals(objectClass)) {
                result = client.listGroups(null, tokenFilter, null);
            } else {
                result = client.listApplications(null, tokenFilter, null, false);
            }
            result.stream().forEach(item -> {
                ConnectorObject connObj;
                if (item instanceof User) {
                    connObj = fromUser((User) item, attributesToGet);
                } else if (item instanceof Group) {
                    connObj = fromGroup((Group) item, attributesToGet);
                } else {
                    connObj = fromApplication((Application) item, attributesToGet);
                }
                final SyncDelta delta = buildSyncDelta(connObj).build();
                if (delta != null) {
                    handler.handle(delta);
                }
            });

        } catch (Exception e) {
            OktaUtils.handleGeneralError("Sync " + tokenFilter + " on " + objectClass + " error", e);
        }
    }

    @Override
    public void test() {
        if (configuration != null && client != null) {
            try {
                schema();
            } catch (Exception ex) {
                OktaUtils.handleGeneralError("Test error. Problems with client service", ex);
            }
            LOG.ok("Test was successfull");
        } else {
            LOG.error("Test error. No instance of the configuration class");
        }
    }

    public Client getClient() {
        return client;
    }

    @Override
    public FilterTranslator<Filter> createFilterTranslator(
            final ObjectClass objectClass,
            final OperationOptions options) {

        return filter -> Collections.singletonList(filter);
    }

    @Override
    public void executeQuery(
            final ObjectClass objectClass,
            final Filter query,
            final ResultsHandler handler,
            final OperationOptions options) {

        LOG.ok("Connector READ");

        Attribute key = null;
        if (query instanceof EqualsFilter) {
            Attribute filterAttr = ((EqualsFilter) query).getAttribute();
            if (filterAttr instanceof Uid
                    || ObjectClass.ACCOUNT.equals(objectClass)
                    || ObjectClass.GROUP.equals(objectClass)
                    || APPLICATION.equals(objectClass)) {
                key = filterAttr;
            }
        }

        Set<String> attributesToGet = new HashSet<>();
        if (options.getAttributesToGet() != null) {
            attributesToGet.addAll(Arrays.asList(options.getAttributesToGet()));
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (key == null) {
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();
                DefaultUserList userList = null;
                try {
                    if (pagesSize != -1) {
                        String nextPage = StringUtil.isBlank(cookie) ? USER_API_URL + "?limit=" + pagesSize : cookie;
                        userList = client.getDataStore().getResource(nextPage, DefaultUserList.class);
                        nextPage = ((AbstractCollectionResource) userList).hasProperty("nextPage")
                                && ((AbstractCollectionResource) userList).getProperty("nextPage") != null
                                ? ((AbstractCollectionResource) userList).getProperty("nextPage").toString() : null;
                        cookie = userList.getCurrentPage().getItems().size() >= pagesSize ? nextPage : null;
                    } else {
                        userList = ((DefaultUserList) client.listUsers());
                    }

                } catch (Exception e) {
                    OktaUtils.wrapGeneralError("While getting Users!", e);
                }

                for (User user : userList) {
                    handler.handle(fromUser(user, attributesToGet));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }
            } else {
                User result = null;
                if (Uid.NAME.equals(key.getName()) || OktaAttribute.ID.equals(key.getName())) {
                    result = null;
                    try {
                        result = client.getUser(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("While getting User : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                } else {
                    try {
                        UserList users = client.listUsers(null,
                                OktaUtils.buildSearchQuery(key.getName(),
                                        AttributeUtil.getAsStringValue(key)), null, null, null);
                        if (users.iterator().hasNext()) {
                            result = users.single();
                        }
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("While getting User : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                }
                if (result != null) {
                    handler.handle(fromUser(result, attributesToGet));
                }
            }
        } else if (APPLICATION.equals(objectClass)) {
            if (key == null) {
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();
                DefaultApplicationList applicationList = null;
                try {
                    if (pagesSize != -1) {
                        String nextPage = StringUtil.isBlank(cookie) ? APP_API_URL + "?limit=" + pagesSize : cookie;
                        applicationList = client.getDataStore().getResource(nextPage, DefaultApplicationList.class);
                        nextPage = ((AbstractCollectionResource) applicationList).hasProperty("nextPage")
                                && ((AbstractCollectionResource) applicationList).getProperty("nextPage") != null
                                ? ((AbstractCollectionResource) applicationList).getProperty("nextPage").toString()
                                : null;
                        cookie = applicationList.getCurrentPage().getItems().size() >= pagesSize ? nextPage : null;
                    } else {
                        applicationList = ((DefaultApplicationList) client.listApplications());
                    }
                } catch (Exception e) {
                    OktaUtils.wrapGeneralError("While getting Applications!", e);
                }

                for (Application application : applicationList) {
                    handler.handle(fromApplication(application, attributesToGet));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }
            } else {
                Application result = null;
                if (Uid.NAME.equals(key.getName()) || OktaAttribute.ID.equals(key.getName())) {
                    result = null;
                    try {
                        result = client.getApplication(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("While getting Application : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                } else {
                    try {
                        ApplicationList applications = client.listApplications(null, OktaUtils.
                                buildSearchQuery(key.getName(), AttributeUtil.getAsStringValue(key)), null, null);
                        if (applications.iterator().hasNext()) {
                            result = applications.single();
                        }
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("While getting Application : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                }
                if (result != null) {
                    handler.handle(fromApplication(result, attributesToGet));
                }
            }
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            if (key == null) {
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();
                DefaultGroupList groupList = null;
                try {
                    if (pagesSize != -1) {
                        String nextPage = StringUtil.isBlank(cookie) ? GROUP_API_URL + "?limit=" + pagesSize : cookie;
                        groupList = client.getDataStore().getResource(nextPage, DefaultGroupList.class
                        );
                        nextPage = ((AbstractCollectionResource) groupList).hasProperty("nextPage")
                                && ((AbstractCollectionResource) groupList).getProperty("nextPage") != null
                                ? ((AbstractCollectionResource) groupList).getProperty("nextPage").toString()
                                : null;
                        cookie = groupList.getCurrentPage().getItems().size() >= pagesSize ? nextPage : null;
                    } else {
                        groupList = ((DefaultGroupList) client.listGroups());
                    }
                } catch (Exception e) {
                    OktaUtils.wrapGeneralError("While getting Applications!", e);
                }

                for (Group group : groupList) {
                    handler.handle(fromGroup(group, attributesToGet));
                }

                if (handler instanceof SearchResultsHandler) {
                    ((SearchResultsHandler) handler).handleResult(new SearchResult(cookie, remainingResults));
                }
            } else {
                Group result = null;
                if (Uid.NAME.equals(key.getName()) || OktaAttribute.ID.equals(key.getName())) {
                    result = null;
                    try {
                        result = client.getGroup(AttributeUtil.getAsStringValue(key));
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("While getting Application : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                } else {
                    try {
                        GroupList groups = client.listGroups(null, OktaUtils.
                                buildSearchQuery(key.getName(), AttributeUtil.getAsStringValue(key)), null);
                        if (groups.iterator().hasNext()) {
                            result = groups.single();
                        }
                    } catch (Exception e) {
                        OktaUtils.wrapGeneralError("While getting Application : "
                                + key.getName() + " - " + AttributeUtil.getAsStringValue(key), e);
                    }
                }
                if (result != null) {
                    handler.handle(fromGroup(result, attributesToGet));
                }
            }
        } else {
            LOG.warn("Search of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Search of type" + objectClass.getObjectClassValue()
                    + " is not supported");
        }
    }

    private ConnectorObject fromUser(final User user, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);
        builder.setUid(user.getId());
        builder.setName(user.getId());
        return builder.addAttributes(
                OktaAttribute.buildUserAttributes(client, user, schema.getSchema(), attributesToGet)).build();
    }

    private ConnectorObject fromApplication(final Application application, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(APPLICATION);
        builder.setUid(application.getId());
        builder.setName(application.getId());
        return builder.addAttributes(
                OktaAttribute.buildExtResourceAttributes(client, application,
                        schema.getSchema(), attributesToGet, APPLICATION_NAME)).build();
    }

    private ConnectorObject fromGroup(final Group group, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.GROUP);
        builder.setUid(group.getId());
        builder.setName(group.getId());
        return builder.addAttributes(
                OktaAttribute.buildExtResourceAttributes(client, group,
                        schema.getSchema(), attributesToGet, ObjectClass.GROUP_NAME)).build();
    }

    private SyncDeltaBuilder buildSyncDelta(final ConnectorObject connectorObject) {
        LOG.info("buildSyncDelta");
        SyncDeltaBuilder bld = new SyncDeltaBuilder();

        Attribute lastUpdate = connectorObject.getAttributeByName(OktaAttribute.LASTUPDATE);
        if (lastUpdate == null || lastUpdate.getValue() == null || lastUpdate.getValue().isEmpty()) {
            OktaUtils.handleGeneralError("LastUpdate attribute is not present");
        }

        Object lastUpdateValue = lastUpdate.getValue().get(0);
        if (lastUpdateValue == null) {
            LOG.ok("token value is null, replacing to 0L");
            lastUpdateValue = 0L;
        }

        // To be sure that sync token is present
        bld.setToken(new SyncToken(lastUpdateValue));
        bld.setObject(connectorObject);
        bld.setDeltaType(SyncDeltaType.CREATE_OR_UPDATE);
        LOG.ok("SyncDeltaBuilder is ok");

        return bld;
    }

    /**
     * Complete the profile with all the properties.
     *
     */
    private void buildProfile(
            final UserBuilder userBuilder,
            final AttributesAccessor accessor,
            final ObjectClass objectClass) {

        ObjectClassInfo objectClassInfo = schema.getSchema().findObjectClassInfo(objectClass.getObjectClassValue());
        accessor.listAttributeNames().stream().forEach(attrName -> {
            if (!OperationalAttributes.ENABLE_NAME.equals(attrName)
                    && !OktaAttribute.ID.equals(attrName)
                    && !Name.NAME.equals(attrName)
                    && !OktaAttribute.STATUS.equals(attrName) && !OperationalAttributes.PASSWORD_NAME.equals(attrName)) {

                objectClassInfo.getAttributeInfo().stream().filter(
                        attr -> attr.getName().equals(attrName)).findFirst().ifPresent(attributeInfo -> {

                            if (OktaAttribute.BASIC_PROFILE_ATTRIBUTES.contains(attributeInfo.getName())) {
                                switch (attributeInfo.getName()) {
                                    case OktaAttribute.FIRSTNAME:
                                        userBuilder.setFirstName(AttributeUtil.getStringValue(accessor.find(attrName)));
                                        break;
                                    case OktaAttribute.LASTNAME:
                                        userBuilder.setLastName(AttributeUtil.getStringValue(accessor.find(attrName)));
                                        break;
                                    case OktaAttribute.EMAIL:
                                        userBuilder.setEmail(AttributeUtil.getStringValue(accessor.find(attrName)));
                                        break;
                                    case OktaAttribute.LOGIN:
                                        userBuilder.setLogin(AttributeUtil.getStringValue(accessor.find(attrName)));
                                        break;
                                    case OktaAttribute.MOBILEPHONE:
                                        userBuilder.setMobilePhone(
                                                AttributeUtil.getStringValue(accessor.find(
                                                        attrName)));
                                        break;
                                    case OktaAttribute.SECOND_EMAIL:
                                        userBuilder.setSecondEmail(
                                                AttributeUtil.getStringValue(accessor.find(attrName)));
                                        break;
                                }
                            } else {
                                if (Boolean.class.isInstance(attributeInfo.getType())) {
                                    userBuilder.putProfileProperty(attrName,
                                            AttributeUtil.getBooleanValue(accessor.find(attrName)));
                                } else if (Integer.class.isInstance(attributeInfo.getType())) {
                                    userBuilder.putProfileProperty(attrName,
                                            AttributeUtil.getIntegerValue(accessor.find(attrName)));
                                } else if (String.class.isInstance(attributeInfo.getType())) {
                                    userBuilder.putProfileProperty(attrName,
                                            AttributeUtil.getStringValue(accessor.find(attrName)));
                                } else {
                                    userBuilder.putProfileProperty(attrName,
                                            AttributeUtil.getSingleValue(accessor.find(attrName)));
                                }
                            }
                        });
            }
        });
    }

    private void updateUserAttributes(final User user, final Set<Attribute> replaceAttributes) {
        ObjectClassInfo objectClassInfo = schema.getSchema().findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        replaceAttributes.stream().forEach(attribute -> {

            if (!OperationalAttributes.ENABLE_NAME.equals(attribute.getName())
                    && !Name.NAME.equals(attribute.getName())
                    && !OktaAttribute.ID.equals(attribute.getName())
                    && !OktaAttribute.STATUS.equals(attribute.getName())
                    && !OperationalAttributes.PASSWORD_NAME.equals(attribute.getName())) {

                objectClassInfo.getAttributeInfo().stream().filter(
                        attr -> attr.getName().equals(attribute.getName())).findFirst().ifPresent(attributeInfo -> {

                            if (attribute.getValue() != null && !attribute.getValue().isEmpty()) {
                                if (OktaAttribute.BASIC_PROFILE_ATTRIBUTES.contains(attribute.getName())) {
                                    switch (attributeInfo.getName()) {
                                        case OktaAttribute.FIRSTNAME:
                                            user.getProfile().setFirstName(AttributeUtil.getStringValue(attribute));
                                            break;
                                        case OktaAttribute.LASTNAME:
                                            user.getProfile().setLastName(AttributeUtil.getStringValue(attribute));
                                            break;
                                        case OktaAttribute.EMAIL:
                                            user.getProfile().setEmail(AttributeUtil.getStringValue(attribute));
                                            break;
                                        case OktaAttribute.LOGIN:
                                            user.getProfile().setLogin(AttributeUtil.getStringValue(attribute));
                                            break;
                                        case OktaAttribute.MOBILEPHONE:
                                            user.getProfile().setMobilePhone(AttributeUtil.getStringValue(attribute));
                                            break;
                                        case OktaAttribute.SECOND_EMAIL:
                                            user.getProfile().setSecondEmail(AttributeUtil.getStringValue(attribute));
                                            break;
                                    }
                                } else {
                                    if (Boolean.class.isInstance(attributeInfo.getType())) {
                                        user.getProfile().put(attribute.getName(),
                                                AttributeUtil.getBooleanValue(attribute));
                                    } else if (Integer.class.isInstance(attributeInfo.getType())) {
                                        user.getProfile().put(attribute.getName(),
                                                AttributeUtil.getIntegerValue(attribute));
                                    } else if (String.class
                                            .isInstance(attributeInfo.getType())) {
                                        user.getProfile().put(attribute.getName(),
                                                AttributeUtil.getStringValue(attribute));
                                    } else {
                                        user.getProfile().put(attribute.getName(),
                                                AttributeUtil.getSingleValue(attribute));
                                    }
                                }
                            }
                        });
            }
        });
    }
}

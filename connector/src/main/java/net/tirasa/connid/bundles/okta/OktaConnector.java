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
import com.okta.sdk.resource.ExtensibleResource;
import com.okta.sdk.resource.ResourceException;
import com.okta.sdk.resource.application.Application;
import com.okta.sdk.resource.application.ApplicationList;
import com.okta.sdk.resource.group.Group;
import com.okta.sdk.resource.group.GroupList;
import com.okta.sdk.resource.log.LogEvent;
import com.okta.sdk.resource.log.LogEventList;
import com.okta.sdk.resource.user.ChangePasswordRequest;
import com.okta.sdk.resource.user.PasswordCredential;
import com.okta.sdk.resource.user.User;
import com.okta.sdk.resource.user.UserBuilder;
import com.okta.sdk.resource.user.UserCredentials;
import com.okta.sdk.resource.user.UserList;
import com.okta.sdk.resource.user.UserStatus;
import java.util.Arrays;
import java.util.Collection;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.stream.Collectors;
import java.util.stream.Stream;
import net.tirasa.connid.bundles.okta.schema.OktaSchema;
import net.tirasa.connid.bundles.okta.utils.CipherAlgorithm;
import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import net.tirasa.connid.bundles.okta.utils.OktaEventType;
import net.tirasa.connid.bundles.okta.utils.OktaFilter;
import net.tirasa.connid.bundles.okta.utils.OktaFilterOp;
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
import org.identityconnectors.framework.common.objects.SyncDeltaBuilder;
import org.identityconnectors.framework.common.objects.SyncDeltaType;
import org.identityconnectors.framework.common.objects.SyncResultsHandler;
import org.identityconnectors.framework.common.objects.SyncToken;
import org.identityconnectors.framework.common.objects.Uid;
import org.identityconnectors.framework.common.objects.filter.FilterTranslator;
import org.identityconnectors.framework.spi.Configuration;
import org.identityconnectors.framework.spi.Connector;
import org.identityconnectors.framework.spi.ConnectorClass;
import org.identityconnectors.framework.spi.PoolableConnector;
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
public class OktaConnector implements Connector, PoolableConnector,
        CreateOp, UpdateOp, DeleteOp, SchemaOp, SyncOp, TestOp, SearchOp<OktaFilter> {

    private static final Log LOG = Log.getLog(OktaConnector.class);

    public static final String APPLICATION_NAME = ObjectClassUtil.createSpecialName("APPLICATION");

    public static final ObjectClass APPLICATION = new ObjectClass(APPLICATION_NAME);

    public static final String SCHEMA_USER_EDITOR_PROFILE_API_URL = "/api/v1/meta/schemas/user/default";

    public static final String USER_API_URL = "/api/v1/users";

    public static final String APP_API_URL = "/api/v1/apps";

    public static final String GROUP_API_URL = "/api/v1/groups";

    public static final String LOG_API_URL = "/api/v1/logs";

    public static final String LIMIT = "50";

    public static final String USER = "USER";

    public static final String FILTER = "filter";

    public static final String CIPHER_ALGORITHM = "cipherAlgorithm";

    public static final String SALT = "salt";

    public static final String SALT_ORDER = "saltOrder";

    public static final String SORT_ORDER = "sortOrder";

    public static final String WORK_FACTOR = "workFactor";

    private static final Set<String> NOT_FOR_PROFILE = CollectionUtil.newReadOnlySet(
            Name.NAME, OperationalAttributes.ENABLE_NAME, OperationalAttributes.PASSWORD_NAME,
            OktaAttribute.ID, OktaAttribute.STATUS,
            OktaAttribute.OKTA_SECURITY_QUESTION, OktaAttribute.OKTA_SECURITY_ANSWER);

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
            if (client == null) {
                this.client = Clients.builder()
                        .setOrgUrl(this.configuration.getDomain())
                        .setClientCredentials(new TokenClientCredentials(this.configuration.getOktaApiToken()))
                        .setRetryMaxAttempts(this.configuration.getRateLimitMaxRetries())
                        .setRetryMaxElapsed(this.configuration.getRetryMaxElapsed())
                        .setConnectionTimeout(this.configuration.getRequestTimeout())
                        .build();
            }
        } catch (Exception ex) {
            OktaUtils.wrapGeneralError("Could not create Okta client", ex);
        }

        if (schema == null) {
            this.schema = new OktaSchema(client);
        }

        LOG.ok("Connector {0} successfully inited", getClass().getName());
    }

    @Override
    public void checkAlive() {
        LOG.ok("Check Alive");
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
            Attribute status = accessor.find(OperationalAttributes.ENABLE_NAME);
            Attribute email = accessor.find(OktaAttribute.EMAIL);
            try {
                UserBuilder userBuilder = UserBuilder.instance();

                if (status == null || CollectionUtil.isEmpty(status.getValue())) {
                    LOG.warn("{0} attribute value not correct or not found, won't handle User status",
                            OperationalAttributes.ENABLE_NAME);
                } else {
                    userBuilder.setActive(AttributeUtil.getBooleanValue(status));
                }

                GuardedString password = accessor.getPassword();
                if (password != null) {
                    String passwordValue = SecurityUtil.decrypt(password);
                    String passwordHashAlgorithm = accessor.findString(CIPHER_ALGORITHM);
                    if (StringUtil.isNotBlank(passwordHashAlgorithm)) {
                        String salt = accessor.findString(SALT);
                        String saltOrder = accessor.findString(SALT_ORDER);
                        switch (CipherAlgorithm.valueOfLabel(passwordHashAlgorithm)) {
                            case SHA:
                            case SHA1:
                            case SSHA:
                            case SSHA1:
                                userBuilder.setSha1PasswordHash(passwordValue, salt, saltOrder);
                                break;

                            case SHA256:
                            case SSHA256:
                                userBuilder.setSha256PasswordHash(passwordValue, salt, saltOrder);
                                break;

                            case SHA512:
                            case SSHA512:
                                userBuilder.setSha512PasswordHash(passwordValue, salt, saltOrder);
                                break;

                            case BCRYPT:
                                userBuilder.setBcryptPasswordHash(
                                        passwordValue, salt, accessor.findInteger(WORK_FACTOR));
                                break;

                            default:
                                OktaUtils.handleGeneralError(
                                        "Hash Algorithm not supported : " + passwordHashAlgorithm);
                        }
                    } else {
                        userBuilder.setPassword(passwordValue.toCharArray());
                    }

                    String securityQuestion = accessor.findString(OktaAttribute.OKTA_SECURITY_QUESTION);
                    if (StringUtil.isNotBlank(securityQuestion)) {
                        userBuilder.setSecurityQuestion(securityQuestion);
                    }
                    String securityAnswer = accessor.findString(OktaAttribute.OKTA_SECURITY_ANSWER);
                    if (StringUtil.isNotBlank(securityAnswer)) {
                        userBuilder.setSecurityQuestionAnswer(securityAnswer);
                    }
                }

                buildProfile(userBuilder, accessor, objectClass);
                result = userBuilder.buildAndCreate(client);

                //Assign User to Groups
                User user = result;
                Optional.ofNullable(accessor.findList(OktaAttribute.OKTA_GROUPS)).map(Collection::stream)
                        .orElseGet(Stream::empty).map(Object::toString).forEach(item -> user.addToGroup(item));
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not create User : " + AttributeUtil.getAsStringValue(email), e);
            }

            if (result == null || result.getId() == null) {
                OktaUtils.handleGeneralError("Something wrong happened during user create, check logs");
            }

            return new Uid(result.getId());
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

            GuardedString password = accessor.getPassword();
            if (password != null && StringUtil.isNotBlank(SecurityUtil.decrypt(password))) {
                Attribute currentPassword = accessor.find(OperationalAttributes.CURRENT_PASSWORD_NAME);
                GuardedString currentPasswordValue =
                        currentPassword == null ? null : AttributeUtil.getGuardedStringValue(currentPassword);
                if (currentPasswordValue != null
                        && StringUtil.isNotBlank(SecurityUtil.decrypt(currentPasswordValue))) {
                    selfPasswordUpdate(user, currentPasswordValue, password);
                } else {
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
            }
            try {
                updateUserAttributes(user, replaceAttributes);
                User updatedUser = user.update(true);

                updateUserStatus(updatedUser, accessor.find(OperationalAttributes.ENABLE_NAME));
                returnUid = new Uid(updatedUser.getId());
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not update User " + uid.getUidValue() + " from attributes ", e);
            }

            if (accessor.findList(OktaAttribute.OKTA_GROUPS) != null) {
                try {
                    //Assign User to Groups
                    final List<Object> groupsToAssign =
                            CollectionUtil.nullAsEmpty(accessor.findList(OktaAttribute.OKTA_GROUPS));

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
                                LOG.error(ex, "Could not remove User {0} from Group {1} ", uid.getUidValue(), grp);
                                OktaUtils.handleGeneralError("Could not remove User from Group " + grp, ex);
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
                user.delete(false);
                user.delete(false);
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
        return schema.getSchema();
    }

    @Override
    public SyncToken getLatestSyncToken(final ObjectClass objectClass) {
        LOG.ok("check the ObjectClass");
        long maxlastUpdate = 0;
        try {
            maxlastUpdate = getLastLogEvent(objectClass);
            LOG.ok("getLatestSyncToken on {0} - {1}", objectClass, maxlastUpdate);
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
            attributesToGet.add(OktaAttribute.LASTUPDATED);
        }

        Object tokenValue = null;
        if (token == null || token.getValue() == null) {
            LOG.info("Synchronization with empty token.");
        } else {
            LOG.info("Synchronization with token.");
            //Add one to get all events after this SyncToken
            tokenValue = Long.valueOf(token.getValue().toString());
        }

        LOG.info("Execute sync query {0} on {1}", tokenValue, objectClass);
        LogEventList logEvents = getEvents(objectClass,
                tokenValue != null ? OktaUtils.convertToDate(tokenValue.toString()) : null);
        if (logEvents != null) {
            logEvents.stream().forEach(item -> {
                ConnectorObject connObj = null;
                ExtensibleResource result;
                try {
                    if (isDeleteEvent(item.getEventType())) {
                        connObj = fromLogEvent(
                                item.getTarget().get(0).getId(), item.getPublished().getTime(), objectClass);
                    } else {
                        try {
                            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                                result = client.getUser(item.getTarget().get(0).getId());
                                connObj = fromUser((User) result, attributesToGet);
                            } else if (ObjectClass.GROUP.equals(objectClass)) {
                                result = client.getGroup(item.getTarget().get(0).getId());
                                connObj = fromGroup((Group) result, attributesToGet);
                            } else {
                                result = client.getApplication(item.getTarget().get(0).getId());
                                connObj = fromApplication((Application) result, attributesToGet);
                            }
                        } catch (Exception ex) {
                            LOG.info("{0} not found", item.getTarget().get(0).getId());
                        }
                    }

                    if (connObj != null && !handler.handle(buildSyncDelta(connObj, item).build())) {
                        LOG.ok("Stop processing of the sync result set");
                        OktaUtils.handleGeneralError("Stop processing of the sync result set");
                    }
                } catch (Exception e) {
                    OktaUtils.handleGeneralError("Sync on " + objectClass + " error", e);
                }
            });
        }
    }

    @Override
    public void test() {
        if (configuration != null && client != null) {
            try {
                new OktaSchema(client).getSchema();
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
    public FilterTranslator<OktaFilter> createFilterTranslator(
            ObjectClass oclass, final OperationOptions options) {

        LOG.info("check the ObjectClass");
        if (oclass == null) {
            throw new IllegalArgumentException("Object class not supported");
        }
        LOG.ok("The ObjectClass is ok");
        return new OktaFilterTranslator(oclass);
    }

    @Override
    public void executeQuery(
            final ObjectClass objectClass,
            final OktaFilter filter,
            final ResultsHandler handler,
            final OperationOptions options) {

        LOG.ok("Connector READ");

        if (filter != null && filter.getAttribute() != null && filter.getValue() == null) {
            return;
        }

        Set<String> attributesToGet = new HashSet<>();
        if (options.getAttributesToGet() != null) {
            attributesToGet.addAll(Arrays.asList(options.getAttributesToGet()));
        }

        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            if (filter == null) {
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
                try {
                    if (filter.getFilters() == null
                            && OktaFilter.SEARCH_ATTRS.contains(filter.getAttribute())
                            && OktaFilterOp.EQUALS.equals(filter.getFilterOp())) {
                        User user = client.getUser(filter.getValue());
                        handler.handle(fromUser(user, attributesToGet));
                    } else {
                        UserList users = client.listUsers(null, null, null, filter.toString(), null);
                        for (User user : users) {
                            if (!handler.handle(fromUser(user, attributesToGet))) {
                                LOG.ok("Stop processing of the result set");
                                break;
                            }
                        }
                    }
                } catch (Exception e) {
                    OktaUtils.wrapGeneralError("While getting User : " + filter, e);
                }
            }
        } else if (APPLICATION.equals(objectClass)) {
            if (filter == null) {
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
                try {
                    ApplicationList applications = client.listApplications(null, filter.toString(), null, null);
                    for (Application app : applications) {
                        if (!handler.handle(fromApplication(app, attributesToGet))) {
                            LOG.ok("Stop processing of the result set");
                            break;
                        }
                    }
                } catch (Exception e) {
                    OktaUtils.wrapGeneralError("While getting Application : " + filter.toString(), e);
                }
                if (result != null) {
                    handler.handle(fromApplication(result, attributesToGet));
                }
            }
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            if (filter == null) {
                int remainingResults = -1;
                int pagesSize = options.getPageSize() != null ? options.getPageSize() : -1;
                String cookie = options.getPagedResultsCookie();
                DefaultGroupList groupList = null;
                try {
                    if (pagesSize != -1) {
                        String nextPage = StringUtil.isBlank(cookie) ? GROUP_API_URL + "?limit=" + pagesSize : cookie;
                        groupList = client.getDataStore().getResource(nextPage, DefaultGroupList.class);
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
                try {
                    GroupList groups = OktaAttribute.ID.equals(filter.getAttribute())
                            || OktaAttribute.NAME.equals(filter.getAttribute())
                            ? client.listGroups(filter.getValue(), null, null)
                            : client.listGroups(null, filter.toString(), null);
                    for (Group group : groups) {
                        if (!handler.handle(fromGroup(group, attributesToGet))) {
                            LOG.ok("Stop processing of the result set");
                            break;
                        }
                    }
                } catch (Exception e) {
                    OktaUtils.wrapGeneralError("While getting Groups: " + filter.toString(), e);
                }
            }
        } else {
            LOG.warn("Search of type {0} is not supported", objectClass.getObjectClassValue());
            throw new UnsupportedOperationException("Search of type" + objectClass.getObjectClassValue()
                    + " is not supported");
        }
    }

    private long getLastLogEvent(final ObjectClass objectClass) {
        String filter = buildFilterByObjectClass(objectClass);
        if (StringUtil.isBlank(filter)) {
            OktaUtils.handleGeneralError("Provide envenType for Sync");
        }
        LogEventList events = client.getDataStore().getResource(
                LOG_API_URL + "?filter=" + filter + "&limit=1&sortOrder=DESCENDING", LogEventList.class);
        return events != null && events.stream().count() > 0 ? events.single().getPublished().getTime() : 0L;
    }

    private LogEventList getEvents(final ObjectClass objectClass, final String from) {
        String filter = buildFilterByObjectClass(objectClass);
        if (StringUtil.isBlank(filter)) {
            LOG.info("Provide envenType for Sync {0}", objectClass);
            return null;
        }
        return client.getLogs(null, from, filter, null, "ASCENDING");
    }

    private String buildFilterByObjectClass(final ObjectClass objectClass) {
        return ObjectClass.ACCOUNT.equals(objectClass)
                ? buildLogEventFilter(configuration.getUserEvents()) : ObjectClass.GROUP.equals(objectClass)
                ? buildLogEventFilter(configuration.getGroupEvents()) : APPLICATION.equals(objectClass)
                ? buildLogEventFilter(configuration.getApplicationEvents()) : null;
    }

    private String buildLogEventFilter(final String[] eventTypes) {
        boolean isFirst = true;
        StringBuilder builder = new StringBuilder();
        for (String type : eventTypes) {
            if (!isFirst) {
                builder.append(" or ");
            }
            builder.append("eventType eq ");
            builder.append("\"");
            builder.append(type);
            builder.append("\"");
            isFirst = false;
        }
        return builder.toString();
    }

    private ConnectorObject fromLogEvent(final String id, final long lastUpdate, final ObjectClass objectClass) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(objectClass);
        builder.setUid(id);
        builder.setName(id);
        builder.addAttribute(
                OktaAttribute.buildAttribute(lastUpdate, OktaAttribute.LASTUPDATED, Long.class).build());
        return builder.build();
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

    private SyncDeltaBuilder buildSyncDelta(final ConnectorObject connectorObject, final LogEvent event) {
        LOG.info("Build SyncDelta");
        SyncDeltaBuilder bld = new SyncDeltaBuilder();
        long published;
        if (isMembershipOperationEvent(event.getEventType())) {
            published = event.getPublished().getTime();
        } else {
            Attribute lastUpdate = connectorObject.getAttributeByName(OktaAttribute.LASTUPDATED);
            published = Long.valueOf(AttributeUtil.getSingleValue(lastUpdate).toString());
        }

        bld.setToken(new SyncToken(published));
        bld.setObject(connectorObject);
        bld.setDeltaType(getSyncDeltaTypeByEvent(event.getEventType()));
        LOG.ok("SyncDeltaBuilder is ok");

        return bld;
    }

    private SyncDeltaType getSyncDeltaTypeByEvent(final String event) {
        OktaEventType oktaEventType = OktaEventType.getValueByName(event);
        if (oktaEventType == null) {
            LOG.error("Okta event not found: {0}", event);
            OktaUtils.handleGeneralError("Okta event not defined");
        }
        return OktaEventType.getValueByName(event).getSyncDeltaType();
    }

    private boolean isDeleteEvent(final String eventType) {
        return OktaEventType.getDeleteEventType().contains(eventType);
    }

    private boolean isMembershipOperationEvent(final String eventType) {
        return OktaEventType.getMembershipOperationEventType().contains(eventType);
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
        accessor.listAttributeNames().stream().
                filter(attrName -> !NOT_FOR_PROFILE.contains(attrName)).
                forEach(attrName -> objectClassInfo.getAttributeInfo().stream().
                filter(attr -> attr.getName().equals(attrName)).findFirst().
                ifPresent(attributeInfo -> {

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
                                userBuilder.setMobilePhone(AttributeUtil.getStringValue(accessor.find(attrName)));
                                break;

                            case OktaAttribute.SECOND_EMAIL:
                                userBuilder.setSecondEmail(AttributeUtil.getStringValue(accessor.find(attrName)));
                                break;

                            default:
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
                }));
    }

    private void updateUserAttributes(final User user, final Set<Attribute> replaceAttributes) {
        ObjectClassInfo objectClassInfo = schema.getSchema().findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        replaceAttributes.stream().
                filter(attribute -> !NOT_FOR_PROFILE.contains(attribute.getName())).
                forEach(attribute -> objectClassInfo.getAttributeInfo().stream().
                filter(attr -> attr.getName().equals(attribute.getName())).findFirst().
                ifPresent(attributeInfo -> {

                    if (!CollectionUtil.isEmpty(attribute.getValue())) {
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

                                default:
                            }
                        } else {
                            if (Boolean.class.isInstance(attributeInfo.getType())) {
                                user.getProfile().put(attribute.getName(), AttributeUtil.getBooleanValue(attribute));
                            } else if (Integer.class.isInstance(attributeInfo.getType())) {
                                user.getProfile().put(attribute.getName(), AttributeUtil.getIntegerValue(attribute));
                            } else if (String.class
                                    .isInstance(attributeInfo.getType())) {
                                user.getProfile().put(attribute.getName(), AttributeUtil.getStringValue(attribute));
                            } else {
                                user.getProfile().put(attribute.getName(), AttributeUtil.getSingleValue(attribute));
                            }
                        }
                    }
                }));
    }

    private void updateUserStatus(final User updatedUser, final Attribute status) {
        if (status == null || CollectionUtil.isEmpty(status.getValue())) {
            LOG.warn("{0} attribute value not correct, can't handle User status update",
                    OperationalAttributes.ENABLE_NAME);
        } else {
            boolean enabled = (boolean) status.getValue().get(0);

            if (updatedUser.getStatus() == UserStatus.ACTIVE && !enabled) {
                updatedUser.suspend();
            } else if (updatedUser.getStatus() == UserStatus.SUSPENDED && enabled) {
                updatedUser.unsuspend();
            } else if (updatedUser.getStatus() == UserStatus.STAGED) {
                if (enabled) {
                    updatedUser.activate(Boolean.FALSE);
                } else {
                    LOG.ok("not suspending user {0} as in STAGED status", updatedUser.getId());
                }
            } else if (updatedUser.getStatus() != UserStatus.DEPROVISIONED && !enabled) {
                updatedUser.deactivate();
            }
        }
    }

    private void selfPasswordUpdate(final User user, final GuardedString oldPassword, final GuardedString newPassword) {
        try {
            user.changePassword(client.instantiate(ChangePasswordRequest.class).
                    setOldPassword(client.instantiate(PasswordCredential.class).
                            setValue(SecurityUtil.decrypt(oldPassword).toCharArray())).
                    setNewPassword(client.instantiate(PasswordCredential.class).
                            setValue(SecurityUtil.decrypt(newPassword).toCharArray())));
            LOG.ok("Self change passsowrd user {0}" + user.getId());
        } catch (ResourceException e) {
            LOG.error(e.getMessage(), e);
            if (!CollectionUtil.isEmpty(e.getCauses())) {
                OktaUtils.handleGeneralError(e.getError().getCauses().get(0).getSummary());
            } else {
                OktaUtils.handleGeneralError(e.getMessage(), e);
            }
        } catch (Exception e) {
            LOG.error(e.getMessage(), e);
            OktaUtils.handleGeneralError(e.getMessage(), e);
        }
    }

    /**
     * Disposes of the {@link OktaConnector}'s resources.
     *
     * @see org.identityconnectors.framework.spi.Connector#dispose()
     */
    @Override
    public void dispose() {
    }
}

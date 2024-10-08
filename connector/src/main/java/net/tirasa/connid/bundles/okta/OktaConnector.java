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
import com.okta.sdk.cache.Caches;
import com.okta.sdk.client.AuthorizationMode;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.client.Clients;
import com.okta.sdk.helper.PaginationUtil;
import com.okta.sdk.resource.api.ApplicationApi;
import com.okta.sdk.resource.api.GroupApi;
import com.okta.sdk.resource.api.SchemaApi;
import com.okta.sdk.resource.api.SystemLogApi;
import com.okta.sdk.resource.api.UserApi;
import com.okta.sdk.resource.api.UserCredApi;
import com.okta.sdk.resource.api.UserLifecycleApi;
import com.okta.sdk.resource.api.UserResourcesApi;
import com.okta.sdk.resource.client.ApiClient;
import com.okta.sdk.resource.client.ApiException;
import com.okta.sdk.resource.group.GroupBuilder;
import com.okta.sdk.resource.model.AddGroupRequest;
import com.okta.sdk.resource.model.Application;
import com.okta.sdk.resource.model.ChangePasswordRequest;
import com.okta.sdk.resource.model.Group;
import com.okta.sdk.resource.model.LogEvent;
import com.okta.sdk.resource.model.OktaUserGroupProfile;
import com.okta.sdk.resource.model.PasswordCredential;
import com.okta.sdk.resource.model.UpdateUserRequest;
import com.okta.sdk.resource.model.User;
import com.okta.sdk.resource.model.UserGetSingleton;
import com.okta.sdk.resource.model.UserProfile;
import com.okta.sdk.resource.model.UserStatus;
import com.okta.sdk.resource.user.UserBuilder;
import java.time.OffsetDateTime;
import java.time.format.DateTimeFormatter;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;
import java.util.function.Function;
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
import org.identityconnectors.framework.common.exceptions.ConnectorException;
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

    public static final String LIMIT = "50";

    public static final String USER = "USER";

    public static final String FILTER = "filter";

    public static final String CIPHER_ALGORITHM = "cipherAlgorithm";

    public static final String SALT = "salt";

    public static final String SALT_ORDER = "saltOrder";

    public static final String WORK_FACTOR = "workFactor";

    private static final Set<String> NOT_FOR_PROFILE = CollectionUtil.newReadOnlySet(
            Name.NAME, OperationalAttributes.ENABLE_NAME, OperationalAttributes.PASSWORD_NAME,
            OktaAttribute.ID, OktaAttribute.STATUS,
            OktaAttribute.OKTA_SECURITY_QUESTION, OktaAttribute.OKTA_SECURITY_ANSWER,
            OktaAttribute.OKTA_GROUPS);

    private OktaConfiguration configuration;

    private ApiClient apiClient;

    private UserApi userApi;

    private UserResourcesApi userResourcesApi;

    private UserLifecycleApi userLifecycleApi;

    private UserCredApi userCredApi;

    private GroupApi groupApi;

    private ApplicationApi appApi;

    private SystemLogApi systemLogApi;

    private OktaSchema schema;

    public UserApi getUserApi() {
        return userApi;
    }

    public UserResourcesApi getUserResourcesApi() {
        return userResourcesApi;
    }

    public UserLifecycleApi getUserLifecycleApi() {
        return userLifecycleApi;
    }

    public GroupApi getGroupApi() {
        return groupApi;
    }

    public ApplicationApi getAppApi() {
        return appApi;
    }

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
            if (userApi == null || userResourcesApi == null || userLifecycleApi == null || userCredApi == null
                    || groupApi == null || appApi == null || systemLogApi == null || schema == null) {

                ClientBuilder builder = Clients.builder()
                        .setCacheManager(Caches.newDisabledCacheManager())
                        .setOrgUrl(this.configuration.getDomain())
                        .setRetryMaxAttempts(this.configuration.getRateLimitMaxRetries())
                        .setRetryMaxElapsed(this.configuration.getRetryMaxElapsed())
                        .setConnectionTimeout(this.configuration.getRequestTimeout());
                if (this.configuration.getClientId() != null && this.configuration.getPrivateKeyPEM() != null) {
                    builder.setAuthorizationMode(AuthorizationMode.PRIVATE_KEY)
                            .setClientId(this.configuration.getClientId())
                            .setScopes(new HashSet<>(Arrays.asList("okta.schemas.read", "okta.users.manage",
                                    "okta.groups.manage", "okta.apps.manage", "okta.logs.read")))
                            .setPrivateKey(this.configuration.getPrivateKeyPEM());
                } else {
                    builder.setClientCredentials(new TokenClientCredentials(this.configuration.getOktaApiToken()));
                }

                this.apiClient = builder.build();
                this.userApi = new UserApi(apiClient);
                this.userResourcesApi = new UserResourcesApi(apiClient);
                this.userLifecycleApi = new UserLifecycleApi(apiClient);
                this.userCredApi = new UserCredApi(apiClient);
                this.groupApi = new GroupApi(apiClient);
                this.appApi = new ApplicationApi(apiClient);
                this.systemLogApi = new SystemLogApi(apiClient);
                this.schema = new OktaSchema(new SchemaApi(apiClient));
            }
        } catch (Exception ex) {
            OktaUtils.wrapGeneralError("Could not create Okta client", ex);
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

        AttributesAccessor accessor = new AttributesAccessor(createAttributes);

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

                //Assign User to Groups
                Optional.ofNullable(accessor.findList(OktaAttribute.OKTA_GROUPS)).map(Collection::stream).
                        orElseGet(Stream::empty).map(Object::toString).forEach(userBuilder::addGroup);

                result = userBuilder.buildAndCreate(userApi);
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not create User : " + AttributeUtil.getAsStringValue(email), e);
            }

            if (result == null || result.getId() == null) {
                OktaUtils.handleGeneralError("Something wrong happened during user create, check logs");
            }

            return new Uid(result.getId());
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            GroupBuilder groupBuilder = GroupBuilder.instance();

            Group result = null;
            try {
                result = groupBuilder.setName(accessor.findString(OktaAttribute.NAME))
                        .setDescription(accessor.findString(OktaAttribute.DESCRIPTION))
                        .buildAndCreate(groupApi);
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not create Group : " + accessor.findString(OktaAttribute.NAME), e);
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

        AttributesAccessor accessor = new AttributesAccessor(replaceAttributes);
        if (ObjectClass.ACCOUNT.equals(objectClass)) {
            Uid returnUid = uid;
            UserGetSingleton user = userApi.getUser(uid.getUidValue(), null, null);

            // 1. update password
            Optional.ofNullable(accessor.getPassword()).
                    map(SecurityUtil::decrypt).filter(StringUtil::isNotBlank).ifPresent(newPassword -> {

                Optional.ofNullable(accessor.find(OperationalAttributes.CURRENT_PASSWORD_NAME)).
                        map(AttributeUtil::getGuardedStringValue).map(SecurityUtil::decrypt).
                        filter(StringUtil::isNotBlank).
                        ifPresent(oldPassword -> selfPasswordUpdate(user.getId(), oldPassword, newPassword));
            });

            // 2. update attributes
            try {
                updateUserProfile(user.getProfile(), replaceAttributes);
                UpdateUserRequest req = new UpdateUserRequest();
                req.setProfile(user.getProfile());

                User update = userApi.updateUser(user.getId(), req, Boolean.FALSE);

                updateUserStatus(update, accessor.find(OperationalAttributes.ENABLE_NAME));
                returnUid = new Uid(update.getId());
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not update User " + uid.getUidValue() + " from attributes ", e);
            }

            // 3. update group memberships
            if (accessor.hasAttribute(OktaAttribute.OKTA_GROUPS)) {
                try {
                    List<Object> groupsToAssign =
                            CollectionUtil.nullAsEmpty(accessor.findList(OktaAttribute.OKTA_GROUPS));

                    Set<String> assignedGroups = userResourcesApi.listUserGroups(user.getId()).stream()
                            .filter(item -> !OktaAttribute.isDefaultEveryoneGroup(item))
                            .map(Group::getId).collect(Collectors.toSet());

                    groupsToAssign.stream().
                            filter(grp -> !assignedGroups.contains(grp.toString())).
                            forEach(grp -> {
                                try {
                                    groupApi.assignUserToGroup(grp.toString(), user.getId());
                                    LOG.ok("User {0} added to Group {1} after update", uid.getUidValue(), grp);
                                } catch (Exception ex) {
                                    OktaUtils.handleGeneralError(
                                            "Could not add User " + uid.getUidValue() + " to Group " + grp, ex);
                                }
                            });

                    assignedGroups.stream().
                            filter(grp -> !groupsToAssign.contains(grp)).
                            forEach(grp -> {
                                try {
                                    groupApi.unassignUserFromGroup(grp, user.getId());
                                    LOG.ok("User {0} removed from Group {1} after update", uid.getUidValue(), grp);
                                } catch (Exception ex) {
                                    OktaUtils.handleGeneralError(
                                            "Could not remove User " + uid.getUidValue() + " from Group " + grp, ex);
                                }
                            });
                } catch (ConnectorException ex) {
                    // skip reporting as thrown by OktaUtils#handleGeneralError
                } catch (Exception ex) {
                    OktaUtils.handleGeneralError("Errors while working with groups for User " + uid.getUidValue(), ex);
                }
            }
            return returnUid;
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            OktaUserGroupProfile groupProfile = new OktaUserGroupProfile();

            Optional.ofNullable(accessor.getName()).
                    ifPresent(name -> groupProfile.setName(name.getNameValue()));

            Optional.ofNullable(accessor.find(OktaAttribute.DESCRIPTION)).
                    ifPresent(desc -> groupProfile.setDescription(AttributeUtil.getStringValue(desc)));

            Group update = null;
            try {
                update = groupApi.replaceGroup(uid.getUidValue(), new AddGroupRequest().profile(groupProfile));
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not update Group " + uid.getUidValue() + " from attributes ", e);
            }

            return new Uid(update.getId());
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
                userApi.deleteUser(uid.getUidValue(), Boolean.FALSE, null);
                userApi.deleteUser(uid.getUidValue(), Boolean.FALSE, null);
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not delete User " + uid.getUidValue(), e);
            }
        } else if (APPLICATION.equals(objectClass)) {
            try {
                appApi.deactivateApplication(uid.getUidValue());
                appApi.deleteApplication(uid.getUidValue());
            } catch (Exception e) {
                OktaUtils.wrapGeneralError("Could not delete Application " + uid.getUidValue(), e);
            }
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            try {
                groupApi.deleteGroup(uid.getUidValue());
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

        Long tokenValue = null;
        if (token == null || token.getValue() == null) {
            LOG.info("Synchronization with empty token.");
        } else {
            LOG.info("Synchronization with token.");
            //Add one to get all events after this SyncToken
            tokenValue = Long.valueOf(token.getValue().toString());
        }

        LOG.info("Execute sync query {0} on {1}", tokenValue, objectClass);
        List<LogEvent> logEvents = getEvents(
                objectClass,
                tokenValue == null ? null : OktaUtils.convertToDate(tokenValue));
        if (logEvents != null) {
            logEvents.stream().forEach(item -> {
                ConnectorObject connObj = null;
                try {
                    if (isDeleteEvent(item.getEventType())) {
                        connObj = fromLogEvent(
                                item.getTarget().get(0).getId(),
                                item.getPublished().toInstant().toEpochMilli(),
                                objectClass);
                    } else {
                        try {
                            if (ObjectClass.ACCOUNT.equals(objectClass)) {
                                UserGetSingleton user = userApi.getUser(item.getTarget().get(0).getId(), null, null);
                                connObj = fromUser(user, attributesToGet);
                            } else if (ObjectClass.GROUP.equals(objectClass)) {
                                Group group = groupApi.getGroup(item.getTarget().get(0).getId());
                                connObj = fromGroup(group, attributesToGet);
                            } else {
                                Application app = appApi.getApplication(item.getTarget().get(0).getId(), null);
                                connObj = fromApplication(app, attributesToGet);
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
        if (configuration != null && schema != null) {
            try {
                schema.getSchema();
            } catch (Exception ex) {
                OktaUtils.handleGeneralError("Test error. Problems with client service", ex);
            }
            LOG.ok("Test was successfull");
        } else {
            LOG.error("Test error. No instance of the configuration class");
        }
    }

    @Override
    public FilterTranslator<OktaFilter> createFilterTranslator(
            final ObjectClass oclass, final OperationOptions options) {

        LOG.info("check the ObjectClass");
        if (oclass == null) {
            throw new IllegalArgumentException("Object class not supported");
        }
        LOG.ok("The ObjectClass is ok");
        return new OktaFilterTranslator(oclass);
    }

    private <T, S> void doExecuteQuery(
            final ObjectClass objectClass,
            final OktaFilter filter,
            final Integer pageSize,
            final String beforeCookie,
            final ResultsHandler handler,
            final Function<String, S> getFunction,
            final Function<String, List<T>> pagedSearchFunction,
            final Function<String, List<T>> searchFunction,
            final Function<T, ConnectorObject> fromObject,
            final Function<S, ConnectorObject> fromObjectSingletonGet) {

        if (filter != null && filter.getFilters() == null
                && OktaAttribute.ID.equals(filter.getAttribute())
                && OktaFilterOp.EQUALS.equals(filter.getFilterOp())) {

            try {
                S object = getFunction.apply(filter.getValue());
                handler.handle(fromObjectSingletonGet.apply(object));
            } catch (Exception e) {
                OktaUtils.wrapGeneralError(
                        "While getting " + objectClass.getObjectClassValue() + " with filter: " + filter, e);
            }
        } else {
            String theFilter = Optional.ofNullable(filter).map(OktaFilter::toString).orElse(null);
            String afterCookie = beforeCookie;
            List<T> objects = null;
            try {
                if (pageSize != null) {
                    List<T> response = pagedSearchFunction.apply(theFilter);
                    objects = response;

                    if (response.size() >= pageSize) {
                        afterCookie = PaginationUtil.getAfter(apiClient);
                    }
                } else {
                    objects = searchFunction.apply(theFilter);
                }
            } catch (Exception e) {
                OktaUtils.wrapGeneralError(
                        "While getting " + objectClass.getObjectClassValue() + " with filter: " + filter, e);
            }

            for (T object : CollectionUtil.nullAsEmpty(objects)) {
                if (!handler.handle(fromObject.apply(object))) {
                    LOG.ok("Stop processing of the result set");
                    break;
                }
            }

            if (handler instanceof SearchResultsHandler) {
                ((SearchResultsHandler) handler).handleResult(new SearchResult(afterCookie, -1));
            }
        }
    }

    @SuppressWarnings("unchecked")
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
            doExecuteQuery(
                    objectClass,
                    filter,
                    options.getPageSize(),
                    options.getPagedResultsCookie(),
                    handler,
                    userId -> userApi.getUser(userId, null, null),
                    f -> userApi.listUsers(
                            null, null, options.getPagedResultsCookie(), options.getPageSize(), f, null, null, null),
                    f -> userApi.listUsers(
                            null, null, null, null, f, null, null, null),
                    user -> fromUser(user, attributesToGet),
                    userGetSingleton -> fromUser(userGetSingleton, attributesToGet));
        } else if (APPLICATION.equals(objectClass)) {
            doExecuteQuery(
                    objectClass,
                    filter,
                    options.getPageSize(),
                    options.getPagedResultsCookie(),
                    handler,
                    id -> appApi.getApplication(id, null),
                    f -> appApi.listApplications(
                            null, options.getPagedResultsCookie(), null, options.getPageSize(), f, null, null),
                    f -> appApi.listApplications(
                            null, null, null, null, f, null, null),
                    o -> fromApplication(o, attributesToGet),
                    o -> fromApplication(o, attributesToGet));
        } else if (ObjectClass.GROUP.equals(objectClass)) {
            doExecuteQuery(
                    objectClass,
                    filter,
                    options.getPageSize(),
                    options.getPagedResultsCookie(),
                    handler,
                    groupApi::getGroup,
                    f -> groupApi.listGroups(
                            null, f, options.getPagedResultsCookie(), options.getPageSize(), null, null, null, null),
                    f -> groupApi.listGroups(
                            null, f, null, null, null, null, null, null),
                    o -> fromGroup(o, attributesToGet),
                    o -> fromGroup(o, attributesToGet));
        } else {
            throw new UnsupportedOperationException(
                    "Search of type" + objectClass.getObjectClassValue() + " is not supported");
        }
    }

    private long getLastLogEvent(final ObjectClass objectClass) {
        String filter = buildFilterByObjectClass(objectClass);
        if (StringUtil.isBlank(filter)) {
            OktaUtils.handleGeneralError("Provide envenType for Sync");
        }

        List<LogEvent> events = systemLogApi.listLogEvents(null, null, null, filter, null, 1, "DESCENDING", Map.of());
        return CollectionUtil.isEmpty(events) ? 0L : events.get(0).getPublished().toInstant().toEpochMilli();
    }

    private List<LogEvent> getEvents(final ObjectClass objectClass, final OffsetDateTime since) {
        String filter = buildFilterByObjectClass(objectClass);
        if (StringUtil.isBlank(filter)) {
            LOG.info("Provide envenType for Sync {0}", objectClass);
            return null;
        }
        return systemLogApi.listLogEvents(
                Optional.ofNullable(since).map(s -> s.format(DateTimeFormatter.ISO_DATE_TIME)).orElse(null),
                null, null, filter, null, null, "ASCENDING", Map.of());
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
        builder.addAttribute(OktaAttribute.buildAttribute(lastUpdate, OktaAttribute.LASTUPDATED, Long.class).build());
        return builder.build();
    }

    private ConnectorObject fromUser(
            final UserGetSingleton user,
            final Set<String> attributesToGet) {

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);
        builder.setUid(user.getId());
        builder.setName(user.getProfile().getLogin());
        builder.addAttributes(OktaAttribute.buildUserAttributes(
                userResourcesApi,
                user.getId(),
                user.getStatus(),
                user.getLastUpdated(),
                user.getProfile(),
                schema.getSchema(),
                attributesToGet));
        return builder.build();
    }

    private ConnectorObject fromUser(
            final User user,
            final Set<String> attributesToGet) {

        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.ACCOUNT);
        builder.setUid(user.getId());
        builder.setName(user.getProfile().getLogin());
        builder.addAttributes(OktaAttribute.buildUserAttributes(
                userResourcesApi,
                user.getId(),
                user.getStatus(),
                user.getLastUpdated(),
                user.getProfile(),
                schema.getSchema(),
                attributesToGet));
        return builder.build();
    }

    private ConnectorObject fromApplication(final Application application, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(APPLICATION);
        builder.setUid(application.getId());
        builder.setName(application.getId());
        builder.addAttributes(OktaAttribute.buildApplicationAttributes(appApi, application, schema.getSchema(),
                attributesToGet));
        return builder.build();
    }

    private ConnectorObject fromGroup(final Group group, final Set<String> attributesToGet) {
        ConnectorObjectBuilder builder = new ConnectorObjectBuilder();
        builder.setObjectClass(ObjectClass.GROUP);
        builder.setUid(group.getId());
        builder.setName(group.getProfile().getName());
        builder.addAttributes(OktaAttribute.buildGroupAttributes(
                groupApi, group, schema.getSchema(), attributesToGet));
        return builder.build();
    }

    private SyncDeltaBuilder buildSyncDelta(final ConnectorObject connectorObject, final LogEvent event) {
        LOG.info("Build SyncDelta");
        SyncDeltaBuilder bld = new SyncDeltaBuilder();
        long published;
        if (isMembershipOperationEvent(event.getEventType())) {
            published = event.getPublished().toInstant().toEpochMilli();
        } else {
            Attribute lastUpdate = connectorObject.getAttributeByName(OktaAttribute.LASTUPDATED);
            published = Long.parseLong(AttributeUtil.getSingleValue(lastUpdate).toString());
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
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getBooleanValue(accessor.find(attrName)));
                        } else if (Integer.class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getIntegerValue(accessor.find(attrName)));
                        } else if (Long.class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getLongValue(accessor.find(attrName)));
                        } else if (Float.class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getFloatValue(accessor.find(attrName)));
                        } else if (Double.class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getDoubleValue(accessor.find(attrName)));
                        } else if (Date.class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getDateValue(accessor.find(attrName)));
                        } else if (Byte[].class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getByteArrayValue(accessor.find(attrName)));
                        } else if (String.class.isInstance(attributeInfo.getType())) {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getStringValue(accessor.find(attrName)));
                        } else {
                            userBuilder.setCustomProfileProperty(attrName,
                                    AttributeUtil.getSingleValue(accessor.find(attrName)));
                        }
                    }
                }));
    }

    private void updateUserProfile(final UserProfile userProfile, final Set<Attribute> replaceAttributes) {
        ObjectClassInfo objectClassInfo = schema.getSchema().findObjectClassInfo(ObjectClass.ACCOUNT_NAME);
        replaceAttributes.stream().
                filter(attribute -> !NOT_FOR_PROFILE.contains(attribute.getName())).
                forEach(attr -> objectClassInfo.getAttributeInfo().stream().
                filter(attrInfo -> attrInfo.getName().equals(attr.getName())).findFirst().
                ifPresent(attrInfo -> {

                    if (OktaAttribute.BASIC_PROFILE_ATTRIBUTES.contains(attr.getName())) {
                        String value = CollectionUtil.isEmpty(attr.getValue())
                                ? null
                                : AttributeUtil.getStringValue(attr);

                        switch (attrInfo.getName()) {
                            case OktaAttribute.FIRSTNAME:
                                userProfile.setFirstName(value);
                                break;

                            case OktaAttribute.LASTNAME:
                                userProfile.setLastName(value);
                                break;

                            case OktaAttribute.EMAIL:
                                userProfile.setEmail(value);
                                break;

                            case OktaAttribute.LOGIN:
                                userProfile.setLogin(value);
                                break;

                            case OktaAttribute.MOBILEPHONE:
                                userProfile.setMobilePhone(value);
                                break;

                            case OktaAttribute.SECOND_EMAIL:
                                userProfile.setSecondEmail(value);
                                break;

                            default:
                        }
                    } else {
                        userProfile.getAdditionalProperties().put(
                                attr.getName(),
                                CollectionUtil.isEmpty(attr.getValue())
                                ? null
                                : AttributeUtil.getSingleValue(attr));
                    }
                }));
    }

    private void updateUserStatus(final User user, final Attribute status) {
        if (status == null || CollectionUtil.isEmpty(status.getValue())) {
            LOG.warn("{0} attribute value not correct, can't handle User status update",
                    OperationalAttributes.ENABLE_NAME);
        } else {
            boolean enabled = (boolean) status.getValue().get(0);

            if (user.getStatus() == UserStatus.ACTIVE && !enabled) {
                userLifecycleApi.suspendUser(user.getId());
            } else if (user.getStatus() == UserStatus.SUSPENDED && enabled) {
                userLifecycleApi.unsuspendUser(user.getId());
            } else if (user.getStatus() == UserStatus.STAGED) {
                if (enabled) {
                    userLifecycleApi.activateUser(user.getId(), Boolean.FALSE);
                } else {
                    LOG.ok("not suspending user {0} as in STAGED status", user.getId());
                }
            } else if (user.getStatus() != UserStatus.DEPROVISIONED && !enabled) {
                userLifecycleApi.deactivateUser(user.getId(), Boolean.FALSE, null);
            }
        }
    }

    private void selfPasswordUpdate(final String userId, final String oldPassword, final String newPassword) {
        try {
            PasswordCredential oldPwd = new PasswordCredential();
            oldPwd.setValue(oldPassword);

            PasswordCredential newPwd = new PasswordCredential();
            newPwd.setValue(newPassword);

            ChangePasswordRequest req = new ChangePasswordRequest();
            req.setOldPassword(oldPwd);
            req.setNewPassword(newPwd);

            userCredApi.changePassword(userId, req, Boolean.FALSE);
            LOG.ok("Self change passsword user {0}" + userId);
        } catch (ApiException e) {
            LOG.error(e, e.getMessage());
            if (e.getCause() == null) {
                OktaUtils.handleGeneralError(e.getMessage(), e);
            } else {
                OktaUtils.handleGeneralError(e.getCause().getMessage(), e.getCause());
            }
        } catch (Exception e) {
            LOG.error(e, e.getMessage());
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

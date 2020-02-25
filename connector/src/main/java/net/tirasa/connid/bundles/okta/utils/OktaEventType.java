/**
 * Copyright (C) 2019 ConnId (connid-dev@googlegroups.com)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *         http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package net.tirasa.connid.bundles.okta.utils;

import java.util.Arrays;
import java.util.Set;
import java.util.stream.Collectors;
import org.identityconnectors.framework.common.objects.SyncDeltaType;

public enum OktaEventType {

    APPLICATION_LIFECYCLE_ACTIVATE("application.lifecycle.activate", SyncDeltaType.CREATE_OR_UPDATE),
    APPLICATION_LIFECYCLE_CREATE("application.lifecycle.create", SyncDeltaType.CREATE_OR_UPDATE),
    APPLICATION_LIFECYCLE_DEACTIVATE("application.lifecycle.deactivate", SyncDeltaType.CREATE_OR_UPDATE),
    APPLICATION_LIFECYCLE_DELETE("application.lifecycle.delete", SyncDeltaType.DELETE),
    APPLICATION_LIFECYCLE_UPDATE("application.lifecycle.update", SyncDeltaType.CREATE_OR_UPDATE),
    APPLICATION_USER_MEMBERSHIP_ADD("application.user_membership.add", SyncDeltaType.CREATE_OR_UPDATE),
    APPLICATION_USER_MEMBERSHIP_CHANGE_USERNAME("application.user_membership.change_username",
            SyncDeltaType.CREATE_OR_UPDATE),
    APPLICATION_USER_MEMBERSHIP_REMOVE("application.user_membership.remove", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_APPLICATION_ASSIGNMENT_ADD("group.application_assignment.add", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_APPLICATION_ASSIGNMENT_REMOVE("group.application_assignment.remove", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_APPLICATION_ASSIGNMENT_SKIP_ASSIGNMENT_RECONCILE("group.application_assignment.skip_assignment_reconcile",
            SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_APPLICATION_ASSIGNMENT_UPDATE("group.application_assignment.update", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_PRIVILEGE_GRANT("group.privilege.grant", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_PRIVILEGE_REVOKE("group.privilege.revoke", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_RULE_ADD_EXCLUSION("group.user_membership.rule.add_exclusion", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_RULE_DEACTIVATED("group.user_membership.rule.deactivated", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_RULE_ERROR("group.user_membership.rule.error", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_RULE_EVALUATION("group.user_membership.rule.evaluation", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_RULE_INVALIDATE("group.user_membership.rule.invalidate", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_RULE_TRIGGER("group.user_membership.rule.trigger", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_ADD("group.user_membership.add", SyncDeltaType.CREATE_OR_UPDATE),
    GROUP_USER_MEMBERSHIP_REMOVE("group.user_membership.remove", SyncDeltaType.CREATE_OR_UPDATE),
    USER_AUTHENTICATION_SSO("user.authentication.sso", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_ACTIVATE("user.lifecycle.activate", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_CREATE("user.lifecycle.create", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_UPDATE("user.lifecycle.update", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_DEACTIVATE("user.lifecycle.deactivate", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_SUSPEND("user.lifecycle.suspend", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_UNSUSPENDED("user.lifecycle.unsuspend", SyncDeltaType.CREATE_OR_UPDATE),
    USER_LIFECYCLE_DELETE("user.lifecycle.delete", SyncDeltaType.DELETE),
    USER_ACCOUNT_ACCESS_SUPER_USER_APP("user.account.access_super_user_app", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_LOCK("user.account.lock", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_LOCK_LIMIT("user.account.lock.limit", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_PRIVILEGE_GRANT("user.account.privilege.grant", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_PRIVILEGE_REVOKE("user.account.privilege.revoke", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_RESET_PASSWORD("user.account.reset_password", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UNLOCK("user.account.unlock", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UNLOCK_BY_ADMIN("user.account.unlock_by_admin", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UNLOCK_FAILURE("user.account.unlock_failure", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UNLOCK_TOKEN("user.account.unlock_token", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UPDATE_PASSWORD("user.account.update_password", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UPDATE_PRIMARY_EMAIL("user.account.update_primary_email", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UPDATE_PROFILE("user.account.update_profile", SyncDeltaType.CREATE_OR_UPDATE),
    USER_ACCOUNT_UPDATE_SECONDARY_EMAIL("user.account.update_secondary_email", SyncDeltaType.CREATE_OR_UPDATE);

    private final String name;

    private final SyncDeltaType syncDeltaType;

    private OktaEventType(final String name, final SyncDeltaType syncDeltaType) {
        this.name = name;
        this.syncDeltaType = syncDeltaType;
    }

    public String getName() {
        return name;
    }

    public SyncDeltaType getSyncDeltaType() {
        return syncDeltaType;
    }

    public static OktaEventType getValueByName(final String name) {
        return Arrays.stream(values()).filter(item -> item.getName().equals(name)).findFirst().orElse(null);
    }
    
    public static Set<String> getDeleteEventType() {
        return Arrays.stream(values()).filter(item -> 
                SyncDeltaType.DELETE.equals(item.getSyncDeltaType())).map(
                        event -> event.getName()).collect(Collectors.toSet());
    }
    
    public static Set<String> getMembershipOperationEventType() {
        return Arrays.stream(values()).filter(item -> 
                item.name().contains("MEMBERSHIP")).map(event -> event.getName()).collect(Collectors.toSet());
    }
}

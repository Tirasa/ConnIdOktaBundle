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

import org.identityconnectors.common.StringUtil;
import org.identityconnectors.framework.spi.AbstractConfiguration;
import org.identityconnectors.framework.spi.ConfigurationProperty;
import org.identityconnectors.framework.spi.StatefulConfiguration;

/**
 * Extends the {@link AbstractConfiguration} class to provide all the necessary
 * parameters to initialize the Okta Connector.
 */
public class OktaConfiguration extends AbstractConfiguration implements StatefulConfiguration {

    private String domain;

    private String oktaApiToken;

    private String clientId;

    private String privateKeyPEM;

    private String[] userEvents = { "user.account.update_profile" };

    private String[] groupEvents = {};

    private String[] applicationEvents = {};

    private int rateLimitMaxRetries = 1;

    private int retryMaxElapsed = 0;

    private int requestTimeout = 20;

    @ConfigurationProperty(order = 1, displayMessageKey = "domain.display",
            groupMessageKey = "basic.group", helpMessageKey = "domain.help", required = true,
            confidential = false)
    public String getDomain() {
        return domain;
    }

    public void setDomain(final String domain) {
        this.domain = domain;
    }

    @ConfigurationProperty(order = 2, displayMessageKey = "oktaApiToken.display",
            groupMessageKey = "basic.group", helpMessageKey = "oktaApiToken.help", required = false,
            confidential = true)
    public String getOktaApiToken() {
        return oktaApiToken;
    }

    public void setOktaApiToken(final String oktaApiToken) {
        this.oktaApiToken = oktaApiToken;
    }

    @ConfigurationProperty(order = 3, displayMessageKey = "clientId.display",
            groupMessageKey = "basic.group", helpMessageKey = "clientId.help", required = false,
            confidential = false)
    public String getClientId() {
        return clientId;
    }

    public void setClientId(final String clientId) {
        this.clientId = clientId;
    }

    @ConfigurationProperty(order = 4, displayMessageKey = "privateKeyPEM.display",
            groupMessageKey = "basic.group", helpMessageKey = "privateKeyPEM.help", required = false,
            confidential = true)
    public String getPrivateKeyPEM() {
        return privateKeyPEM;
    }

    public void setPrivateKeyPEM(final String privateKeyPEM) {
        this.privateKeyPEM = privateKeyPEM;
    }

    @ConfigurationProperty(order = 5,
            displayMessageKey = "userEvents.display",
            groupMessageKey = "basic.group",
            helpMessageKey = "userEvents.help")
    public String[] getUserEvents() {
        return userEvents.clone();
    }

    public void setUserEvents(final String... userEvents) {
        this.userEvents = userEvents.clone();
    }

    @ConfigurationProperty(order = 6,
            displayMessageKey = "groupEvents.display",
            groupMessageKey = "basic.group",
            helpMessageKey = "groupEvents.help")
    public String[] getGroupEvents() {
        return groupEvents.clone();
    }

    public void setGroupEvents(final String... groupEvents) {
        this.groupEvents = groupEvents.clone();
    }

    @ConfigurationProperty(order = 7,
            displayMessageKey = "applicationEvents.display",
            groupMessageKey = "basic.group",
            helpMessageKey = "applicationEvents.help")
    public String[] getApplicationEvents() {
        return applicationEvents.clone();
    }

    public void setApplicationEvents(final String... applicationEvents) {
        this.applicationEvents = applicationEvents.clone();
    }

    public void setRateLimitMaxRetries(final int rateLimitMaxRetries) {
        this.rateLimitMaxRetries = rateLimitMaxRetries;
    }

    @ConfigurationProperty(order = 8,
            displayMessageKey = "rateLimitMaxRetries.display",
            groupMessageKey = "basic.group",
            helpMessageKey = "rateLimitMaxRetries.help")
    public int getRateLimitMaxRetries() {
        return rateLimitMaxRetries;
    }

    public void setRetryMaxElapsed(final int retryMaxElapsed) {
        this.retryMaxElapsed = retryMaxElapsed;
    }

    @ConfigurationProperty(order = 9,
            displayMessageKey = "retryMaxElapsed.display",
            groupMessageKey = "basic.group",
            helpMessageKey = "retryMaxElapsed.help")
    public int getRetryMaxElapsed() {
        return retryMaxElapsed;
    }

    public void setRequestTimeout(final int requestTimeout) {
        this.requestTimeout = requestTimeout;
    }

    @ConfigurationProperty(order = 10,
            displayMessageKey = "requestTimeout.display",
            groupMessageKey = "basic.group",
            helpMessageKey = "requestTimeout.help")
    public int getRequestTimeout() {
        return requestTimeout;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(domain)) {
            throw new IllegalArgumentException("Domain cannot be null or empty.");
        }
        if (StringUtil.isBlank(oktaApiToken)) {
            throw new IllegalArgumentException("OktaApiToken cannot be null or empty.");
        }
        if (requestTimeout < 0) {
            throw new IllegalArgumentException("Timeout cannot be a negative number");
        }
    }

    @Override
    public void release() {
    }
}

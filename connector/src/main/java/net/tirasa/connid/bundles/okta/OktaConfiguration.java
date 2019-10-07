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

/**
 * Extends the {@link AbstractConfiguration} class to provide all the necessary
 * parameters to initialize the Okta Connector.
 */
public class OktaConfiguration extends AbstractConfiguration {

    private String domain;

    private String oktaApiToken;

    private String passwordHashAlgorithm;

    private boolean importHashedPassword;

    private String salt;

    private String saltOrder;

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
            groupMessageKey = "basic.group", helpMessageKey = "oktaApiToken.help", required = true,
            confidential = true)
    public String getOktaApiToken() {
        return oktaApiToken;
    }

    public void setOktaApiToken(final String oktaApiToken) {
        this.oktaApiToken = oktaApiToken;
    }

    @ConfigurationProperty(order = 3, displayMessageKey = "passwordHashAlgorithm.display",
            groupMessageKey = "basic.group", helpMessageKey = "passwordHashAlgorithm.help", required = false,
            confidential = false)
    public String getPasswordHashAlgorithm() {
        return passwordHashAlgorithm;
    }

    public void setPasswordHashAlgorithm(final String passwordHashAlgorithm) {
        this.passwordHashAlgorithm = passwordHashAlgorithm;
    }

    @ConfigurationProperty(order = 4, displayMessageKey = "importHashedPassword.display",
            groupMessageKey = "basic.group", helpMessageKey = "importHashedPassword.help", required = false,
            confidential = false)
    public boolean isImportHashedPassword() {
        return importHashedPassword;
    }

    public void setImportHashedPassword(final boolean importHashedPassword) {
        this.importHashedPassword = importHashedPassword;
    }

    @ConfigurationProperty(order = 5, displayMessageKey = "salt.display",
            groupMessageKey = "basic.group", helpMessageKey = "salt.help", required = false,
            confidential = true)
    public String getSalt() {
        return salt;
    }

    public void setSalt(final String salt) {
        this.salt = salt;
    }

    @ConfigurationProperty(order = 6, displayMessageKey = "saltOrder.display",
            groupMessageKey = "basic.group", helpMessageKey = "saltOrder.help", required = false,
            confidential = false)
    public String getSaltOrder() {
        return saltOrder;
    }

    public void setSaltOrder(final String saltOrder) {
        this.saltOrder = saltOrder;
    }

    @Override
    public void validate() {
        if (StringUtil.isBlank(domain)) {
            throw new IllegalArgumentException("Domain cannot be null or empty.");
        }
        if (StringUtil.isBlank(oktaApiToken)) {
            throw new IllegalArgumentException("OktaApiToken cannot be null or empty.");
        }
    }
}

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

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.module.SimpleModule;
import com.fasterxml.jackson.datatype.jsr310.JavaTimeModule;
import com.okta.commons.lang.Assert;
import com.okta.sdk.authc.credentials.ClientCredentials;
import com.okta.sdk.cache.CacheManager;
import com.okta.sdk.cache.Caches;
import com.okta.sdk.client.AuthenticationScheme;
import com.okta.sdk.client.AuthorizationMode;
import com.okta.sdk.client.ClientBuilder;
import com.okta.sdk.error.ErrorHandler;
import com.okta.sdk.impl.api.DefaultClientCredentialsResolver;
import com.okta.sdk.impl.client.DefaultClientBuilder;
import com.okta.sdk.impl.config.ClientConfiguration;
import com.okta.sdk.impl.deserializer.UserProfileDeserializer;
import com.okta.sdk.impl.oauth2.AccessTokenRetrieverServiceImpl;
import com.okta.sdk.impl.oauth2.OAuth2ClientCredentials;
import com.okta.sdk.impl.serializer.UserProfileSerializer;
import com.okta.sdk.impl.util.ConfigUtil;
import java.nio.file.Files;
import java.nio.file.InvalidPathException;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import org.apache.http.HttpHost;
import org.apache.http.auth.AuthScope;
import org.apache.http.auth.UsernamePasswordCredentials;
import org.apache.http.client.CredentialsProvider;
import org.apache.http.impl.client.BasicCredentialsProvider;
import org.apache.http.impl.client.HttpClientBuilder;
import org.apache.http.impl.client.ProxyAuthenticationStrategy;
import org.openapitools.client.ApiClient;
import org.openapitools.client.model.UserProfile;
import org.openapitools.jackson.nullable.JsonNullableModule;
import org.springframework.http.MediaType;
import org.springframework.http.client.BufferingClientHttpRequestFactory;
import org.springframework.http.client.HttpComponentsClientHttpRequestFactory;
import org.springframework.http.converter.HttpMessageConverter;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.web.client.RestTemplate;
import org.springframework.web.util.DefaultUriBuilderFactory;

public class ConnIdClientBuilder extends DefaultClientBuilder {

    protected final CacheManager cacheManager = Caches.newDisabledCacheManager();

    @SuppressWarnings("rawtypes")
    protected ClientCredentials clientCredentials;

    public ConnIdClientBuilder() {
        super();
        setCacheManager(cacheManager);
    }

    @SuppressWarnings("rawtypes")
    @Override
    public ClientBuilder setClientCredentials(final ClientCredentials clientCredentials) {
        super.setClientCredentials(clientCredentials);
        this.clientCredentials = clientCredentials;
        return this;
    }

    protected BufferingClientHttpRequestFactory requestFactory() {
        HttpClientBuilder clientBuilder = HttpClientBuilder.create();

        ClientConfiguration clientConfig = getClientConfiguration();
        if (clientConfig.getProxy() != null) {
            clientBuilder.useSystemProperties();
            clientBuilder.setProxy(new HttpHost(clientConfig.getProxyHost(), clientConfig.getProxyPort()));
            CredentialsProvider credentialsProvider = new BasicCredentialsProvider();
            AuthScope authScope = new AuthScope(clientConfig.getProxyHost(), clientConfig.getProxyPort());
            UsernamePasswordCredentials usernamePasswordCredentials =
                    new UsernamePasswordCredentials(clientConfig.getProxyUsername(), clientConfig.getProxyPassword());
            credentialsProvider.setCredentials(authScope, usernamePasswordCredentials);
            clientBuilder.setDefaultCredentialsProvider(credentialsProvider);
            clientBuilder.setProxyAuthenticationStrategy(new ProxyAuthenticationStrategy());
        }

        HttpComponentsClientHttpRequestFactory clientHttpRequestFactory = new HttpComponentsClientHttpRequestFactory();
        clientHttpRequestFactory.setHttpClient(clientBuilder.build());
        clientHttpRequestFactory.setConnectionRequestTimeout(clientConfig.getConnectionTimeout() * 1000);
        clientHttpRequestFactory.setConnectTimeout(clientConfig.getConnectionTimeout() * 1000);
        clientHttpRequestFactory.setReadTimeout(clientConfig.getConnectionTimeout() * 1000);

        return new BufferingClientHttpRequestFactory(clientHttpRequestFactory);
    }

    protected RestTemplate restTemplate() {
        ObjectMapper objectMapper = new ObjectMapper();
        objectMapper.setSerializationInclusion(JsonInclude.Include.NON_NULL);
        objectMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
        objectMapper.registerModule(new JavaTimeModule());
        objectMapper.registerModule(new JsonNullableModule());

        SimpleModule module = new SimpleModule();
        module.addSerializer(UserProfile.class, new UserProfileSerializer());
        module.addDeserializer(UserProfile.class, new UserProfileDeserializer());
        objectMapper.registerModule(module);

        MappingJackson2HttpMessageConverter mappingJackson2HttpMessageConverter =
                new MappingJackson2HttpMessageConverter(objectMapper);

        mappingJackson2HttpMessageConverter.setSupportedMediaTypes(Arrays.asList(
                MediaType.APPLICATION_JSON,
                MediaType.parseMediaType("application/x-pem-file"),
                MediaType.parseMediaType("application/x-x509-ca-cert"),
                MediaType.parseMediaType("application/pkix-cert")));

        List<HttpMessageConverter<?>> messageConverters = new ArrayList<>();
        messageConverters.add(mappingJackson2HttpMessageConverter);

        // this allows to encode the + sign
        DefaultUriBuilderFactory uriTemplateHandler = new DefaultUriBuilderFactory();
        uriTemplateHandler.setEncodingMode(DefaultUriBuilderFactory.EncodingMode.VALUES_ONLY);

        RestTemplate restTemplate = new RestTemplate(messageConverters);
        restTemplate.setErrorHandler(new ErrorHandler());
        restTemplate.setRequestFactory(requestFactory());
        restTemplate.setUriTemplateHandler(uriTemplateHandler);

        return restTemplate;
    }

    protected void validateOAuth2ClientConfig() {
        ClientConfiguration clientConfigu = getClientConfiguration();

        Assert.notNull(clientConfigu.getClientId(), "clientId cannot be null");
        Assert.isTrue(
                clientConfigu.getScopes() != null && !clientConfigu.getScopes().isEmpty(),
                "At least one scope is required");
        String privateKey = clientConfigu.getPrivateKey();
        Assert.hasText(
                privateKey,
                "privateKey cannot be null (either PEM file path (or) full PEM content must be supplied)");

        if (!ConfigUtil.hasPrivateKeyContentWrapper(privateKey)) {
            // privateKey is a file path, check if the file exists
            Path privateKeyPemFilePath;
            try {
                privateKeyPemFilePath = Paths.get(privateKey);
            } catch (InvalidPathException ipe) {
                throw new IllegalArgumentException("Invalid privateKey file path", ipe);
            }
            boolean privateKeyPemFileExists = Files.exists(privateKeyPemFilePath, LinkOption.NOFOLLOW_LINKS);
            Assert.isTrue(privateKeyPemFileExists, "privateKey file does not exist");
        }
    }

    @Override
    public ApiClient build() {
        ApiClient apiClient = new ApiClient(restTemplate(), cacheManager, getClientConfiguration());
        apiClient.setBasePath(getClientConfiguration().getBaseUrl());

        if (getClientConfiguration().getAuthorizationMode() != AuthorizationMode.PRIVATE_KEY) {
            if (getClientConfiguration().getClientCredentialsResolver() == null
                    && clientCredentials != null) {

                getClientConfiguration().setClientCredentialsResolver(
                        new DefaultClientCredentialsResolver(clientCredentials));
            } else if (getClientConfiguration().getClientCredentialsResolver() == null) {
                getClientConfiguration().setClientCredentialsResolver(
                        new DefaultClientCredentialsResolver(getClientConfiguration()));
            }

            apiClient.setApiKeyPrefix("SSWS");
            apiClient.setApiKey((String) getClientConfiguration().getClientCredentialsResolver().
                    getClientCredentials().getCredentials());
        } else {
            getClientConfiguration().setAuthenticationScheme(AuthenticationScheme.OAUTH2_PRIVATE_KEY);

            validateOAuth2ClientConfig();

            OAuth2ClientCredentials oAuth2ClientCredentials = new OAuth2ClientCredentials(
                    new AccessTokenRetrieverServiceImpl(getClientConfiguration(), apiClient));

            getClientConfiguration().setClientCredentialsResolver(
                    new DefaultClientCredentialsResolver(oAuth2ClientCredentials));
        }

        return apiClient;
    }
}

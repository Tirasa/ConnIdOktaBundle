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
package net.tirasa.connid.bundles.okta.servermock;

import com.fasterxml.jackson.jaxrs.json.JacksonJsonProvider;
import java.util.List;
import java.util.stream.Collectors;
import net.tirasa.connid.bundles.okta.servermock.impl.AbstractApi;
import org.apache.cxf.Bus;
import org.apache.cxf.endpoint.Server;
import org.apache.cxf.ext.logging.LoggingFeature;
import org.apache.cxf.jaxrs.JAXRSServerFactoryBean;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.context.annotation.Bean;

@SpringBootApplication
public class OktaServerMockApplication {

    public static void main(final String[] args) {
        SpringApplication.run(OktaServerMockApplication.class, args);
    }

    @Autowired
    private Bus bus;

    @Bean
    public Server restContainer(final List<AbstractApi> services) {
        JAXRSServerFactoryBean restContainer = new JAXRSServerFactoryBean();
        restContainer.setBus(bus);
        restContainer.setAddress("/");
        restContainer.setServiceBeans(services.stream().map(Object.class::cast).collect(Collectors.toList()));
        restContainer.setProviders(List.of(
                new JacksonJsonProvider(new OktaObjectMapper()),
                new DateParamConverterProvider()));
        restContainer.setFeatures(List.of(new LoggingFeature()));
        return restContainer.create();
    }

    @Bean
    public ContentBootstrap contentBootstrap() {
        return new ContentBootstrap();
    }
}

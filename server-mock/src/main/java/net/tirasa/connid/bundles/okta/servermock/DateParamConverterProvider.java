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

import java.lang.annotation.Annotation;
import java.lang.reflect.Type;
import java.text.ParseException;
import java.util.Date;
import javax.ws.rs.ext.ParamConverter;
import javax.ws.rs.ext.ParamConverterProvider;

public class DateParamConverterProvider implements ParamConverterProvider {

    private static class DateParamConverter implements ParamConverter<Date> {

        @Override
        public Date fromString(final String value) {
            try {
                return OktaObjectMapper.DATE_FORMAT.get().parse(value);
            } catch (ParseException e) {
                throw new IllegalArgumentException("Unparsable date: " + value, e);
            }
        }

        @Override
        public String toString(final Date value) {
            return OktaObjectMapper.DATE_FORMAT.get().format(value);
        }
    }

    @Override
    @SuppressWarnings("unchecked")
    public <T> ParamConverter<T> getConverter(
            final Class<T> rawType, final Type genericType, final Annotation[] annotations) {

        if (Date.class.equals(rawType)) {
            return (ParamConverter<T>) new DateParamConverter();
        }

        return null;
    }
}

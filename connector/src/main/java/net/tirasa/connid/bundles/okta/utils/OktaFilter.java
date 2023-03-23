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

import java.util.Arrays;
import java.util.List;
import org.identityconnectors.framework.common.objects.Name;
import org.identityconnectors.framework.common.objects.Uid;

public class OktaFilter {

    public static final List<String> ID_ATTRS = Arrays.asList(OktaAttribute.ID, Uid.NAME);

    public static final List<String> USER_NAME_ATTRS = Arrays.asList(OktaAttribute.LOGIN, Name.NAME);

    public static final List<String> GROUP_NAME_ATTRS = Arrays.asList(OktaAttribute.NAME, Name.NAME);

    private final OktaFilterOp filterOp;

    private final String attribute;

    private final String value;

    private final boolean quote;

    private final List<OktaFilter> filters;

    public OktaFilter(final OktaFilterOp filterOp,
            final String attribute,
            final String value,
            final boolean quote,
            final List<OktaFilter> filters) {

        this.filterOp = filterOp;
        this.attribute = attribute;
        this.value = value;
        this.quote = quote;
        this.filters = filters;
    }

    public OktaFilterOp getFilterOp() {
        return filterOp;
    }

    public String getAttribute() {
        return attribute;
    }

    public String getValue() {
        return value;
    }

    public boolean isQuote() {
        return quote;
    }

    public List<OktaFilter> getFilters() {
        return filters;
    }

    @Override
    public String toString() {
        final StringBuilder builder = new StringBuilder();
        toString(builder);
        return builder.toString();
    }

    public void toString(final StringBuilder builder) {
        switch (filterOp) {
            case AND:
            case OR:
                for (int i = 0; i < filters.size(); i++) {
                    if (i != 0) {
                        builder.append(' ');
                        builder.append(filterOp);
                        builder.append(' ');
                    }

                    builder.append(filters.get(i));
                }
                break;

            case EQUALS:
            case CONTAINS:
            case STARTS_WITH:
            case GREATER_THAN:
            case GREATER_OR_EQUAL:
            case LESS_THAN:
            case LESS_OR_EQUAL:
                builder.append(attribute);
                builder.append(' ');
                builder.append(filterOp);
                builder.append(' ');

                if (quote) {
                    builder.append("\"");
                    builder.append(escape(value));
                    builder.append("\"");
                } else {
                    builder.append(value);
                }
                break;

            case IS_PRESENT:
                builder.append(attribute);
                builder.append(' ');
                builder.append(filterOp);
                break;

            default:
        }
    }

    private String escape(final String value) {
        return value.replace("\"", "\\\"");
    }
}

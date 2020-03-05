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

import java.util.Arrays;
import java.util.List;
import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import net.tirasa.connid.bundles.okta.utils.OktaFilter;
import net.tirasa.connid.bundles.okta.utils.OktaFilterOp;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeUtil;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.filter.AbstractFilterTranslator;
import org.identityconnectors.framework.common.objects.filter.AttributeFilter;
import org.identityconnectors.framework.common.objects.filter.ContainsFilter;
import org.identityconnectors.framework.common.objects.filter.EndsWithFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsFilter;
import org.identityconnectors.framework.common.objects.filter.EqualsIgnoreCaseFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanFilter;
import org.identityconnectors.framework.common.objects.filter.GreaterThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanFilter;
import org.identityconnectors.framework.common.objects.filter.LessThanOrEqualFilter;
import org.identityconnectors.framework.common.objects.filter.StartsWithFilter;

/**
 * This is an implementation of AbstractFilterTranslator that gives a concrete representation
 * of which filters can be applied at the connector level
 */
public class OktaFilterTranslator extends AbstractFilterTranslator<OktaFilter> {

    private static final Log LOG = Log.getLog(OktaFilterTranslator.class);

    private final ObjectClass objectClass;

    public OktaFilterTranslator(final ObjectClass objectClass) {
        this.objectClass = objectClass;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createAndExpression(final OktaFilter leftExpression, final OktaFilter rightExpression) {
        return createOktaFilter(OktaFilterOp.AND, null, false, Arrays.asList(leftExpression, rightExpression), false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createOrExpression(final OktaFilter leftExpression, final OktaFilter rightExpression) {
        return createOktaFilter(OktaFilterOp.OR, null, false, Arrays.asList(leftExpression, rightExpression), false);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createContainsExpression(final ContainsFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.CONTAINS, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createEndsWithExpression(final EndsWithFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.ENDS_WITH, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createStartsWithExpression(final StartsWithFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.STARTS_WITH, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createGreaterThanExpression(final GreaterThanFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.GREATER_THAN, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createGreaterThanOrEqualExpression(final GreaterThanOrEqualFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.GREATER_OR_EQUAL, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createLessThanExpression(final LessThanFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.LESS_THAN, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createLessThanOrEqualExpression(final LessThanOrEqualFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.LESS_OR_EQUAL, filter, true, null, not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public OktaFilter createEqualsExpression(final EqualsFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.EQUALS, filter, true, null, not);
    }

    @Override
    public OktaFilter createEqualsIgnoreCaseExpression(final EqualsIgnoreCaseFilter filter, final boolean not) {
        return createOktaFilter(OktaFilterOp.EQUALS, filter, true, null, not);
    }

    private OktaFilter createOktaFilter(final OktaFilterOp type, final AttributeFilter filter,
            final boolean quote, final List<OktaFilter> filters, final boolean not) {
        checkIfNot(not);
        return filter == null
                ? new OktaFilter(type, null, null, quote, filters)
                : new OktaFilter(type, getFilterName(filter), getFilterValue(filter), quote, filters);
    }

    private String getFilterName(final AttributeFilter filter) {
        if (ObjectClass.GROUP == objectClass) {
            return OktaAttribute.ID.equals(filter.getName()) || OktaAttribute.NAME.equals(filter.getName()) 
                    ? filter.getName() : "profile." + filter.getName();
        } else {
            return OktaAttribute.ID.equals(filter.getName()) ? filter.getName() : "profile." + filter.getName();
        }
    }

    private String getFilterValue(final AttributeFilter filter) {
        Object attrValue = AttributeUtil.getSingleValue(filter.getAttribute());
        if (attrValue == null) {
            return null;
        }
        return attrValue.toString();
    }

    private void checkIfNot(final boolean not) {
        if (not) {
            LOG.info("Search with not is not supported by Okta");
        }
    }
}

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

import net.tirasa.connid.bundles.okta.utils.OktaAttribute;
import net.tirasa.connid.bundles.okta.utils.OktaUtils;
import org.identityconnectors.common.logging.Log;
import org.identityconnectors.framework.common.objects.AttributeUtil;
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
public class OktaFilterTranslator extends AbstractFilterTranslator<String> {

    private static final Log LOG = Log.getLog(OktaFilterTranslator.class);

    /**
     * {@inheritDoc}
     */
    @Override
    public String createAndExpression(final String leftExpression, final String rightExpression) {
        return createAndOrExpression("and", leftExpression, rightExpression);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createOrExpression(final String leftExpression, final String rightExpression) {
        return createAndOrExpression("or", leftExpression, rightExpression);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createContainsExpression(final ContainsFilter filter, final boolean not) {
        return createNotExpression(filter, "co", not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createEndsWithExpression(final EndsWithFilter filter, final boolean not) {
        return createNotExpression(filter, "ew", not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createStartsWithExpression(final StartsWithFilter filter, final boolean not) {
        return createNotExpression(filter, "sw", not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createGreaterThanExpression(final GreaterThanFilter filter, final boolean not) {
        return createNotExpression(filter, "gt", !not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createGreaterThanOrEqualExpression(final GreaterThanOrEqualFilter filter, final boolean not) {
        return createNotExpression(filter, "ge", not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createLessThanExpression(final LessThanFilter filter, final boolean not) {
        return createNotExpression(filter, "lt", !not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createLessThanOrEqualExpression(final LessThanOrEqualFilter filter, final boolean not) {
        return createNotExpression(filter, "le", not);
    }

    /**
     * {@inheritDoc}
     */
    @Override
    public String createEqualsExpression(final EqualsFilter filter, final boolean not) {
        return createNotExpression(filter, "eq", not);
    }

    @Override
    protected String createEqualsIgnoreCaseExpression(EqualsIgnoreCaseFilter filter, boolean not) {
        return createNotExpression(filter, "eq", not);
    }

    private String createNotExpression(final AttributeFilter filter, final String operator, final boolean not) {
        String expression = createExpression(filter, operator);
        if (not) {
            LOG.info("Search with not is not supported by Okta");
            return null;
        }
        return expression;
    }

    private static String createAndOrExpression(final String operator, final String... operands) {
        StringBuilder sb = new StringBuilder();
        boolean addOp = false;
        for (String s : operands) {
            if (addOp) {
                sb.append(" ");
                sb.append(operator);
                sb.append(" ");
            }
            addOp = true;
            sb.append(s);
            
        }
        return sb.toString();
    }

    private String createExpression(final AttributeFilter filter, final String operator) {
        LOG.ok("filter {0} ({1}) = {2}", filter.getName(), 
                filter.getAttribute().getName(), filter.getAttribute().getValue());
        StringBuilder sb = new StringBuilder();

        String attrName = OktaAttribute.ID.equals(filter.getName()) ? filter.getName() : "profile." + filter.getName();
        Object attrValue = AttributeUtil.getSingleValue(filter.getAttribute());
        if (attrValue == null) {
            OktaUtils.handleGeneralError("Illegal search filter");
        }
        createCondition(sb, attrName, operator, attrValue.toString());
        return sb.toString();
    }

    private static void createCondition(
            final StringBuilder sb,
            final String name,
            final String operator,
            final Object value) {
        sb.append(name);
        sb.append(" ");
        sb.append(operator);
        sb.append(" \"");
        sb.append(value);
        sb.append("\"");
    }
}

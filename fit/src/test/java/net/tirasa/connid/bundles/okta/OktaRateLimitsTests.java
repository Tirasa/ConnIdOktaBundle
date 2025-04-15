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

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.fail;

import java.util.stream.IntStream;
import org.identityconnectors.framework.common.objects.ObjectClass;
import org.identityconnectors.framework.common.objects.OperationOptionsBuilder;
import org.identityconnectors.framework.common.objects.SearchResult;
import org.identityconnectors.test.common.ToListResultsHandler;
import org.junit.jupiter.api.Test;

public class OktaRateLimitsTests extends AbstractConnectorTests {

    @Test
    public void checkRateLimits() {
        IntStream range = IntStream.rangeClosed(1, 1000);
        try {
            range.parallel().forEach(item -> exec());
            fail();
        } catch (Exception ex) {
        }
    }

    private void exec() {
        ToListResultsHandler handler = new ToListResultsHandler();
        SearchResult result = FACADE.search(
                ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().build());
        assertNotNull(result);

        result = FACADE.search(
                ObjectClass.ACCOUNT, null, handler, new OperationOptionsBuilder().setPageSize(1).build());
        assertNotNull(result);
    }
}

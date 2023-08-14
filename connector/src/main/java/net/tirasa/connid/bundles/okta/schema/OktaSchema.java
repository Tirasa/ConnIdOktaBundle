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
package net.tirasa.connid.bundles.okta.schema;

import com.okta.sdk.resource.api.SchemaApi;
import org.identityconnectors.framework.common.objects.Schema;

public class OktaSchema {

    private final SchemaApi schemaApi;

    private Schema schema;

    public OktaSchema(final SchemaApi schemaApi) {
        this.schemaApi = schemaApi;
    }

    public Schema getSchema() {
        if (schema == null) {
            schema = new OktaSchemaBuilder(schemaApi).getSchema();
        }

        return schema;
    }
}

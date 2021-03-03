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
package com.gfs.ebz.syncope.oauth2;

import javax.ws.rs.GET;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.springframework.stereotype.Service;

@Service
@Path("/oauth2")
public class Keys {

    @GET
    @Produces(MediaType.WILDCARD)
    @Path("/default/v1/keys")
    public Response keys() {
        return Response.ok(
                "{\"keys\":["
                + "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"o9WXHDXbbSUJBbx2yinfTOryGDhG0J8c8zaLsq4BFFM\","
                + "\"use\":\"sig\",\"e\":\"AQAB\",\"n\":\"pM7-ExI6-mQrWTaj12i6vnjnzpDOWWN2AIePiWzAHi_dI9Xf6cNJllU7dSs"
                + "37z1aGoLZzIFG2K4eIAjCN-vbwxO52RmHZCy6hG9StirR5VuKhRijqvTv6lV10H2W6EsmSqSpJfbvAxqOwbt982aXTWZVUm0Dob"
                + "KryXmfAmnLw-RCTDc0FAKP7ElK_zS-VaKRa-00lx6NyT_FjZ5zMnImbsgtz-1coHy_iWvrvzUVuVOkGVqlJv6w79i9Q66o5WCpA"
                + "J-YhfvluQh2_VynbQFwfuoXwq3ybKU_N8Fs38QeJWFic30O2mxGEV0GuA3n_px1oYVlhtAt8gV5P-mRDwqCvw\"},"
                + "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"_jLrgTdERG9o9UagOmJv948vBcZEClrcjXmWnSCNxOg\","
                + "\"use\":\"sig\",\"e\":\"AQAB\",\"n\":\"g_2p_sjRbvsrDbaG3K07vYw6VI8FwXoQToqvSKHIAfZ1DOld58r-H_RU2K9I"
                + "Y3QBmtewlt2Gh6n9F34M9PF36bumsW27nVBIHgQyTb051-sJ13Q3GNvIb2aJVPx8wZXXbh8-4bbaRYWwgHc3hAxZQP8pNOj_5ze"
                + "HWKlfg0co6gKLItsZYQbi1hXAFOUogjJR5mXiODTd5TA56jzGaxPTigv1WT-Af5842LrWKgqZD30xRue-0ElNxxL7_sy7R4xleMF"
                + "A9nwKaE21e7la7y25L9Dp0tlF0M7mcKodCdczVww_aYlPs-9QI2wYFedbOKyAD_nMxKArSyUGPux1ObFlhw\"}"
                + "]}",
                MediaType.APPLICATION_JSON_TYPE).
                build();
    }
}

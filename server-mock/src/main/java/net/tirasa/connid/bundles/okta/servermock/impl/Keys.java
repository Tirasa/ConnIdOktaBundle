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
package net.tirasa.connid.bundles.okta.servermock.impl;

import java.io.IOException;
import java.io.InputStream;
import java.util.concurrent.atomic.AtomicReference;
import javax.ws.rs.Consumes;
import javax.ws.rs.GET;
import javax.ws.rs.POST;
import javax.ws.rs.Path;
import javax.ws.rs.Produces;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import org.apache.cxf.helpers.IOUtils;
import org.springframework.stereotype.Service;

@Service
@Path("/oauth2/default/v1/keys")
public class Keys {

    private static final AtomicReference<String> KEYS = new AtomicReference<>(
            "{\"keys\":["
            + "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"eBfITsAcpZWNbBzV_UWqBj1Xae7m9KB7VZS-QjPRW08\","
            + "\"use\":\"sig\",\"e\":\"AQAB\",\"n\":\"jbbqR3PkMHM2MToR1IvL_uTdM0gUugOlk8yFkuP7IJKzUbx2ZoJvt1Q4pcuj"
            + "uux1bCkbEkhhY75oL3zUHRZTX6yF4wG3IXGLz0870ntwFbMxifaSGFYREOgRZSgqBFh6PY4VFc7fe1y7CSx281MMZU-yDmtOVTU"
            + "Nwlbb-WlmmKbpKHu1LrhkA7mNN02itypt7DJc2j10gCEp1DyK1rvWj0mQopp0fUirQ81iYzXuXe_d8baxE2nCrIkZPsx8apaUZ0h"
            + "lN54lk4lGPIPM3il0P8i2QXUShW-llL9XkO3vMElcN5C01N574m60h7_eu-jZyGS4pbcF0xduQhFLztF8wQ\"},"
            + "{\"kty\":\"RSA\",\"alg\":\"RS256\",\"kid\":\"z0xT1Ne9MqDimuEvnWJO8leK0xoK6gZC1ZakaLGOZic\","
            + "\"use\":\"sig\",\"e\":\"AQAB\",\"n\":\"hDJxXzyxYIjIAZh8-f-PJ_fONMfZC-0aitdql3AX_PIc4ZpGNn6AlN2CTOzPx"
            + "uasxNxRH3VzxTpPOh_AU53Uj895QDkyQHz_4Z-UOvKHsO9ChcCUsQ56k4dGDV_wP2eVn1-hFfYR4tiAFNvIMICB8DJrJpzWoHr2K"
            + "2ZlTON9vi5bKkb2GL6zM37IGWG2rsMIkyPeCb4pl94DojUunCkcgPyUD5s59lN_GhJ8VVLtgl5ddnKEfyG502g360JJNcuLHix5F"
            + "Z3_5XRM47uVwoOdEW9DxzluZZI63cybeQkJrpBsxEvISfkytq7gckG_uFXWxkEIQiDHzabpmw6oQaxl1w\"}"
            + "]}");

    @GET
    @Produces(MediaType.WILDCARD)
    public Response keys() {
        return Response.ok(
                KEYS.get(),
                MediaType.APPLICATION_JSON_TYPE).
                build();
    }

    @POST
    @Consumes(MediaType.APPLICATION_JSON)
    public void set(final InputStream in) throws IOException {
        KEYS.set(IOUtils.readStringFromStream(in));
    }
}

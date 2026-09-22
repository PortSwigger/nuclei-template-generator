/*
 * MIT License
 *
 * Copyright (c) 2021 ProjectDiscovery, Inc.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 *
 */

package io.projectdiscovery.cve.nist.service;

import io.projectdiscovery.cve.CveInfo;
import io.projectdiscovery.nuclei.gui.GeneralSettings;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

import java.io.IOException;
import java.io.InputStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.function.Function;

class CveInfoRetrieverTest {

    private static final String CVE_ID = "CVE-2021-44228";

    @Test
    void testCachedResponseIsUsedWhenTheNvdIsUnreachable() {
        final Map<String, String> storedSettings = new HashMap<>();

        // First lookup succeeds and should populate the cache.
        final Optional<CveInfo> live = CveInfoRetriever.getCveInfo(CVE_ID, settings(storedSettings, uri -> Optional.of(nvdResponse())));
        Assertions.assertTrue(live.isPresent());
        Assertions.assertEquals(CVE_ID, live.get().getId());

        // Second lookup fails, so the cached copy should be served instead.
        final Optional<CveInfo> cached = CveInfoRetriever.getCveInfo(CVE_ID, settings(storedSettings, uri -> Optional.empty()));
        Assertions.assertTrue(cached.isPresent(), "expected the cached response to be used");
        Assertions.assertEquals(CVE_ID, cached.get().getId());
        Assertions.assertEquals(live.get().getSeverity(), cached.get().getSeverity());
        Assertions.assertEquals(live.get().getCvssScore(), cached.get().getCvssScore());
        Assertions.assertEquals(live.get().getCweIds(), cached.get().getCweIds());
        Assertions.assertEquals(live.get().getReferences(), cached.get().getReferences());
    }

    @Test
    void testLookupFailsWithoutACachedResponse() {
        final Optional<CveInfo> result = CveInfoRetriever.getCveInfo(CVE_ID, settings(new HashMap<>(), uri -> Optional.empty()));
        Assertions.assertTrue(result.isEmpty());
    }

    @Test
    void testLowerCaseIdIsUpperCasedBeforeTheRequest() {
        final Map<String, URI> requested = new HashMap<>();
        CveInfoRetriever.getCveInfo("cve-2021-44228", settings(new HashMap<>(), uri -> {
            requested.put("uri", uri);
            return Optional.of(nvdResponse());
        }));

        Assertions.assertTrue(requested.get("uri").toString().contains(CVE_ID), "the id should be upper cased: " + requested.get("uri"));
    }

    private static GeneralSettings settings(Map<String, String> store, Function<URI, Optional<String>> httpGetter) {
        return new GeneralSettings.Builder()
                .withOutputConsumer(message -> {
                })
                .withErrorConsumer(message -> {
                })
                .withExtensionSettingSaver(store::put)
                .withExtensionSettingLoader(store::get)
                .withHttpGetter(httpGetter)
                .build();
    }

    private static String nvdResponse() {
        try (final InputStream inputStream = CveInfoRetrieverTest.class.getResourceAsStream("/nvd/cve-2021-44228.json")) {
            return new String(inputStream.readAllBytes(), StandardCharsets.UTF_8);
        } catch (IOException e) {
            throw new AssertionError("Could not read the NVD fixture", e);
        }
    }
}

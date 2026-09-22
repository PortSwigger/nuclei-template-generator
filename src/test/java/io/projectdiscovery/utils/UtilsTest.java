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

package io.projectdiscovery.utils;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

class UtilsTest {

    @Test
    void testStripYamlDelimiters() {
        Assertions.assertEquals("https://example.com/a", Utils.stripYamlDelimiters("\"https://example.com/a\""));
        Assertions.assertEquals("https://example.com/a", Utils.stripYamlDelimiters("https://example.com/a,"));
        Assertions.assertEquals("https://example.com/a", Utils.stripYamlDelimiters("[https://example.com/a]"));
        Assertions.assertEquals("https://example.com/a", Utils.stripYamlDelimiters("https://example.com/a#"));
        Assertions.assertEquals("https://example.com/a", Utils.stripYamlDelimiters("https://example.com/a"));
    }

    @Test
    void testLocalAddressesAreDetected() {
        Assertions.assertTrue(Utils.isLocalAddress("localhost"));
        Assertions.assertTrue(Utils.isLocalAddress("LOCALHOST"));
        Assertions.assertTrue(Utils.isLocalAddress("127.0.0.1"));
        Assertions.assertTrue(Utils.isLocalAddress("127.1.2.3"));
        Assertions.assertTrue(Utils.isLocalAddress("10.0.0.5"));
        Assertions.assertTrue(Utils.isLocalAddress("192.168.1.1"));
        Assertions.assertTrue(Utils.isLocalAddress("172.16.0.1"));
        Assertions.assertTrue(Utils.isLocalAddress("169.254.1.1"));
        Assertions.assertTrue(Utils.isLocalAddress("0.0.0.0"));
        Assertions.assertTrue(Utils.isLocalAddress("[::1]"));
        Assertions.assertTrue(Utils.isLocalAddress(""));
        Assertions.assertTrue(Utils.isLocalAddress(null));
    }

    @Test
    void testRemoteAddressesAreAllowed() {
        Assertions.assertFalse(Utils.isLocalAddress("example.com"));
        Assertions.assertFalse(Utils.isLocalAddress("8.8.8.8"));
        Assertions.assertFalse(Utils.isLocalAddress("nuclei.projectdiscovery.io"));
        Assertions.assertFalse(Utils.isLocalAddress("172.32.0.1"));
    }
}

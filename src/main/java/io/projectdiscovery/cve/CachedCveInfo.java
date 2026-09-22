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

package io.projectdiscovery.cve;

import java.util.Set;

/**
 * A plain snapshot of {@link CveInfo}, so a successful lookup can be cached and
 * served again when the NVD is unreachable or rate limiting.
 */
public class CachedCveInfo implements CveInfo {

    private String id;
    private String description;
    private String severity;
    private Double cvssScore;
    private String cvssMetrics;
    private Set<String> references;
    private Set<String> cweIds;

    public static CachedCveInfo from(CveInfo source) {
        final CachedCveInfo cached = new CachedCveInfo();
        cached.id = source.getId();
        cached.description = source.getDescription();
        cached.severity = source.getSeverity();
        cached.cvssScore = source.getCvssScore();
        cached.cvssMetrics = source.getCvssMetrics();
        cached.references = source.getReferences();
        cached.cweIds = source.getCweIds();
        return cached;
    }

    @Override
    public String getId() {
        return this.id;
    }

    @Override
    public String getDescription() {
        return this.description;
    }

    @Override
    public String getSeverity() {
        return this.severity;
    }

    @Override
    public Double getCvssScore() {
        return this.cvssScore;
    }

    @Override
    public String getCvssMetrics() {
        return this.cvssMetrics;
    }

    @Override
    public Set<String> getReferences() {
        return this.references == null ? Set.of() : this.references;
    }

    @Override
    public Set<String> getCweIds() {
        return this.cweIds == null ? Set.of() : this.cweIds;
    }
}

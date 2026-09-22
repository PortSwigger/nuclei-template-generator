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

package io.projectdiscovery.nuclei.util;

import com.google.gson.Gson;
import com.google.gson.reflect.TypeToken;
import io.projectdiscovery.nuclei.gui.GeneralSettings;
import io.projectdiscovery.utils.Utils;

import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.lang.reflect.Type;
import java.net.MalformedURLException;
import java.net.URL;
import java.net.URLConnection;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.*;
import java.util.function.Consumer;
import java.util.stream.Collectors;
import java.util.stream.Stream;

public final class SchemaUtils {

    private SchemaUtils() {
    }

    private static final String NUCLEI_JSON_SCHEMA_FILE_NAME = "nuclei-jsonschema.json";
    // Bounded, because this runs while Burp is loading the extension.
    private static final int SCHEMA_TIMEOUT_MILLIS = 10_000;
    private static final String NUCLEI_JSON_SCHEMA_URL = "https://raw.githubusercontent.com/projectdiscovery/nuclei/master/" + NUCLEI_JSON_SCHEMA_FILE_NAME;

    public static Map<String, String> retrieveYamlFieldWithDescriptions(GeneralSettings generalSettings) {
        Map<String, String> result = Collections.emptyMap();

        try {
            final URL jsonSchemaUrl = new URL(NUCLEI_JSON_SCHEMA_URL);
            final URLConnection connection = jsonSchemaUrl.openConnection();
            connection.setConnectTimeout(SCHEMA_TIMEOUT_MILLIS);
            connection.setReadTimeout(SCHEMA_TIMEOUT_MILLIS);

            try (final InputStream inputStream = connection.getInputStream()) {
                result = yamlFieldDescriptionTransformer(inputStream, generalSettings);
            } catch (IOException e) {
                result = retrieveYamlFieldWithDescriptionsFromDisk(generalSettings, e);
            }
        } catch (MalformedURLException e) {
            generalSettings.logError("Malformed URL: " + NUCLEI_JSON_SCHEMA_URL, e);
        } catch (IOException e) {
            result = retrieveYamlFieldWithDescriptionsFromDisk(generalSettings, e);
        }

        if (result.isEmpty()) {
            result = retrieveBundledYamlFieldWithDescriptions(generalSettings);
        }

        return result;
    }

    private static Map<String, String> retrieveYamlFieldWithDescriptionsFromDisk(GeneralSettings generalSettings, IOException e) {
        Map<String, String> result = Collections.emptyMap();

        final List<Path> jsonSchemaPaths = Stream.of(NucleiUtils.getNucleiConfigPath(),
                                                     generalSettings.getTemplatePath(),
                                                     Utils.getTempPath())
                                                 .filter(Objects::nonNull)
                                                 .map(path -> path.resolve(NUCLEI_JSON_SCHEMA_FILE_NAME))
                                                 .collect(Collectors.toList());

        generalSettings.logError(String.format("Could not download the latest nuclei schema from '%s'.\n" +
                                               "Try reloading the plugin or manually saving the file to one of the following locations: %s",
                                               NUCLEI_JSON_SCHEMA_URL,
                                               jsonSchemaPaths.stream().map(path -> String.format("'%s'", path.toString())).collect(Collectors.joining(", "))), e);

        for (Path jsonSchemaPath : jsonSchemaPaths) {
            generalSettings.log(String.format("Trying to access alternate nuclei JSON schema from: '%s'", jsonSchemaPath));
            if (Files.exists(jsonSchemaPath)) {
                try (final InputStream inputStream = Files.newInputStream(jsonSchemaPath)) {
                    final Map<String, String> yamlFieldDescriptorMap = yamlFieldDescriptionTransformer(inputStream, generalSettings);
                    if (!yamlFieldDescriptorMap.isEmpty()) {
                        result = yamlFieldDescriptorMap;
                        break;
                    }
                } catch (IOException e1) {
                    generalSettings.logError(String.format("Could not read nuclei JSON schema from: '%s'", jsonSchemaPath), e1);
                }
            }
        }

        return result;
    }

    private static Map<String, String> yamlFieldDescriptionTransformer(InputStream inputStream, GeneralSettings generalSettings) {
        Map<String, String> result = Collections.emptyMap();
        try (final InputStreamReader inputStreamReader = new InputStreamReader(inputStream, StandardCharsets.UTF_8)) {
            result = retrieveYamlFieldWithDescriptions(inputStreamReader);
        } catch (IOException e) {
            generalSettings.logError("Could not read data from the provided input stream", e);
        }
        return result;
    }

    @SuppressWarnings({"unchecked", "rawtypes"})
    // TODO find a more elegant way
    private static Map<String, String> retrieveYamlFieldWithDescriptions(InputStreamReader inputStreamReader) {
        final Map<String, String> result = new TreeMap<>();
        final Gson gson = new Gson();

        final Type type = new TypeToken<Map<String, Object>>() {
        }.getType();

        final Map<String, Object> parsedJsonSchema = gson.fromJson(inputStreamReader, type);

        final Map<String, Object> definitions = (Map<String, Object>) parsedJsonSchema.get("$defs");
        for (Map.Entry<String, Object> definitionEntry : definitions.entrySet()) {
            final Map<String, Map> properties = ((Map<String, Map>) definitionEntry.getValue()).get("properties");

            if (properties != null) {
                for (Map.Entry<String, Map> field : properties.entrySet()) {
                    result.put(field.getKey(), (String) field.getValue().get("description"));
                }
            } else {
                final Map<String, Object> enumFieldMap = ((Map<String, Object>) definitionEntry.getValue());
                final Collection<String> enums = (Collection<String>) enumFieldMap.get("enum");

                if (enums != null) {
                    for (String enumValue : enums) {
                        result.put(enumValue, (String) enumFieldMap.get("description"));
                    }
                } else {
                    System.err.printf("[DEBUG] Ignoring unknown JSON schema attribute type: '%s'%n", enumFieldMap);
                }
            }
        }
        return result;
    }

    /**
     * Last resort, so autocomplete still works on a first install with no network access.
     * The bundled copy is only as current as the release.
     */
    private static Map<String, String> retrieveBundledYamlFieldWithDescriptions(GeneralSettings generalSettings) {
        try (final InputStream inputStream = SchemaUtils.class.getResourceAsStream("/" + NUCLEI_JSON_SCHEMA_FILE_NAME)) {
            if (inputStream == null) {
                generalSettings.logError("The bundled nuclei JSON schema is missing from the extension.");
                return Collections.emptyMap();
            }

            generalSettings.log("Falling back to the nuclei JSON schema bundled with the extension.");
            return yamlFieldDescriptionTransformer(inputStream, generalSettings);
        } catch (IOException e) {
            generalSettings.logError("Could not read the bundled nuclei JSON schema", e);
            return Collections.emptyMap();
        }
    }
}

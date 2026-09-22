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

package io.projectdiscovery.burp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.HttpService;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.persistence.Preferences;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.InvocationType;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import io.projectdiscovery.nuclei.gui.*;
import io.projectdiscovery.nuclei.gui.settings.SettingsPanel;
import io.projectdiscovery.nuclei.model.*;
import io.projectdiscovery.nuclei.model.util.TransformedRequest;
import io.projectdiscovery.nuclei.util.SchemaUtils;
import io.projectdiscovery.nuclei.util.TemplateUtils;
import io.projectdiscovery.nuclei.yaml.YamlUtil;
import io.projectdiscovery.utils.CommandLineUtils;
import io.projectdiscovery.utils.Utils;
import io.projectdiscovery.utils.gui.SwingUtils;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.*;
import java.util.function.Consumer;
import java.util.function.Supplier;
import java.util.stream.Collectors;
import java.util.stream.IntStream;

public class NucleiExtension implements BurpExtension {

    private static final String EXTENSION_NAME = "Nuclei";
    private static final String GENERATE_CONTEXT_MENU_TEXT = "Generate template";
    private static final String GENERATOR_TAB_NAME = "Generator";
    private static final String CONFIGURATION_TAB_NAME = "Configuration";

    private static final int HTTP_DEFAULT_PORT = 80;
    private static final int HTTPS_DEFAULT_PORT = 443;

    private static MontoyaApi montoyaApi;
    private Map<String, String> yamlFieldDescriptionMap = new HashMap<>();
    private JTabbedPane nucleiTabbedPane;

    @Override
    public void initialize(MontoyaApi api) {
        montoyaApi = api;
        api.extension().setName(EXTENSION_NAME);

        final Preferences preferences = api.persistence().preferences();
        final GeneralSettings generalSettings = new GeneralSettings.Builder()
                .withOutputConsumer(api.logging()::logToOutput)
                .withErrorConsumer(api.logging()::logToError)
                .withExtensionSettingSaver(preferences::setString)
                .withExtensionSettingLoader(preferences::getString)
                .withHttpGetter(uri -> sendThroughBurp(api, uri))
                .build();

        try {
            api.userInterface().registerSuiteTab(EXTENSION_NAME, createConfigurationTab(generalSettings));

            initializeNucleiYamlSchema(generalSettings);

            api.userInterface().registerContextMenuItemsProvider(createContextMenuItemsProvider(generalSettings));

            // Without this the background threads outlive the extension and accumulate
            // every time it is reloaded.
            api.extension().registerUnloadingHandler(() -> {
                CommandLineUtils.shutdown();
                TemplateGeneratorTabbedPane.shutdown();
                montoyaApi = null;
                generalSettings.log("Nuclei extension unloaded.");
            });
        } catch (Throwable e) {
            JOptionPane.showMessageDialog(suiteFrame(), "There was an error while trying to initialize the plugin. Please check the logs.", "An error occurred", JOptionPane.ERROR_MESSAGE);
            generalSettings.logError("Error while trying to initialize the plugin", e);
        }
    }

    private void initializeNucleiYamlSchema(GeneralSettings generalSettings) {
        this.yamlFieldDescriptionMap = SchemaUtils.retrieveYamlFieldWithDescriptions(generalSettings);
        if (this.yamlFieldDescriptionMap.isEmpty()) {
            generalSettings.logError("AutoCompletion will be disabled, because there was an error while downloading, accessing or parsing the nuclei JSON schema.");
        } else {
            generalSettings.log("JSON schema loaded and parsed!");
        }
    }

    private Component createConfigurationTab(GeneralSettings generalSettings) {
        final JTabbedPane tabbedPane = new JTabbedPane();
        tabbedPane.addTab(CONFIGURATION_TAB_NAME, new SettingsPanel(generalSettings));

        this.nucleiTabbedPane = tabbedPane;
        return tabbedPane;
    }

    private ContextMenuItemsProvider createContextMenuItemsProvider(GeneralSettings generalSettings) {
        // Not a functional interface: every ContextMenuItemsProvider method has a default implementation.
        return new ContextMenuItemsProvider() {
            @Override
            public List<Component> provideMenuItems(ContextMenuEvent event) {
                return NucleiExtension.this.createMenuItems(generalSettings, event);
            }
        };
    }

    private List<Component> createMenuItems(GeneralSettings generalSettings, ContextMenuEvent event) {
        final Optional<HttpRequestResponse> selectedRequestResponse = getPrimaryRequestResponse(event);
        if (selectedRequestResponse.isEmpty()) {
            return Collections.emptyList();
        }

        final HttpRequestResponse requestResponse = selectedRequestResponse.get();

        final URL targetUrl;
        try {
            targetUrl = getBaseUrl(requestResponse);
        } catch (MalformedURLException e) {
            generalSettings.logError(e.getMessage());
            return Collections.emptyList();
        }

        final int[] selectionBounds = getSelectionBounds(event);
        final List<JMenuItem> menuItems;

        switch (event.invocationType()) {
            case MESSAGE_EDITOR_REQUEST:
            case MESSAGE_VIEWER_REQUEST: {
                menuItems = createMenuItemsFromHttpRequest(generalSettings, targetUrl, () -> requestResponse.request().toString(), selectionBounds);
                break;
            }
            case MESSAGE_EDITOR_RESPONSE:
            case MESSAGE_VIEWER_RESPONSE: {
                menuItems = createMenuItemsFromHttpResponse(generalSettings, targetUrl, requestResponse, selectionBounds);
                break;
            }
            case INTRUDER_PAYLOAD_POSITIONS: {
                menuItems = generateIntruderTemplate(generalSettings, targetUrl, requestResponse.request().toString());
                break;
            }
            case PROXY_HISTORY: {
                menuItems = createMenuItemsFromProxyHistory(generalSettings, targetUrl, event.selectedRequestResponses());
                break;
            }
            default: {
                menuItems = Collections.emptyList();
            }
        }

        return new ArrayList<>(menuItems);
    }

    /**
     * Message editor and viewer contexts carry a single message, whereas table based contexts such as
     * the proxy history carry a selection, so both have to be consulted.
     */
    private static Optional<HttpRequestResponse> getPrimaryRequestResponse(ContextMenuEvent event) {
        return event.messageEditorRequestResponse()
                    .map(MessageEditorHttpRequestResponse::requestResponse)
                    .or(() -> event.selectedRequestResponses().stream().findFirst());
    }

    private static int[] getSelectionBounds(ContextMenuEvent event) {
        return event.messageEditorRequestResponse()
                    .flatMap(MessageEditorHttpRequestResponse::selectionOffsets)
                    .map(range -> new int[]{range.startIndexInclusive(), range.endIndexExclusive()})
                    .orElse(new int[]{0, 0});
    }

    private static URL getBaseUrl(HttpRequestResponse requestResponse) throws MalformedURLException {
        final HttpService httpService = requestResponse.httpService();
        if (httpService == null) {
            throw new MalformedURLException("The selected message has no associated HTTP service.");
        }

        final boolean secure = httpService.secure();
        final int port = httpService.port();
        // Leave the default port out, so the generated target stays the short form
        final int urlPort = (secure && port == HTTPS_DEFAULT_PORT) || (!secure && port == HTTP_DEFAULT_PORT) ? -1 : port;

        return new URL(secure ? "https" : "http", httpService.host(), urlPort, "/");
    }

    private List<JMenuItem> createMenuItemsFromHttpRequest(GeneralSettings generalSettings, URL targetUrl, Supplier<String> request, int[] selectionBounds) {
        final JMenuItem generateTemplateContextMenuItem = createTemplateWithHttpRequestContextMenuItem(generalSettings, request, targetUrl);
        final JMenuItem generateIntruderTemplateMenuItem = createIntruderTemplateMenuItem(generalSettings, targetUrl, request, selectionBounds);

        final List<JMenuItem> menuItems = new ArrayList<>();
        menuItems.add(generateTemplateContextMenuItem);
        if (generateIntruderTemplateMenuItem != null) {
            menuItems.add(generateIntruderTemplateMenuItem);
        }

        final Set<JMenuItem> addToTabMenuItems = createAddRequestToTabContextMenuItems(generalSettings, () -> new String[]{request.get()});
        if (!addToTabMenuItems.isEmpty()) {
            final JMenu addRequestToTabMenu = new JMenu("Add request to");
            addToTabMenuItems.forEach(addRequestToTabMenu::add);
            menuItems.add(addRequestToTabMenu);
        }

        return menuItems;
    }

    private List<JMenuItem> createMenuItemsFromHttpResponse(GeneralSettings generalSettings, URL targetUrl, HttpRequestResponse requestResponse, int[] selectionBounds) {
        if (!requestResponse.hasResponse()) {
            return Collections.emptyList();
        }

        // Parsing the response body and serialising the request are deferred to the action,
        // so right clicking a large response does not stall the menu.
        final Supplier<TemplateMatcher> contentMatcher = () -> {
            final HttpResponse response = requestResponse.response();
            return TemplateUtils.createContentMatcher(response.toByteArray().getBytes(), response.bodyOffset(), selectionBounds, NucleiExtension::bytesToString);
        };

        final JMenuItem generateTemplateContextMenuItem = createContextMenuItem(() -> generateTemplate(generalSettings, contentMatcher.get(), targetUrl, requestResponse), GENERATE_CONTEXT_MENU_TEXT);

        final List<JMenuItem> menuItems;
        final Supplier<String[]> request = () -> new String[]{requestResponse.request().toString()};
        final Set<JMenuItem> addToTabMenuItems = createAddMatcherToTabContextMenuItems(generalSettings, contentMatcher, request);
        if (addToTabMenuItems.isEmpty()) {
            menuItems = List.of(generateTemplateContextMenuItem);
        } else {
            final JMenu addMatcherToTabMenu = new JMenu("Add matcher to");
            addToTabMenuItems.forEach(addMatcherToTabMenu::add);
            menuItems = Arrays.asList(generateTemplateContextMenuItem, addMatcherToTabMenu);
        }

        return menuItems;
    }

    private List<JMenuItem> createMenuItemsFromProxyHistory(GeneralSettings generalSettings, URL targetUrl, List<HttpRequestResponse> selectedRequestResponses) {
        // A bulk selection can be large, so serialising it is deferred to the action.
        final Supplier<String[]> requests = () -> selectedRequestResponses.stream()
                                                                          .map(requestResponse -> requestResponse.request().toString())
                                                                          .toArray(String[]::new);

        final List<JMenuItem> menuItems = new ArrayList<>(List.of(createContextMenuItem(() -> {
            final Http templateRequests = new Http();
            templateRequests.setRaw(requests.get());
            generateTemplate(generalSettings, targetUrl, templateRequests);
        }, GENERATE_CONTEXT_MENU_TEXT)));

        final Set<JMenuItem> addToTabMenuItems = createAddRequestToTabContextMenuItems(generalSettings, requests);
        if (!addToTabMenuItems.isEmpty()) {
            final JMenu addRequestToTabMenu = new JMenu("Add request to");
            addToTabMenuItems.forEach(addRequestToTabMenu::add);
            menuItems.add(addRequestToTabMenu);
        }

        return menuItems;
    }

    private static Set<JMenuItem> createAddRequestToTabContextMenuItems(GeneralSettings generalSettings, Supplier<String[]> requests) {
        return createAddToTabContextMenuItems(generalSettings, template -> {
            final String[] rawRequests = requests.get();
            final Consumer<Http> firstRequestConsumer = firstRequest -> firstRequest.addRaw(rawRequests);
            createContextMenuActionHandlingMultiRequests(template, rawRequests, firstRequestConsumer, "request");
        });
    }

    private static Optional<Map.Entry<String, Component>> getTabComponentByName(JTabbedPane tabbedPane, String generatorTabName) {
        return IntStream.range(0, tabbedPane.getTabCount())
                        .mapToObj(i -> Map.entry(tabbedPane.getTitleAt(i), tabbedPane.getComponentAt(i)))
                        .filter(entry -> entry.getKey().equals(generatorTabName))
                        .findFirst();
    }

    private JMenuItem createTemplateWithHttpRequestContextMenuItem(GeneralSettings generalSettings, Supplier<String> request, URL targetUrl) {
        return createContextMenuItem(() -> {
            final Http requests = new Http();
            requests.setRaw(request.get());
            generateTemplate(generalSettings, targetUrl, requests);
        }, GENERATE_CONTEXT_MENU_TEXT);
    }

    private JMenuItem createIntruderTemplateMenuItem(GeneralSettings generalSettings, URL targetUrl, Supplier<String> request, int[] selectionBounds) {
        final JMenuItem generateIntruderTemplateMenuItem;
        final int startSelectionIndex = selectionBounds[0];
        final int endSelectionIndex = selectionBounds[1];
        if (endSelectionIndex - startSelectionIndex > 0) {
            generateIntruderTemplateMenuItem = createContextMenuItem(() -> {
                final StringBuilder requestModifier = new StringBuilder(request.get());
                requestModifier.insert(startSelectionIndex, TemplateUtils.INTRUDER_PAYLOAD_MARKER);
                requestModifier.insert(endSelectionIndex + 1, TemplateUtils.INTRUDER_PAYLOAD_MARKER);

                generateIntruderTemplate(generalSettings, targetUrl, requestModifier.toString(), Http.AttackType.batteringram);
            }, GENERATE_CONTEXT_MENU_TEXT + " with payload");
        } else {
            generateIntruderTemplateMenuItem = null;
        }
        return generateIntruderTemplateMenuItem;
    }

    private static Set<JMenuItem> createAddMatcherToTabContextMenuItems(GeneralSettings generalSettings, Supplier<TemplateMatcher> contentMatcher, Supplier<String[]> httpRequest) {
        return createAddToTabContextMenuItems(generalSettings, template -> {
            final TemplateMatcher matcher = contentMatcher.get();
            final Consumer<Http> firstRequestConsumer = firstRequest -> {
                final List<TemplateMatcher> matchers = firstRequest.getMatchers();
                firstRequest.setMatchers(Utils.createNewList(matchers, matcher));
            };
            createContextMenuActionHandlingMultiRequests(template, httpRequest.get(), firstRequestConsumer, "matcher");
        });
    }

    private static void createContextMenuActionHandlingMultiRequests(Template template, String[] httpRequests, Consumer<Http> firstTemplateRequestConsumer, String errorMessageContext) {
        final List<Http> requests = template.getHttp();

        final int requestSize = requests.size();
        if (requestSize == 0) {
            final Http newRequest = new Http();
            newRequest.setRaw(httpRequests);
            template.setHttp(List.of(newRequest));
        } else {
            if (requestSize > 1) {
                JOptionPane.showMessageDialog(suiteFrame(), String.format("The %s will be added to the first request!", errorMessageContext), "Multiple requests present", JOptionPane.WARNING_MESSAGE);
            }
            firstTemplateRequestConsumer.accept(requests.iterator().next());
        }
    }

    private static Set<JMenuItem> createAddToTabContextMenuItems(GeneralSettings generalSettings, Consumer<Template> templateConsumer) {
        final TemplateGeneratorTabContainer templateGeneratorTabContainer = getTemplateGeneratorContainerInstance(generalSettings);

        return templateGeneratorTabContainer.getTabs().stream().map(tab -> {
            final String tabName = tab.getName();
            // TODO add scrollable menu?
            final Runnable action = () -> templateGeneratorTabContainer.getTab(tabName)
                                                                       .ifPresent(templateGeneratorTab -> templateGeneratorTab.getTemplate().ifPresent(template -> {
                                                                           templateConsumer.accept(template);
                                                                           templateGeneratorTab.setTemplate(template);
                                                                       }));
            return createContextMenuItem(action, tabName);
        }).collect(Collectors.toSet());
    }

    private static TemplateGeneratorTabContainer getTemplateGeneratorContainerInstance(GeneralSettings generalSettings) {
        return generalSettings.isDetachedGeneratorWindow() ? TemplateGeneratorWindow.getInstance(generalSettings) : TemplateGeneratorEmbeddedContainer.getInstance(generalSettings);
    }

    private List<JMenuItem> generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request) {
        final List<JMenuItem> menuItems;
        if (request.chars().filter(c -> c == TemplateUtils.INTRUDER_PAYLOAD_MARKER).count() <= 2) {
            menuItems = List.of(createContextMenuItem(() -> generateIntruderTemplate(generalSettings, targetUrl, request, Http.AttackType.batteringram), GENERATE_CONTEXT_MENU_TEXT));
        } else {
            menuItems = Arrays.stream(Http.AttackType.values())
                              .map(attackType -> createContextMenuItem(() -> generateIntruderTemplate(generalSettings, targetUrl, request, attackType), GENERATE_CONTEXT_MENU_TEXT + " - " + attackType))
                              .collect(Collectors.toList());
        }
        return menuItems;
    }

    private static JMenuItem createContextMenuItem(Runnable runnable, String menuItemText) {
        final JMenuItem menuItem = new JMenuItem(menuItemText);
        menuItem.addActionListener((ActionEvent e) -> runnable.run());
        return menuItem;
    }

    private void generateTemplate(GeneralSettings generalSettings, TemplateMatcher contentMatcher, URL targetUrl, HttpRequestResponse requestResponse) {
        final Http requests = new Http();
        requests.setRaw(requestResponse.request().toString());
        requests.setMatchers(contentMatcher, new Status((int) requestResponse.response().statusCode()));

        generateTemplate(generalSettings, targetUrl, requests);
    }

    private void generateIntruderTemplate(GeneralSettings generalSettings, URL targetUrl, String request, Http.AttackType attackType) {
        final Http http = new Http();
        final TransformedRequest intruderRequest = TemplateUtils.transformRequestWithPayloads(attackType, request);
        http.setTransformedRequest(intruderRequest);

        generateTemplate(generalSettings, targetUrl, http);
    }

    private void generateTemplate(GeneralSettings generalSettings, URL targetUrl, Http http) {
        final String author = generalSettings.getAuthor();
        final Info info = new Info("Template Name", author, Info.Severity.info);

        final Template template = new Template("template-id", info, http);
        final String normalizedTemplate = TemplateUtils.normalizeTemplate(YamlUtil.dump(template));

        final NucleiGeneratorSettings nucleiGeneratorSettings = new NucleiGeneratorSettings.Builder(generalSettings, targetUrl, normalizedTemplate)
                .withYamlFieldDescriptionMap(this.yamlFieldDescriptionMap)
                .build();

        SwingUtilities.invokeLater(() -> {
            try {
                final TemplateGeneratorTabContainer templateGeneratorTabContainer = getTemplateGeneratorContainerInstance(generalSettings);
                templateGeneratorTabContainer.addTab(new TemplateGeneratorTab(nucleiGeneratorSettings));

                if (!generalSettings.isDetachedGeneratorWindow()) {
                    configureEmbeddedGeneratorTab(generalSettings, templateGeneratorTabContainer);
                }
            } catch (Throwable e) {
                JOptionPane.showMessageDialog(suiteFrame(), "There was an error while trying to complete the requested action. Please check the logs.", "An error occurred", JOptionPane.ERROR_MESSAGE);
                generalSettings.logError("Error while trying to generate/show the generated template", e);
            }
        });
    }

    private void configureEmbeddedGeneratorTab(GeneralSettings generalSettings, TemplateGeneratorTabContainer templateGeneratorTabContainer) {
        final JComponent generatorComponent = templateGeneratorTabContainer.getComponent();

        if (getTabComponentByName(this.nucleiTabbedPane, GENERATOR_TAB_NAME).isEmpty()) {
            this.nucleiTabbedPane.addTab(GENERATOR_TAB_NAME, generatorComponent);

            final TemplateGeneratorTabbedPane tabbedPane = templateGeneratorTabContainer.getTabbedPane();
            tabbedPane.addChangeListener(e -> {
                if (((JTabbedPane) e.getSource()).getTabCount() == 0) {
                    getTabComponentByName(this.nucleiTabbedPane, GENERATOR_TAB_NAME).map(Map.Entry::getValue)
                                                                                    .ifPresentOrElse(generatorTab -> this.nucleiTabbedPane.remove(generatorTab),
                                                                                                     () -> generalSettings.logError("Nuclei Generator tab was not present to remove."));
                    Arrays.stream(tabbedPane.getChangeListeners())
                          .forEach(tabbedPane::removeChangeListener);
                }
            });
        }

        // Generating is an explicit action with an obvious next step, so land the user
        // on the generated template instead of leaving them in Proxy or Repeater.
        this.nucleiTabbedPane.setSelectedComponent(generatorComponent);

        if (!SwingUtils.selectEnclosingTab(this.nucleiTabbedPane)) {
            generalSettings.logError("Could not bring the Nuclei tab to the front.");
        }
    }

    /**
     * Mirrors Burp's own byte to string mapping, where every byte maps to one character.
     */
    private static String bytesToString(byte[] bytes) {
        return new String(bytes, StandardCharsets.ISO_8859_1);
    }

    /**
     * Sends a GET through Burp rather than a direct connection, so the upstream proxy
     * configured by the user applies.
     *
     * @return the response body for a 200, otherwise empty
     */
    private static Optional<String> sendThroughBurp(MontoyaApi api, URI uri) {
        try {
            final HttpRequestResponse result = api.http().sendRequest(HttpRequest.httpRequestFromUrl(uri.toString()));

            if (!result.hasResponse()) {
                api.logging().logToError(String.format("No response received from '%s'", uri));
                return Optional.empty();
            }

            final HttpResponse response = result.response();
            final short statusCode = response.statusCode();
            if (statusCode != 200) {
                final String hint = (statusCode == 403 || statusCode == 429) ? " Clients without an API key are rate limited, so retrying in a few seconds may work." : "";
                api.logging().logToError(String.format("'%s' returned HTTP %d.%s", uri, statusCode, hint));
                return Optional.empty();
            }

            return Optional.of(response.bodyToString());
        } catch (RuntimeException e) {
            api.logging().logToError(String.format("Could not reach '%s'", uri), e);
            return Optional.empty();
        }
    }

    /**
     * @return Burp's own window, so dialogs open on the monitor Burp is on rather than
     * wherever a null parent happens to place them
     */
    private static Component suiteFrame() {
        return montoyaApi == null ? null : montoyaApi.userInterface().swingUtils().suiteFrame();
    }
}

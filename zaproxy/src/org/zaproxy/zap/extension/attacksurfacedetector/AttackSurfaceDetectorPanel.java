////////////////////////////////////////////////////////////////////////////////////////
//
//     Copyright (C) 2017 Applied Visions - http://securedecisions.com
//
//     The contents of this file are subject to the Mozilla Public License
//     Version 2.0 (the "License"); you may not use this file except in
//     compliance with the License. You may obtain a copy of the License at
//     http://www.mozilla.org/MPL/
//
//     Software distributed under the License is distributed on an "AS IS"
//     basis, WITHOUT WARRANTY OF ANY KIND, either express or implied. See the
//     License for the specific language governing rights and limitations
//     under the License.
//
//     This material is based on research sponsored by the Department of Homeland
//     Security (DHS) Science and Technology Directorate, Cyber Security Division
//     (DHS S&T/CSD) via contract number HHSP233201600058C.
//
//     Contributor(s):
//              Secure Decisions, a division of Applied Visions, Inc
//
////////////////////////////////////////////////////////////////////////////////////////

/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.zaproxy.zap.extension.attacksurfacedetector;

import java.awt.*;
import java.awt.event.*;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.util.*;
import java.util.List;

import javax.swing.*;

import com.denimgroup.threadfix.data.enums.ParameterDataType;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.EndpointSerialization;
import com.denimgroup.threadfix.framework.util.EndpointUtil;
import com.securedecisions.attacksurfacedetector.plugin.zap.action.AttackThread;
import com.securedecisions.attacksurfacedetector.plugin.zap.action.EndpointsButton;
import com.securedecisions.attacksurfacedetector.plugin.zap.action.JsonEndpointsButton;
import com.securedecisions.attacksurfacedetector.plugin.zap.action.LocalEndpointsButton;
import com.securedecisions.attacksurfacedetector.plugin.zap.dialog.OptionsDialog;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;

import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import javax.swing.text.*;

import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import static com.securedecisions.attacksurfacedetector.plugin.zap.action.EndpointsButton.GENERIC_INT_SEGMENT;


public class AttackSurfaceDetectorPanel extends AbstractPanel
{
    private static final long serialVersionUID = 1L;
    private ViewDelegate view = null;
    private Model model;
    private static final Logger LOGGER = Logger.getLogger(AttackSurfaceDetectorPanel.class);
    private JTextField sourceFolderField;
    private JTextField oldSourceFolderField;
    private JTextField serializationField;
    private JTextField oldSerializationField;
    private JTextField targetHostField;
    private JTextField targetPathField;
    private JTextField targetPortField;
    private JCheckBox autoSpiderField;
    private JCheckBox useHttpField;
    private static JTabbedPane basePanel = new JTabbedPane();

    public AttackSurfaceDetectorPanel(ViewDelegate view, final Model model)
    {
        super();
        super.setName("Attack Surface Detector");
        this.model = model;
        this.view = view;
        ZapPropertiesManager.INSTANCE.setView(view);
        initialize();
        ImageIcon SECDEC_ICON = new ImageIcon(AttackSurfaceDetector.class.getResource("/org/zaproxy/zap/extension/attacksurfacedetector/resources/ASD-16px-logo.png"));
        this.setIcon(SECDEC_ICON);
    }

    private void initialize()
    {
        this.setLayout(new BorderLayout());
        basePanel.setName("Attack Surface Detector");
        JPanel optionsPanel = buildOptionsPanel();
        basePanel.addTab("Configuration", null, optionsPanel, "This tab allows the user to alter the configuration of the Attack Surface Detector");
        basePanel.addTab("Results", null, buildMainPanel(), "The results tab of the Attack Surface Detector which contains buttons to import endpoints and a table to view these endpoints");
        basePanel.addTab("Help", null, buildHelpPanel(), "The information tab of the Attack Surface Detector which provides the user with useful information regarding supported formats and general usage");

        this.add(basePanel, BorderLayout.CENTER);
    }


    private JPanel buildMainPanel()
    {
        JTable endPointsTable = buildEndpointsTable();
        ZapPropertiesManager.INSTANCE.setEndpointsTable(endPointsTable);
        JScrollPane scrollPane = new JScrollPane(endPointsTable);
        JPanel buttonPanel = buildButtonPanel();
        JPanel mainPanel = new JPanel();
        mainPanel.setLayout(new GridBagLayout());
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        mainPanel.add(buttonPanel, gridBagConstraints);

        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.anchor = GridBagConstraints.CENTER;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        mainPanel.add(scrollPane, gridBagConstraints);

        return mainPanel;
    }


    private JPanel buildButtonPanel()
    {
        JPanel buttonPanel = new JPanel();
        buttonPanel.setPreferredSize(new java.awt.Dimension(1000, 30));
        buttonPanel.setMaximumSize(new java.awt.Dimension(1000, 30));
        JButton importFromSourceButton = new LocalEndpointsButton(view, model);
        JButton importFromJsonButton = new JsonEndpointsButton(view, model);
        buttonPanel.setLayout(new GridBagLayout());
        int x = 0;
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = x++;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.insets = new java.awt.Insets(3, 0, 0, 0);
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        buttonPanel.add(importFromSourceButton, gridBagConstraints);

        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = x++;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.insets = new java.awt.Insets(3, 0, 0, 0);
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        buttonPanel.add(importFromJsonButton, gridBagConstraints);

        return buttonPanel;
    }

    private JPanel buildHelpPanel()
    {

        JPanel helpPanel = new JPanel();
        JScrollPane helpScroll = new JScrollPane(helpPanel);
        JPanel helpBasePanel = new JPanel();
        helpBasePanel.setLayout(new GridBagLayout());
        Insets helpPanelInsets = new Insets(2, 0, 0, 0);
        helpPanel.setLayout(new GridBagLayout());
        int y = 0;

        JPanel generalHelpPanel = buildGeneralHelpPanel();
        GridBagConstraints generalHelpPanelConstraints = new GridBagConstraints();
        generalHelpPanelConstraints.gridx = 0;
        generalHelpPanelConstraints.gridy = y++;
        generalHelpPanelConstraints.ipadx = 5;
        generalHelpPanelConstraints.ipady = 5;
        generalHelpPanelConstraints.insets = helpPanelInsets;
        generalHelpPanelConstraints.weighty = 1;
        generalHelpPanelConstraints.weightx = 1;
        generalHelpPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(generalHelpPanel, generalHelpPanelConstraints);


        JSeparator generalHelpPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints generalHelpPanelSeparatorConstraints = new GridBagConstraints();
        generalHelpPanelSeparatorConstraints.gridx = 0;
        generalHelpPanelSeparatorConstraints.gridy = y++;
        generalHelpPanelSeparatorConstraints.insets = helpPanelInsets;
        generalHelpPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        generalHelpPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        helpPanel.add(generalHelpPanelSeparator, generalHelpPanelSeparatorConstraints);

        JPanel differenceGeneratorPanel = buildDifferenceGeneratorPanel();
        GridBagConstraints differenceGeneratorConstraints = new GridBagConstraints();
        differenceGeneratorConstraints.gridx = 0;
        differenceGeneratorConstraints.gridy = y++;
        differenceGeneratorConstraints.ipadx = 5;
        differenceGeneratorConstraints.ipady = 5;
        differenceGeneratorConstraints.insets = helpPanelInsets;
        differenceGeneratorConstraints.weighty = 1;
        differenceGeneratorConstraints.weightx = 1;
        differenceGeneratorConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(differenceGeneratorPanel, differenceGeneratorConstraints);

        JSeparator differenceGeneratorPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints differenceGeneratorSeparatorConstraints = new GridBagConstraints();
        differenceGeneratorSeparatorConstraints.gridx = 0;
        differenceGeneratorSeparatorConstraints.gridy = y++;
        differenceGeneratorSeparatorConstraints.insets = helpPanelInsets;
        differenceGeneratorSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        differenceGeneratorSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        helpPanel.add(differenceGeneratorPanelSeparator, differenceGeneratorSeparatorConstraints);


        JPanel frameworkPanel = buildFrameworkPanel();
        GridBagConstraints frameworkPanelConstraints = new GridBagConstraints();
        frameworkPanelConstraints.gridx = 0;
        frameworkPanelConstraints.gridy = y++;
        frameworkPanelConstraints.ipadx = 5;
        frameworkPanelConstraints.ipady = 5;
        frameworkPanelConstraints.insets = helpPanelInsets;
        frameworkPanelConstraints.weighty = 1;
        frameworkPanelConstraints.weightx = 1;
        frameworkPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(frameworkPanel, frameworkPanelConstraints);

        JSeparator frameworkPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints frameworkPanelSeparatorConstraints = new GridBagConstraints();
        frameworkPanelSeparatorConstraints.gridx = 0;
        frameworkPanelSeparatorConstraints.gridy = y++;
        frameworkPanelSeparatorConstraints.insets = helpPanelInsets;
        frameworkPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        frameworkPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        helpPanel.add(frameworkPanelSeparator, frameworkPanelSeparatorConstraints);

        JPanel fileFormatPanel = buildFileFormatPanel();
        GridBagConstraints fileFormatConstraints = new GridBagConstraints();
        fileFormatConstraints.gridx = 0;
        fileFormatConstraints.gridy = y++;
        fileFormatConstraints.ipadx = 5;
        fileFormatConstraints.ipady = 5;
        fileFormatConstraints.insets = helpPanelInsets;
        fileFormatConstraints.anchor = GridBagConstraints.NORTHWEST;
        helpPanel.add(fileFormatPanel, fileFormatConstraints);

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        helpScroll.setPreferredSize(new Dimension(view.getMainFrame().getWidth(), view.getMainFrame().getHeight()-view.getResponsePanel().getHeight() + 100));
        helpBasePanel.add(helpScroll, gridBagConstraints);

        return helpBasePanel;
    }

    private JPanel buildOptionsPanel()
    {
        JPanel optionsPanel = new JPanel();
        JScrollPane optionsScroll = new JScrollPane(optionsPanel);
        optionsPanel.addHierarchyListener(new HierarchyListener()
        {
            @Override
            public void hierarchyChanged(HierarchyEvent e)
            {
                boolean tabIsShowing = optionsPanel.isShowing();
                if (tabIsShowing)
                    loadOptionsProperties();
            }
        });
        JPanel optionsBasePanel = new JPanel();
        optionsBasePanel.setLayout(new GridBagLayout());
        JPanel buttonPanel = buildButtonPanel();
        Insets optionsPanelInsets = new Insets(0, 0, 0, 0);
        optionsPanel.setLayout(new GridBagLayout());
        int y = 0;

        JPanel autoPanel = buildAutoOptionsPanel();
        GridBagConstraints autoPanelConstraints = new GridBagConstraints();
        autoPanelConstraints.gridx = 0;
        autoPanelConstraints.gridy = y++;
        autoPanelConstraints.ipadx = 5;
        autoPanelConstraints.ipady = 5;
        autoPanelConstraints.insets = optionsPanelInsets;
        autoPanelConstraints.weighty = 1;
        autoPanelConstraints.weightx = 1;
        autoPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(autoPanel, autoPanelConstraints);

        JSeparator autoPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints autoPanelSeparatorConstraints = new GridBagConstraints();
        autoPanelSeparatorConstraints.gridx = 0;
        autoPanelSeparatorConstraints.gridy = y++;
        autoPanelSeparatorConstraints.insets = optionsPanelInsets;
        autoPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        autoPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(autoPanelSeparator, autoPanelSeparatorConstraints);

        JPanel sourcePanel = buildSourcePanel();
        GridBagConstraints sourcePanelConstraints = new GridBagConstraints();
        sourcePanelConstraints.gridx = 0;
        sourcePanelConstraints.gridy = y++;
        sourcePanelConstraints.ipadx = 5;
        sourcePanelConstraints.ipady = 5;
        sourcePanelConstraints.insets = optionsPanelInsets;
        sourcePanelConstraints.weighty = 1;
        sourcePanelConstraints.weightx = 1;
        sourcePanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(sourcePanel, sourcePanelConstraints);

        JSeparator sourcePanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints sourcePanelSeparatorConstraints = new GridBagConstraints();
        sourcePanelSeparatorConstraints.gridx = 0;
        sourcePanelSeparatorConstraints.gridy = y++;
        sourcePanelSeparatorConstraints.insets = optionsPanelInsets;
        sourcePanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        sourcePanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(sourcePanelSeparator, sourcePanelSeparatorConstraints);

        JPanel serializationPanel = buildSerializationPanel();
        GridBagConstraints serializationConstraints = new GridBagConstraints();
        serializationConstraints.gridx = 0;
        serializationConstraints.gridy = y++;
        serializationConstraints.ipadx = 5;
        serializationConstraints.ipady = 5;
        serializationConstraints.insets = optionsPanelInsets;
        serializationConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(serializationPanel, serializationConstraints);

        JSeparator serializationPanelSeparator = new JSeparator(JSeparator.HORIZONTAL);
        GridBagConstraints serializatonPanelSeparatorConstraints = new GridBagConstraints();
        serializatonPanelSeparatorConstraints.gridx = 0;
        serializatonPanelSeparatorConstraints.gridy = y++;
        serializatonPanelSeparatorConstraints.insets = optionsPanelInsets;
        serializatonPanelSeparatorConstraints.fill = GridBagConstraints.HORIZONTAL;
        serializatonPanelSeparatorConstraints.anchor = GridBagConstraints.NORTH;
        optionsPanel.add(serializationPanelSeparator, serializatonPanelSeparatorConstraints);

        JPanel targetPanel = buildTargetPanel();
        GridBagConstraints targetPanelConstraints = new GridBagConstraints();
        targetPanelConstraints.gridx = 0;
        targetPanelConstraints.gridy = y++;
        targetPanelConstraints.ipadx = 5;
        targetPanelConstraints.ipady = 5;
        targetPanelConstraints.insets = optionsPanelInsets;
        targetPanelConstraints.anchor = GridBagConstraints.NORTHWEST;
        optionsPanel.add(targetPanel, targetPanelConstraints);

        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 0;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        optionsBasePanel.add(buttonPanel, gridBagConstraints);

        gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridx = 0;
        gridBagConstraints.gridy = 1;
        gridBagConstraints.weightx = 1;
        gridBagConstraints.weighty = 1;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.anchor = GridBagConstraints.NORTHWEST;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        optionsScroll.setPreferredSize(new Dimension(view.getMainFrame().getWidth(), view.getMainFrame().getHeight()-view.getResponsePanel().getHeight() + 100));
        optionsBasePanel.add(optionsScroll, gridBagConstraints);

        loadOptionsProperties();


        return optionsBasePanel;
    }

    private JPanel buildDifferenceGeneratorPanel()
    {
        JPanel differenceGeneratorPanel = new JPanel();
        differenceGeneratorPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel differenceGeneratorPanelTitle = addPanelTitleToGridBagLayout("Attack Surface Difference Generator", differenceGeneratorPanel, yPosition++);
        final JLabel differenceGeneratorDescription = addPanelDescriptionToGridBagLayout("<html>The Attack Surface Difference Generator is a feature of the Attack Surface Detector plugin that is when importing from both source code or JSON.<br>" +
                " This feature is automatically enabled when two seperate versions of the same application are given on the configurations page and provides the following benefits:<html>" , differenceGeneratorPanel, yPosition++);

        final JLabel listLabel = addPanelDescriptionToGridBagLayout("<html><li> Compares two versions highlighting the differences between endpoints" +
                        " The results table will mark new or modified endpoints signifiny a change in the attack surface</li><br>" +
                        "<li>Viewing the details of a modified endpoint will show which parameters have been added, modified or deleted including data types and names</li><br>" +
                        "<li>Viewing the details of a new endpoint will display that the endpoint was not found in the previous version and show it's parameters if applicable</li></html>",
                differenceGeneratorPanel, yPosition++);

        return differenceGeneratorPanel;
    }

    private JPanel buildGeneralHelpPanel()
    {
        JPanel generalHelpPanel = new JPanel();
        generalHelpPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel generalHelpPanelTitle = addPanelTitleToGridBagLayout("General Help", generalHelpPanel, yPosition++);
        final JLabel generalHelpPanelDescription = addPanelDescriptionToGridBagLayout("<html>The purpose of this section is to aid in general Attack Surface Detector usage. For any information or questions not addressed below please visit the following link:</html>", generalHelpPanel, yPosition++);
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-zap/wiki\" target=\"https://github.com/secdec/attack-surface-detector-zap/wiki\">https://github.com/secdec/attack-surface-detector-zap/wiki</a></html>";
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, generalHelpPanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() > 0)
                {
                    if (Desktop.isDesktopSupported())
                    {
                        Desktop desktop = Desktop.getDesktop();
                        try
                        {
                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-zap/wiki");
                            desktop.browse(uri);
                        }
                        catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    }
                    else { }
                }
            }
        });

        final JLabel importLabel = addPanelDescriptionToGridBagLayout("<html><li> Selecting \"Import Endpoints from Source\" or \"Import Endpoints from CLI JSON\" without" +
                        " configuring targer and/or source/JSON location respectively will show a configuration dialog prompting the user to do so</li><br>" +
                        "<li> To import endpoints in order to view their details without attacking the webapplication simply leave the target configuration empty and select submit on the pop up dialog</li><br>" +
                        "<li> To view the details of a specific endpoint simply double click on an endpoint listed in the endpoints table of the results screen</li><br></html>",
                generalHelpPanel, yPosition++);

        return generalHelpPanel;
    }

    private JPanel buildFrameworkPanel()
    {
        JPanel frameworkPanel = new JPanel();
        frameworkPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel frameworkPanelTitle = addPanelTitleToGridBagLayout("Supported Frameworks", frameworkPanel, yPosition++);
        final JLabel frameworkPanelDescription = addPanelDescriptionToGridBagLayout("<html>The Attack Surface Detector uses static code analysis to identify web app endpoints by parsing routes and identifying parameters.<br> The following is a list of the supported languages and frameworks:</html>", frameworkPanel, yPosition++);
        final JLabel frameworksList = addPanelDescriptionToGridBagLayout("<html><li>C# / ASP.NET MVC </li><br>" +
                "<li>C# / Web Forms </li><br>" +
                "<li>Java / Spring MVC </li><br>" +
                "<li>Java / Struts </li><br>" +
                "<li>Java / JSP </li><br>" +
                "<li>Python / Django </li><br>" +
                "<li>Ruby / Rails <br></li></html>", frameworkPanel, yPosition++);

        return frameworkPanel;
    }

    private JPanel buildFileFormatPanel()
    {
        JPanel fileFormatPanel = new JPanel();
        fileFormatPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        final JLabel fileFormatPanelTitle = addPanelTitleToGridBagLayout("Accepted File Formats", fileFormatPanel, yPosition++);
        final JLabel sourcePanelDescription = addPanelDescriptionToGridBagLayout("<html>When importing endpoints from source code the accepted formats are as follows:</html>", fileFormatPanel, yPosition++);
        final JLabel zipFormatList = addPanelDescriptionToGridBagLayout("<html><li>Zip file | *.zip: A compresed version of a source code folder</li><br>" +
                "<li>War file | *.war: A .war file that contains compiled source code</li><br>"  +
                "<li>Directory | dir: A directory containing the source code of a supported framework</li><br></html>", fileFormatPanel, yPosition++);
        final JLabel jsonPanelDescription = addPanelDescriptionToGridBagLayout("<html>When importing endpoints from CLI JSON you must first have a serialized Attack Surface Detector-CLI JSON output file.  <br>To locate this tool and for general usage visit the Attack Surface Detector-CLI github page located below:</html>",fileFormatPanel, yPosition++);
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-cli\" target=\"https://github.com/secdec/attack-surface-detector-cli\">https://github.com/secdec/attack-surface-detector-cli</a></html>";
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, fileFormatPanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() > 0)
                {
                    if (Desktop.isDesktopSupported())
                    {
                        Desktop desktop = Desktop.getDesktop();
                        try
                        {
                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-cli");
                            desktop.browse(uri);
                        }
                        catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    }
                    else { }
                }
            }
        });

        return fileFormatPanel;
    }

    private JPanel buildTargetPanel()
    {
        final JPanel targetPanel = new JPanel();
        targetPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e)
            {
                ZapPropertiesManager.INSTANCE.setUseHttps(useHttpField.isSelected());
            }
        };

        final JLabel targetPanelTitle = addPanelTitleToGridBagLayout("Target Configuration", targetPanel, yPosition++);
        final JLabel targetPanelDescription = addPanelDescriptionToGridBagLayout("<html>This setting allows you to configure the target location for your HTTP/HTTPS requests. Port and host are required for <br>the Attack Surface Detector to generate requests based on the imported endpoints.<br></html>", targetPanel, yPosition++);
        final JLabel targetPanelDescription2 = addPanelDescriptionToGridBagLayout(" ", targetPanel, yPosition++);
        targetHostField = addTextFieldToGridBagLayout("Host:", targetPanel, yPosition++, ZapPropertiesManager.INSTANCE.HOST_KEY);
        targetPortField = addTextFieldToGridBagLayout("Port:", targetPanel, yPosition++, ZapPropertiesManager.PORT_KEY);
        targetPathField = addTextFieldToGridBagLayout("Path (optional):", targetPanel, yPosition++, ZapPropertiesManager.PATH_KEY);
        useHttpField = addCheckBoxToGridBagLayout("Use HTTPS", targetPanel, yPosition++, applicationCheckBoxHttpActionListener);
        useHttpField.setSelected(ZapPropertiesManager.INSTANCE.getUseHttps());
        PlainDocument portDoc = (PlainDocument)targetPortField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());
        return targetPanel;
    }

    private JPanel buildSerializationPanel()
    {
        final JPanel serializationPanel = new JPanel();
        serializationPanel.setLayout(new GridBagLayout());
        int yPosition = 0;
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new GridBagLayout());
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-cli\" target=\"https://github.com/secdec/attack-surface-detector-cli\">https://github.com/secdec/attack-surface-detector-cli</a></html>";
        final JLabel serializationPanelTitle = addPanelTitleToGridBagLayout("Attack Surface Detector CLI JSON", serializationPanel, yPosition++);
        final JLabel serializationPanelDescription = addPanelDescriptionToGridBagLayout("<html>The CLI tool is a command line interface version of Attack Surface Detector that can produce a serialized JSON output of a supported web applications endpoints. <br>To find this tool or help using it please visit the link below:</html>", serializationPanel, yPosition++);
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, serializationPanel, yPosition++);
        final JLabel differenceGeneratorDescription = addPanelDescriptionToGridBagLayout("<html><br>You can optionally choose to compare two different versions of the endpoint JSON files, and the Attack Surface Detector <br>will highlight endpoints and parameters that are new or modified in the newer version of the application.</html>", serializationPanel, yPosition++);
        final JLabel serializationPanelDescription2 = addPanelDescriptionToGridBagLayout(" ", serializationPanel, yPosition++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() > 0)
                {
                    if (Desktop.isDesktopSupported())
                    {
                        Desktop desktop = Desktop.getDesktop();
                        try
                        {
                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-cli");
                            desktop.browse(uri);
                        }
                        catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    }
                    else { }
                }
            }
        });
        final JButton sourceFolderBrowseButton = new JButton("Select JSON file ...");
        sourceFolderBrowseButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = serializationField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals("")))
                    currentDirectory = System.getProperty("user.home");
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Please select endpoint JSON file");
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));
                if (chooser.showOpenDialog(serializationPanel) == JFileChooser.APPROVE_OPTION)
                {
                    serializationField.setText(chooser.getSelectedFile().getAbsolutePath());
                    ZapPropertiesManager.INSTANCE.setJsonFile(serializationField.getText());
                }
            }
        });
        serializationField = addTextFieldToGridBagLayout("Endpoint JSON to analyze:", serializationPanel, yPosition++, ZapPropertiesManager.INSTANCE.INSTANCE.JSON_FILE_KEY, sourceFolderBrowseButton);


        final JButton oldSourceFolderBrowseButton = new JButton("Select JSON file ...");
        oldSourceFolderBrowseButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser2 = new JFileChooser();
                String currentDirectory = oldSerializationField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals("")))
                    currentDirectory = System.getProperty("user.home");
                chooser2.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser2.setDialogTitle("Please select endpoint JSON file");
                chooser2.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser2.setAcceptAllFileFilterUsed(false);
                chooser2.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));
                if (chooser2.showOpenDialog(serializationPanel) == JFileChooser.APPROVE_OPTION)
                {
                    oldSerializationField.setText(chooser2.getSelectedFile().getAbsolutePath());
                    ZapPropertiesManager.INSTANCE.setOldJsonFile(oldSerializationField.getText());
                }
            }
        });


        oldSerializationField = addTextFieldToGridBagLayout("Comparison endpoint JSON (optional):", serializationPanel, yPosition++, ZapPropertiesManager.INSTANCE.OLD_JSON_FILE_KEY, oldSourceFolderBrowseButton);

        return serializationPanel;
    }

    private JPanel buildAutoOptionsPanel() {
        final JPanel autoOptionsPanel = new JPanel();
        autoOptionsPanel.setLayout(new GridBagLayout());
        int yPosition = 0;

        final JLabel autoOptionsPanelTitle = addPanelTitleToGridBagLayout("Attack Surface Detector Plugin Behavior", autoOptionsPanel, yPosition++);
        final JLabel autoOptionsPanelDescription = addPanelDescriptionToGridBagLayout("This setting allows the user to enable or disable automatic spidering after importing endpoints.", autoOptionsPanel, yPosition++);
        ActionListener applicationCheckBoxSpiderActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                    ZapPropertiesManager.setAutoSpider(autoSpiderField.isSelected());
            }
        };

        final JLabel bufferLabel = addPanelDescriptionToGridBagLayout(" ", autoOptionsPanel, yPosition++);
        autoSpiderField = addCheckBoxToGridBagLayout(new JLabel("Automatically start spider after importing endpoints "), autoOptionsPanel, yPosition++, applicationCheckBoxSpiderActionListener);

        return autoOptionsPanel;
    }


    private JPanel buildSourcePanel()
    {
        final JPanel sourcePanel = new JPanel();
        sourcePanel.setLayout(new GridBagLayout());
        int y = 0;
        JPanel titlePanel = new JPanel();
        titlePanel.setLayout(new GridBagLayout());
        final JLabel sourcePanelTitle = addPanelTitleToGridBagLayout("Local Source Code", sourcePanel, y++);
        final JLabel sourcePanelDescription = addPanelDescriptionToGridBagLayout("<html>This setting lets you configure the location of your source code. For more information on supported frameworks and general usage click the link below:", sourcePanel, y++);
        String link = "<html><a href=\"https://github.com/secdec/attack-surface-detector-zap/wiki\" target=\"https://github.com/secdec/attack-surface-detector-zap/wiki\">https://github.com/secdec/attack-surface-detector-zap/wiki</a></html>";
        final JLabel linkLabel = addPanelDescriptionToGridBagLayout(link, sourcePanel, y++);
        final JLabel differenceGeneratorDescription = addPanelDescriptionToGridBagLayout("<html><br>You can optionally choose to compare two different versions of the source code, and the Attack Surface Detector <br>will highlight endpoints and parameters that are new or modified in the newer version of the source code.</html>", sourcePanel, y++);
        final JLabel sourcePanelDescription2 = addPanelDescriptionToGridBagLayout(" ", sourcePanel, y++);
        linkLabel.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        linkLabel.addMouseListener(new MouseAdapter()
        {
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() > 0)
                {
                    if (Desktop.isDesktopSupported())
                    {
                        Desktop desktop = Desktop.getDesktop();
                        try
                        {
                            URI uri = new URI("https://github.com/secdec/attack-surface-detector-zap/wiki");
                            desktop.browse(uri);
                        }
                        catch (IOException ex) { }
                        catch (URISyntaxException ex) { }
                    }
                    else { }
                }
            }
        });
        final JButton sourceFolderBrowseButton = new JButton("Select folder or zip file ...");
        sourceFolderBrowseButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = sourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals("")))
                    currentDirectory = System.getProperty("user.home");
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Please select the folder containing the source code");
                chooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                chooser.setAcceptAllFileFilterUsed(false);
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.war | Web application archive", "war"));
                chooser.addChoosableFileFilter( new FileFilter()
                {
                    public boolean accept(File f)
                    {
                        return f.isDirectory();
                    }

                    public String getDescription()
                    {
                        return "dir | Directory/Folder";
                    }
                });
                if (chooser.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION)
                {
                    sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
                    ZapPropertiesManager.INSTANCE.setSourceFolder(sourceFolderField.getText());
                }
            }
        });
        sourceFolderField = addTextFieldToGridBagLayout("Source code to analyze:", sourcePanel, y++, ZapPropertiesManager.SOURCE_FOLDER_KEY, sourceFolderBrowseButton);

        final JButton oldSourceFolderBrowseButton = new JButton("Select folder or zip file ...");
        oldSourceFolderBrowseButton.addActionListener(new ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser2 = new JFileChooser();
                String currentDirectory = oldSourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals("")))
                    currentDirectory = System.getProperty("user.home");
                chooser2.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser2.setDialogTitle("Please select the folder containing the source code");
                chooser2.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                chooser2.setAcceptAllFileFilterUsed(false);
                chooser2.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
                chooser2.addChoosableFileFilter( new FileNameExtensionFilter("*.war | Web application archive", "war"));
                chooser2.addChoosableFileFilter( new FileFilter()
                {
                    public boolean accept(File f)
                    {
                        return f.isDirectory();
                    }
                    public String getDescription()
                    {
                        return "dir | Directory/Folder";
                    }
                });
                if (chooser2.showOpenDialog(sourcePanel) == JFileChooser.APPROVE_OPTION)
                {
                    oldSourceFolderField.setText(chooser2.getSelectedFile().getAbsolutePath());
                    ZapPropertiesManager.INSTANCE.setOldSourceFolder(oldSourceFolderField.getText());
                }
            }
        });
        oldSourceFolderField = addTextFieldToGridBagLayout("Comparison source code (optional):", sourcePanel, y++, ZapPropertiesManager.OLD_SOURCE_FOLDER_KEY, oldSourceFolderBrowseButton);

        return sourcePanel;
    }

    private JTable buildEndpointsTable()
    {
        Object[][] data = {};
        String[] columnNames = {"Detected Endpoints", "Number of Detected Parameters", "GET Method", "POST Method", "New/Modified", "Endpoint"};
        DefaultTableModel dtm = new DefaultTableModel(data, columnNames)
        {
            @Override
            public boolean isCellEditable(int row, int column)
            {
                return false;
            }
        };
        JTable endpointsTable = new JTable(dtm);
        endpointsTable.addMouseListener(new MouseListener()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                if (e.getClickCount() == 2)
                {
                    EndpointDecorator decorator = (EndpointDecorator) endpointsTable.getModel().getValueAt(endpointsTable.getSelectedRow(), 5);
                    ZapPropertiesManager.INSTANCE.setEndpointDecorator(decorator);

                    JPanel detailPanel = new JPanel();
                    detailPanel.setLayout(new GridBagLayout());
                    JLabel displayArea = new JLabel();
                    String displayStr = new String();
                    int y = 0;
                    GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
                    gridBagConstraints1.gridx = 0;
                    gridBagConstraints1.gridy = y++;
                    gridBagConstraints1.weightx = 1.0D;
                    gridBagConstraints1.insets = new java.awt.Insets(0, 0, 0, 0);
                    gridBagConstraints1.fill = GridBagConstraints.BOTH;
                    gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
                    Endpoint.Info endpoint = decorator.getEndpoint();
                    if (endpoint != null)
                    {

                        if (decorator.getStatus() == EndpointDecorator.Status.NEW) {
                            displayStr = "<html><b>New Endpoint</b><br>";
                            displayStr = displayStr + "URL:<br>";
                        } else
                            displayStr = displayStr + "<html> URL:<br>";

                        displayStr = displayStr + "" + endpoint.getUrlPath() + "<br><br>Methods:<br>";
                        // TODO - Gather all Endpoint objects pointing to the same endpoint and output their HTTP methods (Endpoints only have
                        //  one HTTP method at a time now)
                        if (endpoint.getHttpMethod().length() > 4)
                            displayStr = displayStr + endpoint.getHttpMethod().substring(14);
                        else
                            displayStr = displayStr + endpoint.getHttpMethod();

                        displayStr = displayStr + "<br>Parameters and type:<br>";
                        if (decorator.getStatus() == EndpointDecorator.Status.CHANGED)
                        {
                            for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet()) {
                                boolean found = false;
                                for (Map.Entry<String, RouteParameter> compParameter : decorator.getComparePoint().getParameters().entrySet())
                                {
                                    if (parameter.getKey().equalsIgnoreCase(compParameter.getKey()))
                                    {
                                        found = true;
                                        if (!parameter.getValue().getDataType().getDisplayName().equals(compParameter.getValue().getDataType().getDisplayName()))
                                            displayStr = displayStr + "<strong>" + parameter.getKey() + " - " + compParameter.getValue().getDataType().getDisplayName().toUpperCase() + " -> " + parameter.getValue().getDataType().getDisplayName().toUpperCase() + "</strong> (modified parameter type) <br>";
                                        else
                                            displayStr = displayStr + parameter.getKey() + " - " + parameter.getValue().getDataType().getDisplayName() + "<br>";
                                        break;
                                    }
                                }
                                if (!found)
                                    displayStr = displayStr + "<strong>" + parameter.getKey() + "</strong> - <strong>" + parameter.getValue().getDataType().getDisplayName().toUpperCase() + "</strong> (added parameter)<br>";
                            }
                            for (Map.Entry<String, RouteParameter> compParameter : decorator.getComparePoint().getParameters().entrySet())
                            {
                                boolean found = false;
                                for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                                {
                                    if (parameter.getKey().equalsIgnoreCase(compParameter.getKey()))
                                    {
                                        found = true;
                                        break;
                                    }
                                }
                                if (!found)
                                    displayStr = displayStr + "<span style='text-decoration: line-through;'>" + compParameter.getKey() + " - " + compParameter.getValue().getDataType().getDisplayName().toUpperCase() + "</span> (removed parameter)<br>";
                            }
                        }
                        else
                        {
                            for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                                displayStr = displayStr + parameter.getKey() + " - " + parameter.getValue().getDataType().getDisplayName() + "<br>";
                        }
                        displayStr = displayStr + "</html>";
                        displayArea.setText(displayStr);
                        detailPanel.add(displayArea, gridBagConstraints1);
                    }
                    else
                        detailPanel.add(new JLabel("No Endpoint Selected"));

                    JOptionPane.showMessageDialog(view.getMainFrame(), detailPanel, "Endpoint Details", JOptionPane.INFORMATION_MESSAGE);
                }
                else
                {
                    EndpointDecorator decorator = (EndpointDecorator) endpointsTable.getModel().getValueAt(endpointsTable.getSelectedRow(), 5);
                    ZapPropertiesManager.INSTANCE.setEndpointDecorator(decorator);
                }
            }

            @Override
            public void mousePressed(MouseEvent e) { }
            @Override
            public void mouseReleased(MouseEvent e) { }
            @Override
            public void mouseEntered(MouseEvent e) { }
            @Override
            public void mouseExited(MouseEvent e) { }
        });
        TableColumn tc = endpointsTable.getColumnModel().getColumn(2);
        tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
        tc = endpointsTable.getColumnModel().getColumn(3);
        tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
        tc = endpointsTable.getColumnModel().getColumn(4);
        tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
        tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
        endpointsTable.getColumnModel().getColumn(5).setMinWidth(0);
        endpointsTable.getColumnModel().getColumn(5).setMaxWidth(0);
        endpointsTable.getColumnModel().getColumn(5).setWidth(0);

        return endpointsTable;
    }

    private void loadOptionsProperties()
    {
        ZapPropertiesManager zapPropertiesManager = ZapPropertiesManager.INSTANCE;
        sourceFolderField.setText(zapPropertiesManager.getSourceFolder());
        oldSourceFolderField.setText(zapPropertiesManager.getOldSourceFolder());
        serializationField.setText(zapPropertiesManager.getJsonFile());
        oldSerializationField.setText(zapPropertiesManager.getOldJsonFile());
        targetHostField.setText(zapPropertiesManager.getTargetHost());
        targetPathField.setText(zapPropertiesManager.getTargetPath());
        targetPortField.setText(zapPropertiesManager.getTargetPort());
        autoSpiderField.setSelected(zapPropertiesManager.getAutoSpider());
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey)
    {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, null, null);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, Runnable threadFixPropertyFieldListenerRunnable)
    {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, threadFixPropertyFieldListenerRunnable, null);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, JButton button)
    {
        return addTextFieldToGridBagLayout(labelText, gridBagContainer, yPosition, propertyKey, null, button);
    }

    private JTextField addTextFieldToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, String propertyKey, Runnable threadFixPropertyFieldListenerRunnable, JButton button)
    {
        JLabel textFieldLabel = new JLabel(labelText);
        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.BOTH;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        JTextField textField = new JTextField(40);
        textField.addFocusListener(new ThreadFixPropertyFieldListener(textField, propertyKey, threadFixPropertyFieldListenerRunnable));
        gridBagConstraints = new GridBagConstraints();
        if (button == null)
            gridBagConstraints.gridwidth = 2;
        else
            gridBagConstraints.gridwidth = 1;

        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(textField, gridBagConstraints);

        if (button != null)
        {
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.WEST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        return textField;
    }


    private JLabel addPanelTitleToGridBagLayout(String titleText, Container gridBagContainer, int yPosition)
    {
        final JLabel panelTitle = new JLabel(titleText, JLabel.LEFT);
        //panelTitle.setForeground(new Color(34, 47, 98));
        panelTitle.setForeground(new Color(3, 85, 98));
        Font font = panelTitle.getFont();
        panelTitle.setFont(new Font(font.getFontName(), font.getStyle(), font.getSize() + 4));
        panelTitle.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.NORTH;
        gridBagContainer.add(panelTitle, gridBagConstraints);
        return panelTitle;
    }


    private JLabel addPanelDescriptionToGridBagLayout(String descriptionText, Container gridBagContainer, int yPosition)
    {
        final JLabel panelDescription = new JLabel(descriptionText);
        panelDescription.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 3;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.fill = GridBagConstraints.HORIZONTAL;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(panelDescription, gridBagConstraints);
        return panelDescription;
    }

    private JCheckBox addCheckBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener)
    {
        return addCheckBoxToGridBagLayout(labelText, gridBagContainer, yPosition, actionListener, null);
    }

    private JCheckBox addCheckBoxToGridBagLayout(JLabel label, Container gridBagContainer, int yPosition, ActionListener actionListener)
    {
        return addCheckBoxToGridBagLayout(label, gridBagContainer, yPosition, actionListener, null);
    }

    private JCheckBox addCheckBoxToGridBagLayout(String labelText, Container gridBagContainer, int yPosition, ActionListener actionListener, JButton button)
    {
        JLabel textFieldLabel = new JLabel(labelText);
        JCheckBox checkBox = new JCheckBox();

        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 2;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagConstraints.insets = new Insets(0,22,0,0);
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        gridBagConstraints = new GridBagConstraints();
        if (button == null)
            gridBagConstraints.gridwidth = 2;
        else
            gridBagConstraints.gridwidth = 1;

        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(checkBox, gridBagConstraints);

        if (button != null)
        {
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }

        checkBox.addActionListener(actionListener);

        return checkBox;
    }

    private JCheckBox addCheckBoxToGridBagLayout(JLabel textFieldLabel, Container gridBagContainer, int yPosition, ActionListener actionListener, JButton button)
    {
        JCheckBox checkBox = new JCheckBox();

        textFieldLabel.setHorizontalAlignment(SwingConstants.LEFT);
        GridBagConstraints gridBagConstraints = new GridBagConstraints();
        gridBagConstraints.gridwidth = 1;
        gridBagConstraints.gridx = 1;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagContainer.add(checkBox, gridBagConstraints);

        gridBagConstraints = new GridBagConstraints();
        if (button == null)
            gridBagConstraints.gridwidth = 2;
        else
            gridBagConstraints.gridwidth = 1;

        gridBagConstraints.gridx = 2;
        gridBagConstraints.gridy = yPosition;
        gridBagConstraints.ipadx = 5;
        gridBagConstraints.ipady = 5;
        gridBagConstraints.anchor = GridBagConstraints.WEST;
        gridBagContainer.add(textFieldLabel, gridBagConstraints);

        if (button != null)
        {
            gridBagConstraints = new GridBagConstraints();
            gridBagConstraints.gridwidth = 1;
            gridBagConstraints.gridx = 3;
            gridBagConstraints.gridy = yPosition;
            gridBagConstraints.ipadx = 5;
            gridBagConstraints.ipady = 5;
            gridBagConstraints.fill = GridBagConstraints.NONE;
            gridBagConstraints.anchor = GridBagConstraints.NORTHEAST;
            gridBagContainer.add(button, gridBagConstraints);
        }
        checkBox.addActionListener(actionListener);

        return checkBox;
    }

    private class ThreadFixPropertyFieldListener implements DocumentListener, FocusListener
    {
        private JTextField jTextField;
        private String propertyName;
        private Runnable runnable;

        private String lastValue = null;

        public ThreadFixPropertyFieldListener(JTextField jTextField, String propertyName)
        {
            this(jTextField, propertyName, null);
        }

        public ThreadFixPropertyFieldListener(JTextField jTextField, String propertyName, Runnable runnable)
        {
            this.jTextField = jTextField;
            this.propertyName = propertyName;
            this.runnable = runnable;
        }

        protected void update()
        {
            ZapPropertiesManager.INSTANCE.setPropertyValue(propertyName, jTextField.getText().trim());
            if (runnable != null)
                runnable.run();
        }

        @Override
        public void insertUpdate(DocumentEvent e)
        {
            update();
        }

        @Override
        public void removeUpdate(DocumentEvent e)
        {
            update();
        }

        @Override
        public void changedUpdate(DocumentEvent e)
        {
            update();
        }

        @Override
        public void focusGained(FocusEvent e)
        {
            lastValue = jTextField.getText().trim();
        }

        @Override
        public void focusLost(FocusEvent e)
        {
            String currentValue = jTextField.getText().trim();
            if (!currentValue.equals(lastValue))
                update();
        }
    }
}


class PortFilter extends DocumentFilter
{
    static final int maxLength = 5;
    @Override
    public void insertString(FilterBypass fb, int offset, String string, AttributeSet attr) throws BadLocationException
    {
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.insert(offset, string);
        int val = Integer.parseInt(sb.toString());
        if (isInteger(sb.toString()) && sb.length() <= maxLength && val <= 65535)
            super.insertString(fb, offset, string, attr);
        else
            Toolkit.getDefaultToolkit().beep();
    }

    private boolean isInteger(String text)
    {
        try
        {
            Integer.parseInt(text);
            return true;
        }
        catch (NumberFormatException e)
        {
            return false;
        }
    }

    @Override
    public void replace(FilterBypass fb, int offset, int length, String text, AttributeSet attrs) throws BadLocationException
    {

        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.replace(offset, offset + length, text);
        int val = Integer.parseInt(sb.toString());
        if (isInteger(sb.toString()) && (sb.length() <= maxLength) && val <= 65535)
            super.replace(fb, offset, length, text, attrs);
        else
            Toolkit.getDefaultToolkit().beep();
    }

    @Override
    public void remove(FilterBypass fb, int offset, int length) throws BadLocationException
    {
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.delete(offset, offset + length);
        if ((isInteger(sb.toString()) && (sb.length() <= maxLength)) || (sb.length() == 0))
            super.remove(fb, offset, length);
        else
            Toolkit.getDefaultToolkit().beep();
    }
}





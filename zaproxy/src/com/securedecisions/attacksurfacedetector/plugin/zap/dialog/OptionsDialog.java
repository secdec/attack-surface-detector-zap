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
package com.securedecisions.attacksurfacedetector.plugin.zap.dialog;

import org.apache.commons.io.filefilter.DirectoryFileFilter;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.attacksurfacedetector.ZapPropertiesManager;

import javax.swing.*;
import javax.swing.filechooser.FileFilter;
import javax.swing.filechooser.FileNameExtensionFilter;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.File;

public class OptionsDialog {
    private static final Logger logger = Logger.getLogger(OptionsDialog.class);
    static boolean https;
    static boolean autoSpider;

    public static boolean ValidateSource(final ViewDelegate view)
    {
       if (ZapPropertiesManager.INSTANCE.getTargetUrl() != null && !(ZapPropertiesManager.INSTANCE.getSourceFolder() == null || ZapPropertiesManager.INSTANCE.getSourceFolder().isEmpty()))
          return true;
       else
            return showNotConfigS(view);
    }

    public static boolean ValidateJson(final ViewDelegate view)
    {
        if (ZapPropertiesManager.INSTANCE.getTargetUrl() != null && !(ZapPropertiesManager.INSTANCE.getJsonFile() == null || ZapPropertiesManager.INSTANCE.getJsonFile().isEmpty()))
            return true;
        else
            return showNotConfigE(view);
    }

   public static boolean show(final ViewDelegate view)
   {
        logger.debug("Attempting to show dialog.");
        https = ZapPropertiesManager.INSTANCE.getUseHttps();
        autoSpider = ZapPropertiesManager.INSTANCE.getAutoSpider();
        final JLabel sourceFolderLabel = new JLabel("Source code to analyze:");
        final JTextField sourceFolderField = new JTextField(40);
        sourceFolderField.setText(ZapPropertiesManager.INSTANCE.getSourceFolder());
        final JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = sourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Select a folder or zip file");
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
                if (chooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                    sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

       final JLabel oldSourceFolderLabel = new JLabel("Comparison source code (optional):");
       final JTextField oldSourceFolderField = new JTextField(40);
       oldSourceFolderField.setText(ZapPropertiesManager.INSTANCE.getOldSourceFolder());
       final JButton oldBrowseButton = new JButton("Browse");
       oldBrowseButton.addActionListener(new java.awt.event.ActionListener()
       {
           @Override
           public void actionPerformed(java.awt.event.ActionEvent e)
           {
               JFileChooser oldChooser = new JFileChooser();
               String currentDirectory = oldSourceFolderField.getText();
               if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                   currentDirectory = System.getProperty("user.home");
               }
               oldChooser.setCurrentDirectory(new java.io.File(currentDirectory));
               oldChooser.setDialogTitle("Select a folder or zip file");
               oldChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
               oldChooser.setAcceptAllFileFilterUsed(false);
               oldChooser.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
               oldChooser.addChoosableFileFilter( new FileNameExtensionFilter("*.war | Web application archive", "war"));
               oldChooser.addChoosableFileFilter( new FileFilter()
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
               if (oldChooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                   oldSourceFolderField.setText(oldChooser.getSelectedFile().getAbsolutePath());
           }
       });

       final JLabel jsonFileLabel = new JLabel("Endpoint JSON to analyze:");
       final JTextField jsonFileField = new JTextField(40);
       jsonFileField.setText(ZapPropertiesManager.INSTANCE.getJsonFile());
       final JButton jsonButton = new JButton("Browse");
       jsonButton.addActionListener(new java.awt.event.ActionListener()
       {
           @Override
           public void actionPerformed(java.awt.event.ActionEvent e)
           {
               JFileChooser chooser = new JFileChooser();
               String currentDirectory = jsonFileField.getText();
               if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                   currentDirectory = System.getProperty("user.home");
               }
               chooser.setCurrentDirectory(new java.io.File(currentDirectory));
               chooser.setDialogTitle("Select endpoint JSON file");
               chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
               chooser.setAcceptAllFileFilterUsed(false);
               chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));

               if (chooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                   jsonFileField.setText(chooser.getSelectedFile().getAbsolutePath());
           }
       });

       final JLabel oldJsonFileLabel = new JLabel("Comparison endpoint JSON (optional):");
       final JTextField oldJsonFileField = new JTextField(40);
       oldJsonFileField.setText(ZapPropertiesManager.INSTANCE.getOldJsonFile());
       final JButton oldJsonBrowseButton = new JButton("Browse");
       oldJsonBrowseButton.addActionListener(new java.awt.event.ActionListener()
       {
           @Override
           public void actionPerformed(java.awt.event.ActionEvent e)
           {
               JFileChooser oldChooser = new JFileChooser();
               String currentDirectory = oldJsonFileField.getText();
               if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                   currentDirectory = System.getProperty("user.home");
               }
               oldChooser.setCurrentDirectory(new java.io.File(currentDirectory));
               oldChooser.setDialogTitle("Select endpoint JSON file");
               oldChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
               oldChooser.setAcceptAllFileFilterUsed(false);
               oldChooser.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));
               if (oldChooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                   oldJsonFileField.setText(oldChooser.getSelectedFile().getAbsolutePath());
           }
       });

        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField(40);
        hostField.setText(ZapPropertiesManager.INSTANCE.getTargetHost());

        JLabel portLabel = new JLabel("Port:");
        JTextField portField = new JTextField(40);
        portField.setText(ZapPropertiesManager.INSTANCE.getTargetPort());
        PlainDocument portDoc = (PlainDocument)portField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());

        JLabel pathLabel = new JLabel("Path (optional):");
        JTextField pathField = new JTextField(40);
        pathField.setText(ZapPropertiesManager.INSTANCE.getTargetPath());

        JLabel httpsLabel = new JLabel("Use HTTPS");
        JCheckBox httpsField = new JCheckBox();
        httpsField.setSelected(https);

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e) {
                https = httpsField.isSelected();
            }
        };

        httpsField.addActionListener(applicationCheckBoxHttpActionListener);
        JLabel autoSpiderLabel = new JLabel("Automatically start spider after importing endpoints");
        JCheckBox autoSpiderField = new JCheckBox();
        autoSpiderField.setSelected(autoSpider);
        ActionListener applicationCheckBoxSpiderActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoSpider = autoSpiderField.isSelected();
            }
        };
        autoSpiderField.addActionListener(applicationCheckBoxSpiderActionListener);

        int y = 0;

        GridBagLayout experimentLayout = new GridBagLayout();
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.weightx = 1;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        GridBagConstraints browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = y++;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel myPanel = new JPanel();
        myPanel.setLayout(experimentLayout);
        myPanel.add(sourceFolderLabel, labelConstraints);
        myPanel.add(sourceFolderField, textBoxConstraints);
        myPanel.add(browseButton, browseButtonConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = y++;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(oldSourceFolderLabel, labelConstraints);
        myPanel.add(oldSourceFolderField, textBoxConstraints);
        myPanel.add(oldBrowseButton, browseButtonConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = y++;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(jsonFileLabel, labelConstraints);
        myPanel.add(jsonFileField, textBoxConstraints);
        myPanel.add(jsonButton, browseButtonConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = y++;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(oldJsonFileLabel, labelConstraints);
        myPanel.add(oldJsonFileField, textBoxConstraints);
        myPanel.add(oldJsonBrowseButton, browseButtonConstraints);

        GridBagLayout mainLayout = new GridBagLayout();
        JPanel basePanel = new JPanel(mainLayout);

        GridBagLayout optionsLayout = new GridBagLayout();
        JPanel optionsPanel = new JPanel(optionsLayout);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = y++;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(hostLabel, labelConstraints);
        myPanel.add(hostField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        myPanel.add(portLabel, labelConstraints);
        myPanel.add(portField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = y;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = y;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        myPanel.add(pathLabel, labelConstraints);
        myPanel.add(pathField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.anchor = GridBagConstraints.WEST;
        textBoxConstraints.weightx = 1;

        optionsPanel.add(httpsField, labelConstraints);
        optionsPanel.add(httpsLabel, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.anchor = GridBagConstraints.WEST;
        textBoxConstraints.weightx = 1;

        optionsPanel.add(autoSpiderField, labelConstraints);
        optionsPanel.add(autoSpiderLabel, textBoxConstraints);

        GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        basePanel.add(myPanel, panelConstraints);

        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 1;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(optionsPanel, panelConstraints);

        Object[] options1 = { "Submit", "Reset",
                "Cancel" };
        int result = JOptionPane.showOptionDialog(view.getMainFrame(), basePanel, "Attack Surface Detector",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE,
                null, options1, null);
        if (result == JOptionPane.YES_OPTION)
        {
            ZapPropertiesManager.setTargetHost(hostField.getText());
            ZapPropertiesManager.setTargetPath(pathField.getText());
            ZapPropertiesManager.setTargetPort(portField.getText());
            ZapPropertiesManager.setUseHttps(https);
            ZapPropertiesManager.setAutoSpider(autoSpider);
            ZapPropertiesManager.setSourceFolder(sourceFolderField.getText());
            ZapPropertiesManager.setOldSourceFolder(oldSourceFolderField.getText());
            ZapPropertiesManager.setJsonFile(jsonFileField.getText());
            ZapPropertiesManager.setOldJsonFile(oldJsonFileField.getText());

            return true;
        }
        else if(result == JOptionPane.NO_OPTION)
            return show(view);
        else
            return false;
    }

    public static boolean showNotConfigS(final ViewDelegate view)
    {
        logger.debug("Attempting to show dialog.");
        https = ZapPropertiesManager.INSTANCE.getUseHttps();
        autoSpider = ZapPropertiesManager.INSTANCE.getAutoSpider();
        final JLabel sourceFolderLabel = new JLabel("Source code to analyze:");
        final JTextField sourceFolderField = new JTextField(40);
        sourceFolderField.setText(ZapPropertiesManager.INSTANCE.getSourceFolder());
        final JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = sourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Select a folder or zip file");
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
                if (chooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                    sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        final JLabel oldSourceFolderLabel = new JLabel("Comparison source code (optional):");
        final JTextField oldSourceFolderField = new JTextField(40);
        oldSourceFolderField.setText(ZapPropertiesManager.INSTANCE.getOldSourceFolder());
        final JButton oldBrowseButton = new JButton("Browse");
        oldBrowseButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser oldChooser = new JFileChooser();
                String currentDirectory = oldSourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                oldChooser.setCurrentDirectory(new java.io.File(currentDirectory));
                oldChooser.setDialogTitle("Select a folder or zip file");
                oldChooser.setFileSelectionMode(JFileChooser.FILES_AND_DIRECTORIES);
                oldChooser.setAcceptAllFileFilterUsed(false);
                oldChooser.addChoosableFileFilter( new FileNameExtensionFilter("*.zip | ZIP archive", "zip"));
                oldChooser.addChoosableFileFilter( new FileNameExtensionFilter("*.war | Web application archive", "war"));
                oldChooser.addChoosableFileFilter( new FileFilter()
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
                if (oldChooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                    oldSourceFolderField.setText(oldChooser.getSelectedFile().getAbsolutePath());
            }
        });

        JLabel warningLabel = new JLabel();
        if(ZapPropertiesManager.INSTANCE.getSourceFolder() == null || ZapPropertiesManager.INSTANCE.getSourceFolder().isEmpty())
            warningLabel.setText("Source code is required to import endpoints from source");
        else
            warningLabel.setText("URL configuration is required to populate the site map with the detected endpoints");
        JPanel warningPanel = new JPanel();
        warningPanel.add(warningLabel);

        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField(40);
        hostField.setText(ZapPropertiesManager.INSTANCE.getTargetHost());

        JLabel portLabel = new JLabel("Port:");
        JTextField portField = new JTextField(40);
        portField.setText(ZapPropertiesManager.INSTANCE.getTargetPort());
        PlainDocument portDoc = (PlainDocument)portField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());

        JLabel pathLabel = new JLabel("Path (optional):");
        JTextField pathField = new JTextField(40);
        pathField.setText(ZapPropertiesManager.INSTANCE.getTargetPath());

        JLabel httpsLabel = new JLabel("Use HTTPS");
        JCheckBox httpsField = new JCheckBox();
        httpsField.setSelected(https);

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e) {
                https = httpsField.isSelected();
            }
        };

        httpsField.addActionListener(applicationCheckBoxHttpActionListener);
        JLabel autoSpiderLabel = new JLabel("Automatically start spider after importing endpoints");
        JCheckBox autoSpiderField = new JCheckBox();
        autoSpiderField.setSelected(autoSpider);
        ActionListener applicationCheckBoxSpiderActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoSpider = autoSpiderField.isSelected();
            }
        };
        autoSpiderField.addActionListener(applicationCheckBoxSpiderActionListener);

        GridBagLayout experimentLayout = new GridBagLayout();
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.weightx = 1;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        GridBagConstraints browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 0;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel myPanel = new JPanel();
        myPanel.setLayout(experimentLayout);
        myPanel.add(sourceFolderLabel, labelConstraints);
        myPanel.add(sourceFolderField, textBoxConstraints);
        myPanel.add(browseButton, browseButtonConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 1;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(oldSourceFolderLabel, labelConstraints);
        myPanel.add(oldSourceFolderField, textBoxConstraints);
        myPanel.add(oldBrowseButton, browseButtonConstraints);

        GridBagLayout mainLayout = new GridBagLayout();
        JPanel basePanel = new JPanel(mainLayout);

        GridBagLayout optionsLayout = new GridBagLayout();
        JPanel optionsPanel = new JPanel(optionsLayout);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 2;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 2;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 2;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(hostLabel, labelConstraints);
        myPanel.add(hostField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 3;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 3;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 3;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(portLabel, labelConstraints);
        myPanel.add(portField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 4;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 4;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 4;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(pathLabel, labelConstraints);
        myPanel.add(pathField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.anchor = GridBagConstraints.WEST;
        textBoxConstraints.weightx = 1;

        optionsPanel.add(httpsField, labelConstraints);
        optionsPanel.add(httpsLabel, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.anchor = GridBagConstraints.WEST;
        textBoxConstraints.weightx = 1;

        optionsPanel.add(autoSpiderField, labelConstraints);
        optionsPanel.add(autoSpiderLabel, textBoxConstraints);

        GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(warningPanel, panelConstraints);

        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 1;
        basePanel.add(myPanel, panelConstraints);

        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 2;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(optionsPanel, panelConstraints);

        Object[] options1 = { "Submit", "Reset", "Cancel" };
        int result = JOptionPane.showOptionDialog(view.getMainFrame(), basePanel, "Attack Surface Detector",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE,
                null, options1, null);
        if (result == JOptionPane.YES_OPTION)
        {
            ZapPropertiesManager.setTargetHost(hostField.getText());
            ZapPropertiesManager.setTargetPath(pathField.getText());
            ZapPropertiesManager.setTargetPort(portField.getText());
            ZapPropertiesManager.setUseHttps(https);
            ZapPropertiesManager.setAutoSpider(autoSpider);
            ZapPropertiesManager.setSourceFolder(sourceFolderField.getText());
            ZapPropertiesManager.setOldSourceFolder(oldSourceFolderField.getText());

            return true;
        }
        else if(result == JOptionPane.NO_OPTION)
            return showNotConfigS(view);
        else
            return false;
    }

    public static boolean showNotConfigE(final ViewDelegate view)
    {
        logger.debug("Attempting to show dialog.");
        https = ZapPropertiesManager.INSTANCE.getUseHttps();
        autoSpider = ZapPropertiesManager.INSTANCE.getAutoSpider();
        final JLabel jsonFileLabel = new JLabel("Endpoint JSON to analyze:");
        final JTextField jsonFileField = new JTextField(40);
        jsonFileField.setText(ZapPropertiesManager.INSTANCE.getJsonFile());
        final JButton jsonButton = new JButton("Browse");
        jsonButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = jsonFileField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Select endpoint JSON file");
                chooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                chooser.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));

                if (chooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                    jsonFileField.setText(chooser.getSelectedFile().getAbsolutePath());
            }
        });

        final JLabel oldJsonFileLabel = new JLabel("Comparison endpoint JSON (optional):");
        final JTextField oldJsonFileField = new JTextField(40);
        oldJsonFileField.setText(ZapPropertiesManager.INSTANCE.getOldJsonFile());
        final JButton oldJsonBrowseButton = new JButton("Browse");
        oldJsonBrowseButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                JFileChooser oldChooser = new JFileChooser();
                String currentDirectory = oldJsonFileField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                oldChooser.setCurrentDirectory(new java.io.File(currentDirectory));
                oldChooser.setDialogTitle("Select endpoint JSON file");
                oldChooser.setFileSelectionMode(JFileChooser.FILES_ONLY);
                oldChooser.setAcceptAllFileFilterUsed(false);
                oldChooser.addChoosableFileFilter( new FileNameExtensionFilter("*.json | JSON File", "json"));
                if (oldChooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION)
                    oldJsonFileField.setText(oldChooser.getSelectedFile().getAbsolutePath());
            }
        });

        JLabel warningLabel = new JLabel();
        if(ZapPropertiesManager.INSTANCE.getJsonFile() == null || ZapPropertiesManager.INSTANCE.getJsonFile().isEmpty())
            warningLabel.setText("JSON file is required to import endpoints from Attack Surface Detector CLI");
        else
            warningLabel.setText("URL configuration is required to populate the site map with the detected endpoints");
        JPanel warningPanel = new JPanel();
        warningPanel.add(warningLabel);

        JLabel hostLabel = new JLabel("Host:");
        JTextField hostField = new JTextField(40);
        hostField.setText(ZapPropertiesManager.INSTANCE.getTargetHost());

        JLabel portLabel = new JLabel("Port:");
        JTextField portField = new JTextField(40);
        portField.setText(ZapPropertiesManager.INSTANCE.getTargetPort());
        PlainDocument portDoc = (PlainDocument)portField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());

        JLabel pathLabel = new JLabel("Path (optional):");
        JTextField pathField = new JTextField(40);
        pathField.setText(ZapPropertiesManager.INSTANCE.getTargetPath());

        JLabel httpsLabel = new JLabel("Use HTTPS");
        JCheckBox httpsField = new JCheckBox();
        httpsField.setSelected(https);

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e) {
                https = httpsField.isSelected();
            }
        };

        httpsField.addActionListener(applicationCheckBoxHttpActionListener);
        JLabel autoSpiderLabel = new JLabel("Automatically start spider after importing endpoints");
        JCheckBox autoSpiderField = new JCheckBox();
        autoSpiderField.setSelected(autoSpider);
        ActionListener applicationCheckBoxSpiderActionListener = new ActionListener()
        {
            @Override
            public void actionPerformed(ActionEvent e) {
                autoSpider = autoSpiderField.isSelected();
            }
        };
        autoSpiderField.addActionListener(applicationCheckBoxSpiderActionListener);

        GridBagLayout experimentLayout = new GridBagLayout();
        GridBagConstraints labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.weightx = 1;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        GridBagConstraints browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 0;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        JPanel myPanel = new JPanel();
        myPanel.setLayout(experimentLayout);
        myPanel.add(jsonFileLabel, labelConstraints);
        myPanel.add(jsonFileField, textBoxConstraints);
        myPanel.add(jsonButton, browseButtonConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 1;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(oldJsonFileLabel, labelConstraints);
        myPanel.add(oldJsonFileField, textBoxConstraints);
        myPanel.add(oldJsonBrowseButton, browseButtonConstraints);

        GridBagLayout mainLayout = new GridBagLayout();
        JPanel basePanel = new JPanel(mainLayout);

        GridBagLayout optionsLayout = new GridBagLayout();
        JPanel optionsPanel = new JPanel(optionsLayout);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 2;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 2;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 2;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(hostLabel, labelConstraints);
        myPanel.add(hostField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 3;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 3;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 3;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(portLabel, labelConstraints);
        myPanel.add(portField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 4;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 4;
        textBoxConstraints.anchor = GridBagConstraints.WEST;

        browseButtonConstraints = new GridBagConstraints();
        browseButtonConstraints.gridwidth = 1;
        browseButtonConstraints.gridx = 5;
        browseButtonConstraints.gridy = 4;
        browseButtonConstraints.fill = GridBagConstraints.HORIZONTAL;

        myPanel.add(pathLabel, labelConstraints);
        myPanel.add(pathField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.anchor = GridBagConstraints.WEST;
        textBoxConstraints.weightx = 1;

        optionsPanel.add(httpsField, labelConstraints);
        optionsPanel.add(httpsLabel, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;

        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.anchor = GridBagConstraints.WEST;
        textBoxConstraints.weightx = 1;

        optionsPanel.add(autoSpiderField, labelConstraints);
        optionsPanel.add(autoSpiderLabel, textBoxConstraints);

        GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(warningPanel, panelConstraints);

        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 1;
        basePanel.add(myPanel, panelConstraints);

        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 2;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(optionsPanel, panelConstraints);

        Object[] options1 = { "Submit", "Reset", "Cancel" };
        int result = JOptionPane.showOptionDialog(view.getMainFrame(), basePanel, "Attack Surface Detector",
                JOptionPane.YES_NO_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE,
                null, options1, null);
        if (result == JOptionPane.YES_OPTION)
        {
            ZapPropertiesManager.setTargetHost(hostField.getText());
            ZapPropertiesManager.setTargetPath(pathField.getText());
            ZapPropertiesManager.setTargetPort(portField.getText());
            ZapPropertiesManager.setUseHttps(https);
            ZapPropertiesManager.setAutoSpider(autoSpider);
            ZapPropertiesManager.setJsonFile(jsonFileField.getText());
            ZapPropertiesManager.setOldJsonFile(oldJsonFileField.getText());

            return true;
        }
        else if(result == JOptionPane.NO_OPTION)
            return showNotConfigE(view);
        else
            return false;
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
        } catch (NumberFormatException e) {
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

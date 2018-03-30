package com.denimgroup.threadfix.plugin.zap.dialog;

import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

import javax.swing.*;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;

public class OptionsDialog {
    private static final Logger logger = Logger.getLogger(SourceDialog.class);
    static boolean https;
    static boolean autoSpider;

    public static boolean Validate(final ViewDelegate view)
   {
       if (ZapPropertiesManager.INSTANCE.getTargetUrl() != null && !(ZapPropertiesManager.INSTANCE.getSourceFolder() == null || ZapPropertiesManager.INSTANCE.getSourceFolder().isEmpty()))
          return true;
       else
            return show(view);
   }

    public static boolean show(final ViewDelegate view) {
        logger.info("Attempting to show dialog.");
        https = ZapPropertiesManager.INSTANCE.getUseHttps();
        autoSpider = ZapPropertiesManager.INSTANCE.getAutoSpider();
        final JLabel sourceFolderLabel = new JLabel("Source Code Folder");
        final JTextField sourceFolderField = new JTextField(40);
        sourceFolderField.setText(ZapPropertiesManager.INSTANCE.getSourceFolder());
        final JButton browseButton = new JButton("Browse");
        browseButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JFileChooser chooser = new JFileChooser();
                String currentDirectory = sourceFolderField.getText();
                if ((currentDirectory == null) || (currentDirectory.trim().equals(""))) {
                    currentDirectory = System.getProperty("user.home");
                }
                chooser.setCurrentDirectory(new java.io.File(currentDirectory));
                chooser.setDialogTitle("Select A Source Code Folder");
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setAcceptAllFileFilterUsed(false);
                if (chooser.showOpenDialog(view.getMainFrame()) == JFileChooser.APPROVE_OPTION) {
                    sourceFolderField.setText(chooser.getSelectedFile().getAbsolutePath());
                }
            }
        });


        JLabel hostLabel = new JLabel("Host");
        JTextField hostField = new JTextField(ZapPropertiesManager.INSTANCE.getTargetHost());

        JLabel portLabel = new JLabel("Port");
        JTextField portField = new JTextField(ZapPropertiesManager.INSTANCE.getTargetPort());
        PlainDocument portDoc = (PlainDocument)portField.getDocument();
        portDoc.setDocumentFilter(new PortFilter());

        JLabel pathLabel = new JLabel("Path (optional)");
        JTextField pathField = new JTextField(ZapPropertiesManager.INSTANCE.getTargetPath());

        JLabel httpsLabel = new JLabel("use Https");
        JCheckBox httpsField = new JCheckBox();
        httpsField.setSelected(https);

        ActionListener applicationCheckBoxHttpActionListener = new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                https = httpsField.isSelected();
            }
        };

        httpsField.addActionListener(applicationCheckBoxHttpActionListener);


        JLabel autoSpiderLabel = new JLabel("Automatically start spider after importing endpoints: ");
        JCheckBox autoSpiderField = new JCheckBox();
        autoSpiderField.setSelected(autoSpider);

        ActionListener applicationCheckBoxSpiderActionListener = new ActionListener() {
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
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;

        GridBagConstraints textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;

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

        GridBagLayout mainLayout = new GridBagLayout();
        JPanel basePanel = new JPanel(mainLayout);



        GridBagLayout optionsLayout = new GridBagLayout();
        JPanel optionsPanel = new JPanel(optionsLayout);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 0;
        labelConstraints.weightx = 1.0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.anchor = GridBagConstraints.WEST;


        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 0;
        textBoxConstraints.weighty = 1.0;
        textBoxConstraints.weightx = 1.0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints.anchor = GridBagConstraints.EAST;

        optionsPanel.add(hostLabel, labelConstraints);
        optionsPanel.add(hostField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 1;
        labelConstraints.weightx = 1.0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.anchor = GridBagConstraints.WEST;


        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 1;
        textBoxConstraints.weighty = 1.0;
        textBoxConstraints.weightx = 1.0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints.anchor = GridBagConstraints.EAST;

        optionsPanel.add(portLabel, labelConstraints);
        optionsPanel.add(portField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 2;
        labelConstraints.weightx = 1.0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.anchor = GridBagConstraints.WEST;


        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 2;
        textBoxConstraints.weighty = 1.0;
        textBoxConstraints.weightx = 1.0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints.anchor = GridBagConstraints.EAST;

        optionsPanel.add(pathLabel, labelConstraints);
        optionsPanel.add(pathField, textBoxConstraints);

        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 3;
        labelConstraints.weightx = 1.0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.anchor = GridBagConstraints.WEST;


        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 3;
        textBoxConstraints.weighty = 1.0;
        textBoxConstraints.weightx = 1.0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints.anchor = GridBagConstraints.EAST;

        optionsPanel.add(httpsLabel, labelConstraints);
        optionsPanel.add(httpsField, textBoxConstraints);


        labelConstraints = new GridBagConstraints();
        labelConstraints.gridwidth = 1;
        labelConstraints.gridx = 0;
        labelConstraints.gridy = 4;
        labelConstraints.weightx = 1.0;
        labelConstraints.fill = GridBagConstraints.HORIZONTAL;
        labelConstraints.anchor = GridBagConstraints.WEST;


        textBoxConstraints = new GridBagConstraints();
        textBoxConstraints.gridwidth = 4;
        textBoxConstraints.gridx = 1;
        textBoxConstraints.gridy = 4;
        textBoxConstraints.weighty = 1.0;
        textBoxConstraints.weightx = 1.0;
        textBoxConstraints.fill = GridBagConstraints.HORIZONTAL;
        textBoxConstraints.anchor = GridBagConstraints.EAST;

        optionsPanel.add(autoSpiderLabel, labelConstraints);
        optionsPanel.add(autoSpiderField, textBoxConstraints);



        GridBagConstraints panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 0;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(myPanel, panelConstraints);



        panelConstraints = new GridBagConstraints();
        panelConstraints.gridwidth = 1;
        panelConstraints.gridx = 0;
        panelConstraints.gridy = 1;
        panelConstraints.fill = GridBagConstraints.HORIZONTAL;
        basePanel.add(optionsPanel, panelConstraints);

        Object[] options1 = { "Submit", "Cancel",
                "Reset" };
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

            return true;
        }
        else if(result == JOptionPane.NO_OPTION)
        {
            return false;
        }
        else
        {
            return show(view);
        }

    }
}

class PortFilter extends DocumentFilter {
    static final int maxLength = 5;
    @Override
    public void insertString(FilterBypass fb, int offset, String string,
                             AttributeSet attr) throws BadLocationException {
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.insert(offset, string);
        int val = Integer.parseInt(sb.toString());

        if (test(sb.toString()) && sb.length() <= maxLength && val <= 65535) {
            super.insertString(fb, offset, string, attr);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }
    }

    private boolean test(String text) {
        try {
            Integer.parseInt(text);
            return true;
        } catch (NumberFormatException e) {
            return false;
        }
    }

    @Override
    public void replace(FilterBypass fb, int offset, int length, String text,
                        AttributeSet attrs) throws BadLocationException {

        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.replace(offset, offset + length, text);
        int val = Integer.parseInt(sb.toString());

        if (test(sb.toString()) && (sb.length() <= maxLength) && val <= 65535) {
            super.replace(fb, offset, length, text, attrs);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }

    }

    @Override
    public void remove(FilterBypass fb, int offset, int length)
            throws BadLocationException {
        Document doc = fb.getDocument();
        StringBuilder sb = new StringBuilder();
        sb.append(doc.getText(0, doc.getLength()));
        sb.delete(offset, offset + length);

        if ((test(sb.toString()) && (sb.length() <= maxLength)) || (sb.length() == 0)) {
            super.remove(fb, offset, length);
        } else {
            Toolkit.getDefaultToolkit().beep();
        }

    }
}

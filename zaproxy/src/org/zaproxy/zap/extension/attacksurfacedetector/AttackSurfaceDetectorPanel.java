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
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;
import java.util.List;

import javax.swing.*;

import com.denimgroup.threadfix.data.enums.ParameterDataType;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.util.EndpointUtil;
import com.securedecisions.attacksurfacedetector.plugin.zap.action.AttackThread;
import com.securedecisions.attacksurfacedetector.plugin.zap.action.LocalEndpointsAction;
import com.securedecisions.attacksurfacedetector.plugin.zap.dialog.OptionsDialog;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;

import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import static com.securedecisions.attacksurfacedetector.plugin.zap.action.EndpointsAction.GENERIC_INT_SEGMENT;

/**
 * This class creates the Spider AJAX Panel where the found URLs are displayed
 * It has a button to stop the crawler and another one to open the options.
 *
 */
public class AttackSurfaceDetectorPanel extends AbstractPanel{
    private static final long serialVersionUID = 1L;
    private javax.swing.JToolBar panelToolbar = null;
    private ViewDelegate view = null;
    private JButton viewSelectedButton;
    private Model model;
    private AttackThread attackThread = null;
    Map<String, String> nodes = new HashMap<String, String>();

    public AttackSurfaceDetectorPanel(ViewDelegate view, final Model model)
    {
        super();
        super.setName("Attack Surface Detector");
        this.model = model;
        this.view = view;
        initialize();
        ImageIcon SECDEC_ICON = new ImageIcon(AttackSurfaceDetector.class.getResource("/org/zaproxy/zap/extension/attacksurfacedetector/resources/secdec-S-16x16.png"));
        this.setIcon(SECDEC_ICON);
    }

    private  void initialize()
    {
        this.setLayout(new BorderLayout());
        this.setSize(600, 200);

        JPanel basePanel = new JPanel();
        basePanel.setLayout(new java.awt.GridBagLayout());
        basePanel.setName("Attack Surface Detector");

        GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
        GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
        gridBagConstraints1.gridx = 0;
        gridBagConstraints1.gridy = 0;
        gridBagConstraints1.weightx = 1.0D;
        gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
        gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
        gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;

        basePanel.add(buildToolBar(),gridBagConstraints1);
        JTable endPointsTable = buildEndpointsTable();
        ZapPropertiesManager.INSTANCE.setEndpointsTable(endPointsTable);
        JScrollPane scrollPane = new JScrollPane(endPointsTable);

        gridBagConstraints2.gridx = 0;
        gridBagConstraints2.gridy = 1;
        gridBagConstraints2.weightx = 1.0;
        gridBagConstraints2.weighty = 1.0;
        gridBagConstraints2.insets = new java.awt.Insets(4,4,4,4);
        gridBagConstraints2.fill = java.awt.GridBagConstraints.BOTH;
        gridBagConstraints2.anchor = java.awt.GridBagConstraints.NORTHWEST;
        basePanel.add(scrollPane,gridBagConstraints2);
        this.add(basePanel, java.awt.BorderLayout.CENTER);
    }

    private javax.swing.JToolBar buildToolBar()
    {
        panelToolbar = new javax.swing.JToolBar();
        panelToolbar.setLayout(new java.awt.GridBagLayout());
        panelToolbar.setEnabled(true);
        panelToolbar.setFloatable(false);
        panelToolbar.setRollover(true);
        panelToolbar.setPreferredSize(new java.awt.Dimension(1000,30));
        panelToolbar.setFont(new java.awt.Font("Dialog", java.awt.Font.PLAIN, 12));
        panelToolbar.setName("Attack Surface Detector");

        JButton importButton = new JButton("Import Endpoints from Source");
        viewSelectedButton = new JButton("View Selected");
        viewSelectedButton.setEnabled(false);
        ZapPropertiesManager.INSTANCE.setViewSelectedButton(viewSelectedButton);
        JButton optionsButton = new JButton("Options");
        importButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                boolean configured = OptionsDialog.Validate(view);
                boolean completed = false;
                viewSelectedButton.setEnabled(false);
                ZapPropertiesManager.INSTANCE.setEndpointDecorator(null);
                if (configured)
                {
                    EndpointDecorator[] endpoints = getEndpoints(ZapPropertiesManager.INSTANCE.getSourceFolder());
                    EndpointDecorator comparePoints[] = null;
                    String oldSourceFolder = ZapPropertiesManager.INSTANCE.getOldSourceFolder();
                    if(oldSourceFolder != null && !oldSourceFolder.isEmpty())
                        comparePoints = getEndpoints(oldSourceFolder);

                    if ((endpoints == null) || (endpoints.length == 0))
                        view.showWarningDialog("Failed to retrieve endpoints from the source. Check your inputs.");
                    else
                    {
                        if (comparePoints != null && comparePoints.length !=0)
                            endpoints = compareEndpoints(endpoints, comparePoints, view);

                        fillEndpointsToTable(endpoints);
                        buildNodesFromEndpoints(endpoints);
                        String url = ZapPropertiesManager.INSTANCE.getTargetUrl();
                        if (url != null)
                        { // cancel not pressed
                            completed = attackUrl(url, view);
                            if (!completed)
                                view.showWarningDialog("Invalid URL.");
                        }
                        else
                            view.showMessageDialog("The endpoints were successfully generated from source.");
                    }
                }
                if (completed)
                    view.showMessageDialog("The endpoints were successfully generated from source.");
            }
        });
        optionsButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) { boolean shouldContinue = OptionsDialog.show(view); }
        });
        viewSelectedButton.addActionListener(new java.awt.event.ActionListener()
        {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JPanel detailPanel = new JPanel();
                detailPanel.setLayout(new GridBagLayout());
                JLabel displayArea = new JLabel();
                String displayStr = new String();
                int y = 0;
                GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
                gridBagConstraints1.gridx = 0;
                gridBagConstraints1.gridy = y++;
                gridBagConstraints1.weightx = 1.0D;
                gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
                gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
                gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
                EndpointDecorator decorator = ZapPropertiesManager.INSTANCE.getEndpointDecorator();
                Endpoint.Info endpoint = decorator.getEndpoint();

                if(endpoint != null)
                {

                    if(decorator.getStatus() == EndpointDecorator.Status.NEW)
                    {
                        displayStr = "<html><b>New Endpoint</b><br>";
                        displayStr = displayStr + "URL:<br>";
                    }
                    else
                        displayStr = displayStr + "<html> URL:<br>";

                    displayStr = displayStr + "" + endpoint.getUrlPath() + "<br><br>Methods:<br>";
                    // TODO - Gather all Endpoint objects pointing to the same endpoint and output their HTTP methods (Endpoints only have
                    //  one HTTP method at a time now)
                    if(endpoint.getHttpMethod().length() >4)
                        displayStr = displayStr + endpoint.getHttpMethod().substring(14);
                    else
                        displayStr = displayStr + endpoint.getHttpMethod();


                    displayStr = displayStr +"<br>Parameters and type:<br>";
                    if(decorator.getStatus() == EndpointDecorator.Status.CHANGED)
                    {
                        for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                        {   boolean found = false;
                            for (Map.Entry<String, RouteParameter> compParameter : decorator.getComparePoint().getParameters().entrySet())
                            {
                                if (parameter.getKey().equalsIgnoreCase(compParameter.getKey()))
                                {
                                    found = true;
                                    if(!parameter.getValue().getDataType().getDisplayName().equals(compParameter.getValue().getDataType().getDisplayName()))
                                        displayStr = displayStr + "<strong>" + parameter.getKey() + " - " + compParameter.getValue().getDataType().getDisplayName().toUpperCase() + " -> " + parameter.getValue().getDataType().getDisplayName().toUpperCase()+"</strong> (modified parameter type) <br>";
                                    else
                                        displayStr = displayStr + parameter.getKey() + " - "+ parameter.getValue().getDataType().getDisplayName() + "<br>";
                                    break;
                                }
                            }
                            if (!found)
                                displayStr = displayStr + "<strong>" + parameter.getKey() + "</strong> - <strong>" + parameter.getValue().getDataType().getDisplayName().toUpperCase() + "</strong> (added parameter)<br>";
                        }
                        for (Map.Entry<String, RouteParameter> compParameter : decorator.getComparePoint().getParameters().entrySet())
                        {   boolean found = false;
                            for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                            {
                                if (parameter.getKey().equalsIgnoreCase(compParameter.getKey()))
                                {
                                    found = true;
                                    break;
                                }
                            }
                            if(!found)
                                displayStr = displayStr + "<span style='text-decoration: line-through;'>" +compParameter.getKey() + " - " + compParameter.getValue().getDataType().getDisplayName().toUpperCase() + "</span> (removed parameter)<br>";
                        }
                    }
                    else
                    {
                        for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
                        {
                            displayStr = displayStr + parameter.getKey() + " - "+ parameter.getValue().getDataType().getDisplayName() + "<br>";
                        }
                    }

                    displayStr = displayStr + "</html>";
                    displayArea.setText(displayStr);
                    detailPanel.add(displayArea, gridBagConstraints1);
                }
                else
                    detailPanel.add(new JLabel("No Endpoint Selected"));

                JOptionPane.showMessageDialog(view.getMainFrame(), detailPanel, "Endpoint Details", JOptionPane.INFORMATION_MESSAGE);
            }
        });


        JPanel buttonPanel = new JPanel();
        buttonPanel.setLayout(new GridBagLayout());

        GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
        gridBagConstraints1.gridx = 0;
        gridBagConstraints1.gridy = 0;
        gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
        gridBagConstraints1.anchor = GridBagConstraints.WEST;

        GridBagConstraints gridBagConstraints2 = new GridBagConstraints();
        gridBagConstraints1.gridx = 1;
        gridBagConstraints1.gridy = 0;
        gridBagConstraints1.insets = new java.awt.Insets(0,0,0,0);
        gridBagConstraints1.anchor = GridBagConstraints.WEST;
        gridBagConstraints2.weightx = 1.0;
        gridBagConstraints2.weighty= 1.0;

        GridBagConstraints gridBagConstraints3 = new GridBagConstraints();
        gridBagConstraints1.gridx = 2;
        gridBagConstraints1.gridy = 0;
        gridBagConstraints1.insets = new java.awt.Insets(0,0,0,0);
        gridBagConstraints1.anchor = GridBagConstraints.WEST;

        buttonPanel.add(importButton, gridBagConstraints1);
        buttonPanel.add(viewSelectedButton, gridBagConstraints2);
        buttonPanel.add(optionsButton, gridBagConstraints3);

        GridBagConstraints toolConstraints1 = new GridBagConstraints();
        toolConstraints1.gridx = 0;
        gridBagConstraints1.gridy = 0;
        toolConstraints1.insets = new java.awt.Insets(4,4,4,4);
        toolConstraints1.anchor = GridBagConstraints.WEST;
        toolConstraints1.weightx = 1.0;
        toolConstraints1.weighty= 1.0;

        panelToolbar.add(buttonPanel, toolConstraints1);

        return panelToolbar;
    }

    private JTable buildEndpointsTable()
   {
        Object[][] data = {};
       String[] columnNames = { "Detected Endpoints","Number of Detected Parameters","GET Method","POST Method","New/Modified","Endpoint"};
        DefaultTableModel dtm = new DefaultTableModel(data, columnNames){
         @Override
         public boolean isCellEditable(int row, int column) { return false; }};
        JTable endpointsTable = new JTable(dtm);
        endpointsTable.addMouseListener(new MouseListener()
        {
            @Override
            public void mouseClicked(MouseEvent e)
            {
                EndpointDecorator decorator = (EndpointDecorator)endpointsTable.getModel().getValueAt(endpointsTable.getSelectedRow(), 5);
                if(!viewSelectedButton.isEnabled())
                    viewSelectedButton.setEnabled(true);
                ZapPropertiesManager.INSTANCE.setEndpointDecorator(decorator);
        }
            @Override
            public void mousePressed(MouseEvent e){}
            @Override
            public void mouseReleased(MouseEvent e){}
            @Override
            public void mouseEntered(MouseEvent e){}
            @Override
            public void mouseExited(MouseEvent e){}
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

    private EndpointDecorator[] getEndpoints(String sourceFolder)
    {
        if (sourceFolder== null || sourceFolder.trim().isEmpty())
            return  null;
        EndpointDatabase endpointDatabase = EndpointDatabaseFactory.getDatabase(sourceFolder);
        EndpointDecorator[] endpoints = null;
        if (endpointDatabase != null)
        {
            List<Endpoint> endpointList = endpointDatabase.generateEndpoints();
            endpointList = EndpointUtil.flattenWithVariants(endpointList);
            endpoints = new EndpointDecorator[endpointList.size()];
            int i = 0;
            for (Endpoint endpoint : endpointList)
                endpoints[i++] = new EndpointDecorator(Endpoint.Info.fromEndpoint(endpoint));
        }
        return endpoints;
    }


    public void buildNodesFromEndpoints(EndpointDecorator[] endpoints)
    {
        int count = 0;
        for (EndpointDecorator decorator : endpoints)
        {
            Endpoint.Info endpoint = decorator.getEndpoint();
            String endpointPath = endpoint.getUrlPath();
            if (endpointPath.startsWith("/"))
                endpointPath = endpointPath.substring(1);

            endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");
            boolean first = true;
            String reqString = endpointPath;
            String method = endpoint.getHttpMethod();
            for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
            {
                if (first)
                {
                    first = false;
                    reqString = reqString + "?";
                }
                else
                    reqString = reqString + "&";

                if (parameter.getValue().getDataType() == ParameterDataType.STRING)
                    reqString = reqString + parameter.getKey() + "="+"debug";

                else if (parameter.getValue().getDataType() == ParameterDataType.INTEGER)
                    reqString = reqString + parameter.getKey() + "="+"-1";

                else if (parameter.getValue().getDataType() == ParameterDataType.BOOLEAN)
                    reqString = reqString + parameter.getKey() + "="+"true";

                else if (parameter.getValue().getDataType() == ParameterDataType.DECIMAL)
                    reqString = reqString + parameter.getKey() + "="+".1";

                else if (parameter.getValue().getDataType() == ParameterDataType.DATE_TIME)
                    reqString = reqString + parameter.getKey() + "="+ new Date();

                else if (parameter.getValue().getDataType() == ParameterDataType.LOCAL_DATE)
                    reqString = reqString + parameter.getKey() + "="+new Date();

                else
                    reqString = reqString + parameter.getKey() + "=default";

            }
            reqString = reqString.replace("{", "");
            reqString = reqString.replace("}", "");
            reqString = reqString.replace(" ", "");
            nodes.put(reqString, method);
        }
    }

    public boolean attackUrl(String url,  ViewDelegate view)
    {
        try {
            if(!url.substring(url.length()-1).equals("/"))
                url = url+"/";
            attack(new URL(url), view);
            return true;
        }
        catch (MalformedURLException e1)
        {
            return false;
        }
    }

    private void attack (URL url,  ViewDelegate view)
    {
        if (attackThread != null && attackThread.isAlive())
            return;
        attackThread = new AttackThread(new LocalEndpointsAction(view, model), view);
        attackThread.setNodes(nodes);
        attackThread.setURL(url);
        attackThread.start();
    }

    private void fillEndpointsToTable(EndpointDecorator[] endpoints)
    {
        JTable endpointTable = ZapPropertiesManager.INSTANCE.getEndpointsTable();
        DefaultTableModel dtm = (DefaultTableModel)endpointTable.getModel();
        while(dtm.getRowCount() > 0)
            dtm.removeRow(0);
        for (EndpointDecorator decorator : endpoints)
        {
            Endpoint.Info endpoint = decorator.getEndpoint();
            boolean hasGet = false;
            boolean hasPost = false;
            String method = endpoint.getHttpMethod();
            if(method.toString().equalsIgnoreCase("post"))
                hasPost = true;
            else if (method.toString().equalsIgnoreCase("get"))
                hasGet = true;
            boolean status = (decorator.getStatus() == EndpointDecorator.Status.NEW) || (decorator.getStatus() == EndpointDecorator.Status.CHANGED);
            dtm.addRow(new Object[]{endpoint.getUrlPath(), endpoint.getParameters().size(), hasGet, hasPost, status, decorator});
        }
    }

    private EndpointDecorator[] compareEndpoints(EndpointDecorator[] decorators, EndpointDecorator[] comparePoints, final ViewDelegate view)
    {
        for(EndpointDecorator decorator : decorators)
        {
            EndpointDecorator.Status newStat = EndpointDecorator.Status.NEW;
            for(EndpointDecorator comparePointDec : comparePoints)
            {
                if (decorator.getEndpoint().getUrlPath().equals(comparePointDec.getEndpoint().getUrlPath()) && decorator.getEndpoint().getHttpMethod().equals(comparePointDec.getEndpoint().getHttpMethod()))
                {
                    if (decorator.checkSum() != comparePointDec.checkSum())
                    {
                        newStat = EndpointDecorator.Status.CHANGED;
                        decorator.setComparePoint(comparePointDec.getEndpoint());
                        break;
                    }
                    else
                    {
                        newStat = EndpointDecorator.Status.UNCHANGED;
                        break;
                    }
                }
            }
            decorator.setStatus(newStat);
        }

        return decorators;
    }
}

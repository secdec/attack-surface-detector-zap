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
package org.zaproxy.zap.extension.threadfix;

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
import com.denimgroup.threadfix.plugin.zap.action.AttackThread;
import com.denimgroup.threadfix.plugin.zap.action.LocalEndpointsAction;
import com.denimgroup.threadfix.plugin.zap.dialog.OptionsDialog;
import jdk.nashorn.internal.scripts.JO;
import org.apache.log4j.Logger;
import org.parosproxy.paros.Constant;
import org.parosproxy.paros.control.Control;
import org.parosproxy.paros.control.Control.Mode;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.extension.history.HistoryFilter;
import org.parosproxy.paros.model.HistoryReference;
import org.parosproxy.paros.model.Model;
import org.parosproxy.paros.network.HttpMessage;
import javax.swing.table.DefaultTableModel;
import javax.swing.table.TableColumn;
import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.interfaces.Endpoint;

import static com.denimgroup.threadfix.plugin.zap.action.EndpointsAction.GENERIC_INT_SEGMENT;

/**
 * This class creates the Spider AJAX Panel where the found URLs are displayed
 * It has a button to stop the crawler and another one to open the options.
 *
 */
public class AttackSurfaceDetectorPanel extends AbstractPanel{
    private static final long serialVersionUID = 1L;

    private javax.swing.JScrollPane scrollLog = null;
    private javax.swing.JPanel attackSurfaceDetectorPanel = null;
    private javax.swing.JToolBar panelToolbar = null;
    private JLabel filterStatus = null;
    private JButton stopScanButton;
    private JButton startScanButton;
    private JButton optionsButton = null;
    private ViewDelegate view = null;
    private JButton viewSelectedButton;
    private Model model;
    private AttackThread attackThread = null;
    //List<String> nodes = new ArrayList<>();
    Map<String, String> nodes = new HashMap<String, String>();

    /**
     * This is the default constructor
     */
    public AttackSurfaceDetectorPanel(ViewDelegate view, final Model model) {
        super();
        super.setName("Attack Surface Detector");
        this.model = model;
        this.view = view;
        initialize();
    }

    /**
     * This method initializes this class and its attributes
     *
     */
    private  void initialize() {
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


        //maybe add table to a panel and then add panel to scrollPane?


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

        JButton importButton = new JButton("Import endpoints from source");
        viewSelectedButton = new JButton("View Selected");
        viewSelectedButton.setEnabled(false);
        JButton optionsButton = new JButton("Options");

        importButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {


                boolean configured = OptionsDialog.Validate(view);
                boolean completed = false;
                viewSelectedButton.setEnabled(false);
                if (configured) {
                    Endpoint.Info[] endpoints = getEndpoints(ZapPropertiesManager.INSTANCE.getSourceFolder());

                    if ((endpoints == null) || (endpoints.length == 0)) {
                        view.showWarningDialog("Failed to retrieve endpoints from the source. Check your inputs.");
                    } else {
                        fillEndpointsToTable(endpoints);
                        buildNodesFromEndpoints(endpoints);

                        String url = ZapPropertiesManager.INSTANCE.getTargetUrl();
                        if (url != null) { // cancel not pressed
                            completed = attackUrl(url, view);
                            if (!completed) {
                                view.showWarningDialog("Invalid URL.");
                            }
                        }
                        else
                        {
                            view.showMessageDialog("The endpoints were successfully generated from source.");
                        }
                    }
                }
                if (completed) {
                    view.showMessageDialog("The endpoints were successfully generated from source.");
                }
            }
        });
        optionsButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                boolean shouldContinue = OptionsDialog.show(view);
            }
        });

        viewSelectedButton.addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {
                JPanel detailPanel = new JPanel();
                detailPanel.setLayout(new GridBagLayout());
                int y = 0;
                GridBagConstraints gridBagConstraints1 = new GridBagConstraints();
                gridBagConstraints1.gridx = 0;
                gridBagConstraints1.gridy = y++;
                gridBagConstraints1.weightx = 1.0D;
                gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
                gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
                gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
                Endpoint.Info endpoint = ZapPropertiesManager.INSTANCE.getEndpoint();
                if(endpoint != null)
                {
                    detailPanel.add(new JLabel("URL: " + endpoint.getUrlPath()), gridBagConstraints1);

                    gridBagConstraints1 = new GridBagConstraints();
                    gridBagConstraints1.gridx = 0;
                    gridBagConstraints1.gridy = y++;
                    gridBagConstraints1.weightx = 1.0D;
                    gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
                    gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
                    gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
                    detailPanel.add(new JLabel("Methods: "), gridBagConstraints1);

                    gridBagConstraints1 = new GridBagConstraints();
                    gridBagConstraints1.gridx = 0;
                    gridBagConstraints1.gridy = y++;
                    gridBagConstraints1.weightx = 1.0D;
                    gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
                    gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
                    gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;

                    if (endpoint.getHttpMethod().length() > 4) {
                        detailPanel.add(new JLabel(endpoint.getHttpMethod().substring(14)), gridBagConstraints1);

                    } else
                        detailPanel.add(new JLabel(endpoint.getHttpMethod()), gridBagConstraints1);

                    for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet()) {
                        gridBagConstraints1 = new GridBagConstraints();
                        gridBagConstraints1.gridx = 0;
                        gridBagConstraints1.gridy = y++;
                        gridBagConstraints1.weightx = 1.0D;
                        gridBagConstraints1.insets = new java.awt.Insets(4,4,4,4);
                        gridBagConstraints1.fill = java.awt.GridBagConstraints.HORIZONTAL;
                        gridBagConstraints1.anchor = java.awt.GridBagConstraints.NORTHWEST;
                        detailPanel.add(new JLabel( parameter.getKey() + " - " + parameter.getValue().getDataType().getDisplayName()), gridBagConstraints1);
                    }
                }
                else
                {
                    detailPanel.add(new JLabel("No Endpoint Selected"));

                }

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
        String[] columnNames =
                               {               "Detected Endpoints",
                                               "Number of Detected Parameters",
                                               "GET Method",
                                               "POST Method",
                                               "Endpoint"
                                               };

        DefaultTableModel dtm = new DefaultTableModel(data, columnNames){
            @Override
         public boolean isCellEditable(int row, int column)
         {
              //all cells false
             return false;
         }};

               JTable endpointsTable = new JTable(dtm);
               endpointsTable.addMouseListener(new MouseListener() {
                   @Override
                   public void mouseClicked(MouseEvent e)
                   {
                       Endpoint.Info endpoint = (Endpoint.Info)endpointsTable.getModel().getValueAt(endpointsTable.getSelectedRow(), 4);
                       if(!viewSelectedButton.isEnabled())
                           viewSelectedButton.setEnabled(true);

                       ZapPropertiesManager.INSTANCE.setEndpoint(endpoint);
                   }

                   @Override
                   public void mousePressed(MouseEvent e)
                   {

                   }

                   @Override
                   public void mouseReleased(MouseEvent e)
                   {

                   }

                  @Override
                  public void mouseEntered(MouseEvent e)
                   {

                   }

                   @Override
                   public void mouseExited(MouseEvent e)
                   {

                    }
                       });

               TableColumn tc = endpointsTable.getColumnModel().getColumn(2);
               tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
               tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
               tc = endpointsTable.getColumnModel().getColumn(3);
               tc.setCellEditor(endpointsTable.getDefaultEditor(Boolean.class));
               tc.setCellRenderer(endpointsTable.getDefaultRenderer(Boolean.class));
               endpointsTable.getColumnModel().getColumn(4).setMinWidth(0);
               endpointsTable.getColumnModel().getColumn(4).setMaxWidth(0);
               endpointsTable.getColumnModel().getColumn(4).setWidth(0);

               return endpointsTable;
   }

    private Endpoint.Info[] getEndpoints(String sourceFolder) {
        if (sourceFolder== null || sourceFolder.trim().isEmpty())
            return  null;
        EndpointDatabase endpointDatabase = EndpointDatabaseFactory.getDatabase(sourceFolder);
        Endpoint.Info[] endpoints = null;
        if (endpointDatabase != null) {
            List<Endpoint> endpointList = endpointDatabase.generateEndpoints();
            endpointList = EndpointUtil.flattenWithVariants(endpointList);
            endpoints = new Endpoint.Info[endpointList.size()];
            int i = 0;
            for (Endpoint endpoint : endpointList) {
                endpoints[i++] = Endpoint.Info.fromEndpoint(endpoint);
            }
        }

        return endpoints;
    }

    public void buildNodesFromEndpoints(Endpoint.Info[] endpoints) {
        int count = 0;
        for (Endpoint.Info endpoint : endpoints)
        {
            String endpointPath = endpoint.getUrlPath();
            if (endpointPath.startsWith("/"))
            {
                endpointPath = endpointPath.substring(1);
            }
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
                {
                    reqString = reqString + "&";
                }

                if (parameter.getValue().getDataType() == ParameterDataType.STRING)
                {
                    reqString = reqString + parameter.getKey() + "="+"debug";
                }

                else if (parameter.getValue().getDataType() == ParameterDataType.INTEGER)
                {
                    reqString = reqString + parameter.getKey() + "="+"-1";
                }

                else if (parameter.getValue().getDataType() == ParameterDataType.BOOLEAN)
                {
                    reqString = reqString + parameter.getKey() + "="+"true";
                }
                else if (parameter.getValue().getDataType() == ParameterDataType.DECIMAL)
                {
                    reqString = reqString + parameter.getKey() + "="+".1";
                }
                else if (parameter.getValue().getDataType() == ParameterDataType.DATE_TIME)
                {
                    reqString = reqString + parameter.getKey() + "="+ new Date();
                }
                else if (parameter.getValue().getDataType() == ParameterDataType.LOCAL_DATE)
                {
                    reqString = reqString + parameter.getKey() + "="+new Date();
                }
                else
                {
                    reqString = reqString + parameter.getKey() + "=default";
                }
            }
            reqString = reqString.replace("{", "");
            reqString = reqString.replace("}", "");
            reqString = reqString.replace(" ", "");
            nodes.put(reqString, method);

        }
    }

    public boolean attackUrl(String url,  ViewDelegate view) {
        try {
            if(!url.substring(url.length()-1).equals("/")){
                url = url+"/";
            }
            attack(new URL(url), view);
            return true;
        } catch (MalformedURLException e1) {
            return false;
        }
    }

    private void attack (URL url,  ViewDelegate view) {
        if (attackThread != null && attackThread.isAlive()) {
            return;
        }
        attackThread = new AttackThread(new LocalEndpointsAction(view, model), view);
        attackThread.setNodes(nodes);
        attackThread.setURL(url);
        attackThread.start();

    }

    private void fillEndpointsToTable(Endpoint.Info[] endpoints)
    {
        int count = 0;
        JTable endpointTable = ZapPropertiesManager.INSTANCE.getEndpointsTable();
        DefaultTableModel dtm = (DefaultTableModel)endpointTable.getModel();
        while(dtm.getRowCount() > 0)
        {
            dtm.removeRow(0);
        }
        for (Endpoint.Info endpoint : endpoints)
        {
            boolean hasGet = false;
            boolean hasPost = false;
            String method = endpoint.getHttpMethod();
            if(method.toString().equalsIgnoreCase("post"))
                hasPost = true;
            else if (method.toString().equalsIgnoreCase("get"))
                hasGet = true;
            dtm.addRow(new Object[]
                    {
                            endpoint.getUrlPath(),
                            endpoint.getParameters().size(),
                            hasGet,
                            hasPost,
                            endpoint
                    });
            count++;
        }

    }


}

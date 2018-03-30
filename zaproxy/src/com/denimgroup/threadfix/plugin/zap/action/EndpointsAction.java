////////////////////////////////////////////////////////////////////////
//
//     Copyright (c) 2009-2015 Denim Group, Ltd.
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
//     The Original Code is ThreadFix.
//
//     The Initial Developer of the Original Code is Denim Group, Ltd.
//     Portions created by Denim Group, Ltd. are Copyright (C)
//     Denim Group, Ltd. All Rights Reserved.
//
//     Contributor(s): Denim Group, Ltd.
//
////////////////////////////////////////////////////////////////////////

package com.denimgroup.threadfix.plugin.zap.action;

import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.enums.ParameterDataType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.plugin.zap.dialog.OptionsDialog;
import com.denimgroup.threadfix.plugin.zap.dialog.UrlDialog;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.threadfix.ZapPropertiesManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public abstract class EndpointsAction extends JMenuItem {

	public static final String GENERIC_INT_SEGMENT = "\\{id\\}";

    private AttackThread attackThread = null;

    Map<String, String> nodes = new HashMap<String, String>();

    public EndpointsAction(final ViewDelegate view, final Model model) {
        getLogger().info("Initializing Attack Surface Detector menu item: \"" + getMenuItemText() + "\"");
        setText(getMenuItemText());

        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e) {

                getLogger().info("About to show dialog.");
                
                boolean configured = OptionsDialog.Validate(view);
                boolean completed = false;
                
                if (configured) {
                    getLogger().info("configured");Endpoint.Info[] endpoints = getEndpoints();

                    if ((endpoints == null) || (endpoints.length == 0)) {
	                	view.showWarningDialog(getNoEndpointsMessage());
	                } else {
                        fillEndpointsToTable(endpoints);
                        getLogger().info("Got " + endpoints.length + " endpoints.");

                        buildNodesFromEndpoints(endpoints, view);

		                String url = ZapPropertiesManager.INSTANCE.getTargetUrl();
                        if (url != null) { // cancel not pressed
                            completed = attackUrl(url, view);
                            if (!completed) {
                                view.showWarningDialog("Invalid URL.");
                            }
                        }
                        else
                        {
                            view.showMessageDialog(getCompletedMessage());
                        }
	                }
                }
                if (completed) {
                	view.showMessageDialog(getCompletedMessage());
                }
            }
        });
    }

    public void buildNodesFromEndpoints(Endpoint.Info[] endpoints , final ViewDelegate view) {
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
            getLogger().warn("Bad URL format.");
            return false;
        }
    }

    private void attack (URL url,  ViewDelegate view) {
        getLogger().info("Starting url " + url);

        if (attackThread != null && attackThread.isAlive()) {
            return;
        }
        attackThread = new AttackThread(this, view);
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

    protected abstract String getMenuItemText();

    protected abstract String getNoEndpointsMessage();

    protected abstract String getCompletedMessage();


    protected abstract Logger getLogger();

    public abstract Endpoint.Info[] getEndpoints();

    public void notifyProgress(AttackThread.Progress progress) {
        getLogger().info("Status is " + progress);
    }

}

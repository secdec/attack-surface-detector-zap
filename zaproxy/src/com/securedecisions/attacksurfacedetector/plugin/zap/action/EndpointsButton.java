///////////////////////////////////////////////////////////////////////////////
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
//     Contributor(s):
//              Denim Group, Ltd.
//              Secure Decisions, a division of Applied Visions, Inc
//
//////////////////////////////////////////////////////////////////////////

package com.securedecisions.attacksurfacedetector.plugin.zap.action;

import com.denimgroup.threadfix.data.entities.RouteParameter;
import com.denimgroup.threadfix.data.enums.ParameterDataType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.securedecisions.attacksurfacedetector.plugin.zap.dialog.OptionsDialog;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.attacksurfacedetector.EndpointDecorator;
import org.zaproxy.zap.extension.attacksurfacedetector.ZapPropertiesManager;

import javax.swing.*;
import javax.swing.table.DefaultTableModel;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.*;

public abstract class EndpointsButton extends JButton {
    public static final String GENERIC_INT_SEGMENT = "\\{id\\}";
    private AttackThread attackThread = null;
    Map<String, String> nodes = new HashMap<String, String>();
    public int mode;

    public EndpointsButton(final ViewDelegate view, final Model model, int mode)
    {
        this.mode = mode;
        getLogger().info("Initializing Attack Surface Detector menu item: \"" + getMenuItemText().replaceAll("[\r\n]","") + "\"");
        setText(getMenuItemText());
        addActionListener(new java.awt.event.ActionListener() {
            @Override
            public void actionPerformed(java.awt.event.ActionEvent e)
            {
                getLogger().debug("About to show dialog.");
                boolean configured = false;
                if(mode == 0)
                    configured = OptionsDialog.ValidateSource(view);
                else if(mode == 1)
                    configured = OptionsDialog.ValidateJson(view);
                boolean completed = false;
                if (configured)
                {
                    try
                    {
                        EndpointDecorator[] endpoints = null;
                        String oldSourceFolder = null;
                        if(mode == 0)
                        {
                            endpoints  = getEndpoints(ZapPropertiesManager.INSTANCE.getSourceFolder());
                            oldSourceFolder = ZapPropertiesManager.INSTANCE.getOldSourceFolder();
                        }
                        if(mode == 1)
                        {
                            endpoints = getEndpoints(ZapPropertiesManager.INSTANCE.getJsonFile());
                            oldSourceFolder = ZapPropertiesManager.INSTANCE.getOldJsonFile();
                        }
                        EndpointDecorator comparePoints[] = null;
                        if(oldSourceFolder != null && !oldSourceFolder.isEmpty())
                            comparePoints = getEndpoints(oldSourceFolder);

                        if ((endpoints == null) || (endpoints.length == 0))
                            view.showWarningDialog(getNoEndpointsMessage());
                        else
                        {
                            if (comparePoints != null && comparePoints.length !=0)
                                endpoints = compareEndpoints(endpoints, comparePoints, view);
                            fillEndpointsToTable(endpoints);
                            getLogger().debug("Got " + endpoints.length + " endpoints.");

                            buildNodesFromEndpoints(endpoints, view);

                            String url = ZapPropertiesManager.INSTANCE.getTargetUrl();
                            if (url != null)
                            { // cancel not pressed
                                completed = attackUrl(url, view);
                                if (!completed)
                                    view.showWarningDialog("Invalid URL.");
                            }
                            else
                                view.showMessageDialog(getCompletedMessage());
                        }

                    }
                    catch (Exception ex)
                    {
                        getLogger().debug(Arrays.toString(ex.getStackTrace()).replaceAll("[\r\n]",""));
                        JOptionPane.showMessageDialog(view.getMainFrame(), "An error occurred processing input. See zap.log for more details");
                    }
                }
                if (completed)
                {
                    view.showMessageDialog(getCompletedMessage());
                }
            }
        });
    }

    public void buildNodesFromEndpoints(EndpointDecorator[] endpoints , final ViewDelegate view)
    {
        for (EndpointDecorator decorator : endpoints)
        {
            Endpoint.Info endpoint = decorator.getEndpoint();
            String endpointPath = endpoint.getUrlPath();
            if (endpointPath.charAt(0) == '\\')
                endpointPath = endpointPath.substring(1);
            endpointPath = endpointPath.replaceAll(GENERIC_INT_SEGMENT, "1");
            boolean first = true;
            StringBuffer reqStringBuff = new StringBuffer(endpointPath);
            String method = endpoint.getHttpMethod();
            for (Map.Entry<String, RouteParameter> parameter : endpoint.getParameters().entrySet())
            {
                if (first)
                {
                    first = false;
                    if (parameter.getValue().getDataType() == ParameterDataType.STRING)
                        reqStringBuff.append('?' + parameter.getKey() + "= debug");

                    else if (parameter.getValue().getDataType() == ParameterDataType.INTEGER)
                        reqStringBuff.append('?' + parameter.getKey() + "= -1");

                    else if (parameter.getValue().getDataType() == ParameterDataType.BOOLEAN)
                        reqStringBuff.append('?' + parameter.getKey() + "= true");

                    else if (parameter.getValue().getDataType() == ParameterDataType.DECIMAL)
                        reqStringBuff.append('?' + parameter.getKey() + "= .1");

                    else if (parameter.getValue().getDataType() == ParameterDataType.DATE_TIME)
                        reqStringBuff.append('?' + parameter.getKey() + '='+ new Date());

                    else if (parameter.getValue().getDataType() == ParameterDataType.LOCAL_DATE)
                        reqStringBuff.append('?' + parameter.getKey() + '=' + new Date());

                    else
                        reqStringBuff.append('?' + parameter.getKey() + "=default");
                }
                else
                {
                    if (parameter.getValue().getDataType() == ParameterDataType.STRING)
                        reqStringBuff.append('&' + parameter.getKey() + "= debug");

                    else if (parameter.getValue().getDataType() == ParameterDataType.INTEGER)
                        reqStringBuff.append('&' + parameter.getKey() + "= -1");

                    else if (parameter.getValue().getDataType() == ParameterDataType.BOOLEAN)
                        reqStringBuff.append('&' + parameter.getKey() + "= true");

                    else if (parameter.getValue().getDataType() == ParameterDataType.DECIMAL)
                        reqStringBuff.append('&' + parameter.getKey() + "= .1");

                    else if (parameter.getValue().getDataType() == ParameterDataType.DATE_TIME)
                        reqStringBuff.append('&' + parameter.getKey() + '=' + new Date());

                    else if (parameter.getValue().getDataType() == ParameterDataType.LOCAL_DATE)
                        reqStringBuff.append('&' + parameter.getKey() + '=' + new Date());

                    else
                        reqStringBuff.append('&' + parameter.getKey() + "=default");
                }

            }
            String reqString = reqStringBuff.toString();
            reqString = reqString.replace("{", "");
            reqString = reqString.replace("}", "");
            reqString = reqString.replace(" ", "");
            nodes.put(reqString, method);
        }
    }

    public boolean attackUrl(String url,  ViewDelegate view)
    {
        try
        {
            if(!url.substring(url.length()-1).equals("/"))
                url = url+"/";
            attack(new URL(url), view);
            return true;
        }
        catch (MalformedURLException e1)
        {
            getLogger().warn("Bad URL format.");
            return false;
        }
    }

    private void attack (URL url,  ViewDelegate view)
    {
        getLogger().debug("Starting url " + url);
        if (attackThread != null && attackThread.isAlive()) {
            return;
        }
        attackThread = new AttackThread(this, view);
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
            if(method.equalsIgnoreCase("post"))
                hasPost = true;
            else if (method.toString().equalsIgnoreCase("get"))
                hasGet = true;
            boolean status = (decorator.getStatus() == EndpointDecorator.Status.NEW) || (decorator.getStatus() == EndpointDecorator.Status.CHANGED);
            dtm.addRow(new Object[]
                    {
                            endpoint.getUrlPath(),
                            endpoint.getParameters().size(),
                            hasGet,
                            hasPost,
                            status,
                            decorator
                    });
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

    public void notifyProgress(AttackThread.Progress progress)
    {
        getLogger().info("Status is " + progress.toString().replaceAll("[\r\n]",""));
    }

    protected abstract String getMenuItemText();
    protected abstract String getNoEndpointsMessage();
    protected abstract String getCompletedMessage();
    protected abstract Logger getLogger();
    public abstract EndpointDecorator[] getEndpoints(String sourceFolder);


}

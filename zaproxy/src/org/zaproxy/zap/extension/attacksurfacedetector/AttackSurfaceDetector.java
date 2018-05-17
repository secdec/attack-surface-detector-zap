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
////////////////////////////////////////////////////////////////////////

package org.zaproxy.zap.extension.attacksurfacedetector;

import com.securedecisions.attacksurfacedetector.plugin.zap.action.LocalEndpointsAction;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.AbstractPanel;
import org.parosproxy.paros.extension.ExtensionAdaptor;
import org.parosproxy.paros.extension.ExtensionHook;

import javax.swing.*;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ResourceBundle;

public class AttackSurfaceDetector extends ExtensionAdaptor {
    private LocalEndpointsAction localEndpointsAction = null;
    private ResourceBundle messages = null;
    private AbstractPanel statusPanel;
    JTabbedPane tabbedPane;
    JCheckBox autoSpiderField;
    private static final Logger logger = Logger.getLogger(AttackSurfaceDetector.class);
    static { logger.debug("Loading Class"); }

    public AttackSurfaceDetector()
    {
        super();
        logger.debug("calling constructor");
        initialize();
        logger.debug("No-arg Constructor");
        this.setEnabled(true);
    }

    public AttackSurfaceDetector(String name)
    {
        super(name);
        logger.debug("1-arg Constructor");
    }

    private void initialize()
    {
        logger.debug("Initialize");
        this.setName("Attack Surface Detector");
    }

    @Override
    public void hook(ExtensionHook extensionHook)
    {
        logger.debug("Hook");
        super.hook(extensionHook);
        if (getView() != null)
        {
            extensionHook.getHookMenu().addToolsMenuItem(getLocalEndpointsAction());
            extensionHook.getHookView().addStatusPanel(new AttackSurfaceDetectorPanel(getView(), getModel()));
        }
    }

    public LocalEndpointsAction getLocalEndpointsAction()
    {
        logger.debug("Getting menu");
        if (localEndpointsAction == null)
            localEndpointsAction = new LocalEndpointsAction(getView(), getModel());

        return localEndpointsAction;
    }

    public String getMessageString(String key) { return messages.getString(key); }

    @Override
    public String getAuthor()
    {
        logger.debug("Getting Author");
        return "Secure Decisions";
    }

    @Override
    public String getDescription()
    {
        logger.debug("Getting Description");
        return "Source Code Analysis";
    }

    @Override
    public URL getURL()
    {
        logger.debug("Getting URL");
        try
        {
            return new URL("https://github.com/secdec/attack-surface-detector-zap/wiki");
        }
        catch (MalformedURLException e)
        {
            return null;
        }
    }
    @Override
    public boolean isEnabled()
    {
        return true;
    }
}
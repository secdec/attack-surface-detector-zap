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

import com.denimgroup.threadfix.data.enums.FrameworkType;
import com.denimgroup.threadfix.data.interfaces.Endpoint;
import com.denimgroup.threadfix.framework.engine.framework.FrameworkCalculator;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabase;
import com.denimgroup.threadfix.framework.engine.full.EndpointDatabaseFactory;
import com.denimgroup.threadfix.framework.engine.full.TemporaryExtractionLocation;
import com.denimgroup.threadfix.framework.util.EndpointUtil;
import org.apache.log4j.Logger;
import org.parosproxy.paros.extension.ViewDelegate;
import org.parosproxy.paros.model.Model;
import org.zaproxy.zap.extension.attacksurfacedetector.EndpointDecorator;
import org.zaproxy.zap.extension.attacksurfacedetector.ZapPropertiesManager;

import java.io.File;
import java.util.ArrayList;
import java.util.List;

public class LocalEndpointsButton extends EndpointsButton {

    private String errorMessage = "An error occurred processing input. Please check input";
    private static final long serialVersionUID = 1L;
    private static final Logger LOGGER = Logger.getLogger(LocalEndpointsButton.class);
    public LocalEndpointsButton(final ViewDelegate view, final Model model) {
        super(view, model, 0);
    }
    @Override
    protected String getMenuItemText() {
        return "Import Endpoints from Source";
    }
    @Override
    protected String getNoEndpointsMessage() { return "Failed to retrieve endpoints from the source. Check your inputs."; }
    @Override
    protected String getCompletedMessage() {
        return "The endpoints were successfully generated from source.";
    }
    @Override
    protected  String getErrorMessage() {return errorMessage;}
    protected Logger getLogger() {
        return LOGGER;
    }

    public EndpointDecorator[] getEndpoints(String sourceFolder, boolean comparison)
    {
        getLogger().debug("Got source information, about to generate endpoints.");
        File file= new File(sourceFolder);
        TemporaryExtractionLocation zipExtractor = null;
        if (TemporaryExtractionLocation.isArchive(sourceFolder)) {
            zipExtractor = new TemporaryExtractionLocation(sourceFolder);
            zipExtractor.extract();

            file = zipExtractor.getOutputPath();
        }

        List<FrameworkType> frameworks = FrameworkCalculator.getTypes(file);
        ArrayList<List<Endpoint>> endpointsListList =new ArrayList<>(frameworks.size());
        EndpointDecorator[] endpoints = null;
        int decSize = 0;
        for (FrameworkType framework :  frameworks)
        {
            EndpointDatabase endpointDatabase = EndpointDatabaseFactory.getDatabase(file, framework);
            if(endpointDatabase != null)
            {
                List<Endpoint> endpointsList = EndpointUtil.flattenWithVariants(endpointDatabase.generateEndpoints());
                endpointsListList.add(endpointsList);
                decSize += endpointsList.size();
            }
        }
        endpoints = new EndpointDecorator[decSize];
        int pos = 0;
        for(List<Endpoint> endpointList: endpointsListList)
        {
            for(Endpoint endpoint : endpointList)
            {
                endpoints[pos++] = new EndpointDecorator(Endpoint.Info.fromEndpoint(endpoint, false));
            }
        }

        if (zipExtractor != null) {
            zipExtractor.release();
        }
        return endpoints;
    }
}

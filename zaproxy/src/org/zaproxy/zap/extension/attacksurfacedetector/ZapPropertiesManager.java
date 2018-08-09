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

package org.zaproxy.zap.extension.attacksurfacedetector;

import com.denimgroup.threadfix.data.interfaces.Endpoint;
import org.apache.log4j.Logger;

import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.Properties;

import org.parosproxy.paros.Constant;
import org.parosproxy.paros.extension.ViewDelegate;

import javax.swing.*;

/**
 * Created by mac on 9/23/13.
 */
public class ZapPropertiesManager extends AbstractZapPropertiesManager {

    private static final Logger logger = Logger.getLogger(ZapPropertiesManager.class);
    public static final ZapPropertiesManager INSTANCE = new ZapPropertiesManager();
    private static boolean hasChanges = false;
    private ViewDelegate view = null;
    private ZapPropertiesManager(){}
    public static final String
            FILE_NAME = "asd.properties",
            API_KEY_KEY = "key",
            URL_KEY = "url",
            APP_ID_KEY = "application-id",
            SOURCE_FOLDER_KEY = "source-folder",
            OLD_SOURCE_FOLDER_KEY = "old-source-folder",
            JSON_FILE_KEY = "json-file",
            OLD_JSON_FILE_KEY = "old-json-file",
            AUTO_SPIDER_KEY = "auto-spider",
            HOST_KEY = "host",
            PORT_KEY = "port",
            PATH_KEY = "path",
            HTTPS_KEY = "use-https",
            SAVE_MESSAGE = "Saving ZAP properties.";

    @Override
    public String getKey() {
        String key = getProperties().getProperty(API_KEY_KEY);
        return key;
    }

    public void setPropertyValue(String key, String value) {
        JOptionPane.showMessageDialog(view.getMainFrame(), "Key = " + key + " value = " + value);
        Properties properties = getProperties();
        properties.setProperty(key, value);
        saveProperties(properties);
        hasChanges = true;
    }

    private static JTable endpointsTable;

    private EndpointDecorator decorator;

    @Override
    public String getAppId() {
        return getProperties().getProperty(APP_ID_KEY);
    }

    public EndpointDecorator getEndpointDecorator() {
        return decorator;
    }

    public void setEndpointDecorator(EndpointDecorator decorator)
    {
        this.decorator = decorator;
    }

    public ViewDelegate getView() {
        return view;
    }

    public void setView(ViewDelegate view)
    {
        this.view = view;
    }
    public void setEndpointsTable(JTable table){endpointsTable = table;}

    public static JTable getEndpointsTable() {return endpointsTable;}

    public String getSourceFolder()
    {
        String sourceFolder = getProperties().getProperty(SOURCE_FOLDER_KEY);
        return sourceFolder;
    }
    public String getOldSourceFolder()
    {
        String oldSourceFolder = getProperties().getProperty(OLD_SOURCE_FOLDER_KEY);
        return oldSourceFolder;
    }

    public String getJsonFile()
    {
        String jsonFile = getProperties().getProperty(JSON_FILE_KEY);
        return jsonFile;
    }
    public String getOldJsonFile()
    {
        String oldJsonFile = getProperties().getProperty(OLD_JSON_FILE_KEY);
        return oldJsonFile;
    }


    public String getTargetHost()
    {
        String targetHost = getProperties().getProperty(HOST_KEY);
        return targetHost;
    }

    public String getTargetPort()
    {
        String targetPort = getProperties().getProperty(PORT_KEY);
        return targetPort;
    }

    public String getTargetPath()
    {
        String sourceFolder = getProperties().getProperty(PATH_KEY);
        return sourceFolder;
    }

    public boolean getAutoSpider()
    {
        String autoSpider = getProperties().getProperty(AUTO_SPIDER_KEY);
        boolean shouldSpider = Boolean.parseBoolean(autoSpider);
        return shouldSpider;
    }

    public boolean getUseHttps()
    {
        String useHttps = getProperties().getProperty(HTTPS_KEY);
        boolean shouldUseHttps = Boolean.parseBoolean(useHttps);
        return shouldUseHttps;
    }

    public static void setKeyAndUrl(String newKey, String newUrl)
    {
        Properties properties = getProperties();
        properties.setProperty(API_KEY_KEY, newKey);
        properties.setProperty(URL_KEY, newUrl);
        saveProperties(properties);
    }

    public static void setAppId(String appId)
    {
        Properties properties = getProperties();
        properties.setProperty(APP_ID_KEY, appId);
        saveProperties(properties);
    }

    public static void setSourceFolder(String sourceFolder)
    {
        Properties properties = getProperties();
        properties.setProperty(SOURCE_FOLDER_KEY, sourceFolder);
        saveProperties(properties);
    }

    public static void setOldSourceFolder(String oldSourceFolder)
    {
        Properties properties = getProperties();
        properties.setProperty(OLD_SOURCE_FOLDER_KEY, oldSourceFolder);
        saveProperties(properties);
    }

    public static void setJsonFile(String jsonFile)
    {
        Properties properties = getProperties();
        properties.setProperty(JSON_FILE_KEY, jsonFile);
        saveProperties(properties);
    }

    public static void setOldJsonFile(String oldJsonFile)
    {
        Properties properties = getProperties();
        properties.setProperty(OLD_JSON_FILE_KEY, oldJsonFile);
        saveProperties(properties);
    }

    public static void setTargetHost(String targetHost)
    {
        Properties properties = getProperties();
        properties.setProperty(HOST_KEY, targetHost);
        saveProperties(properties);
    }

    public static void setTargetPort(String targetPort)
    {
        Properties properties = getProperties();
        properties.setProperty(PORT_KEY, targetPort);
        saveProperties(properties);
    }

    public static void setTargetPath(String targetPath)
    {
        Properties properties = getProperties();
        properties.setProperty(PATH_KEY, targetPath);
        saveProperties(properties);
    }

    public static void setUseHttps(boolean useHttps)
    {
        Properties properties = getProperties();
        if (useHttps)
            properties.setProperty(HTTPS_KEY, "true");
        else
            properties.setProperty(HTTPS_KEY, "false");
        saveProperties(properties);
    }

    public static void setAutoSpider(boolean autoSpider)
    {
        Properties properties = getProperties();
        if (autoSpider)
            properties.setProperty(AUTO_SPIDER_KEY, "true");
        else
            properties.setProperty(AUTO_SPIDER_KEY, "false");
        saveProperties(properties);
    }

    private static Properties getProperties()
    {
        Properties properties = new Properties();
        File file = new File(Constant.getZapHome(), FILE_NAME);
        if (!file.exists()) {
            try {
                file.createNewFile();
            } catch (IOException e) {
                logger.warn("Failed trying to initialize properties file.", e);
            }
        }
        if (file.exists())
        {
            try (FileReader reader = new FileReader(file)) {
                properties.load(reader);
            } catch (IOException e) {
                logger.warn("Failed attempting to load from properties file.", e);
            }
        } else {
            logger.warn("File didn't exist");
        }
        return properties;
    }

    public String getTargetUrl()
    {
        String proto = new String();
        if (getUseHttps())
            proto = "https://";
        else
            proto = "http://";

        String path = getTargetPath();
        String port = getTargetPort();
        String host = getTargetHost();
        if(port == null || port.trim().isEmpty() || host == null || host.trim().isEmpty())
            return null;

        if (path == null || path.trim().isEmpty())
             return proto + host + ":" + port;
        else
            return proto + host + ":" + port + "/" + path;
    }
    private static void saveProperties(Properties properties)
    {
        try (FileWriter writer = new FileWriter(new File(Constant.getZapHome(), FILE_NAME)))
        {
            properties.store(writer, SAVE_MESSAGE);
        }
        catch (IOException e)
        {
            logger.warn(e.getMessage(), e);
        }
    }
}

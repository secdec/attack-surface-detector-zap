# Summary
During web application penetration testing, it is important to enumerate  your application's attack surface. While Dynamic Application Security Testing (DAST) tools (such as Burp Suite and ZAP) are good at spidering to identify application attack surfaces, they will often fail to identify unlinked endpoints and optional parameters. These endpoints and parameters not found often go untested, which can leave your application open to an attacker.
This tool is the Attack Surface Detector, a plugin for OWASP ZAP. This tool figures out the endpoints of a web application, the parameters these endpoints accept, and the data type of those parameters. This includes the unlinked endpoints a spider won't find in client-side code, or optional parameters totally unused in client-side code. The plugin then imports this data into ZAP so you view the results, or work with the detected endpoints and parameters from the target site map.

# How it Works
The Attack Surface Detector uses static code analyses to identify web app endpoints by parsing routes and identifying parameters (with supported languages and frameworks).

## Supported Frameworks:
  * C# / ASP.NET MVC
  * C# / Web Forms
  * Java / Spring MVC
  * Java / Struts
  * Java JSP
  * Python / Django
  * Ruby / Rails

To see a brief demonstration for the Attack Surface Detector, you can check it out [here:](https://youtu.be/jUUJNRcmqwI) *note: this demonstration is for a plugin built for Portswigger's Burp Suite. Implementation and operation is nearly identical to this plugin*


## How to Install

1.	Download and install the latest build of OWASP ZAP from https://github.com/zaproxy/zaproxy/wiki/Downloads
2.	Launch application

### Installing the Plugin
1. For Build/install instructions click [here:](https://github.com/secdec/attack-surface-detector-zap/wiki)


## License

Licensed under the [MPL](https://github.com/secdec/attack-surface-detector-zap/blob/master/LICENSE) License.
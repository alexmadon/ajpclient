# ajpclient


When testing an java app running on tomcat on the 8009 ajp13 connector, you can create an apache proxy with mod_proxy and connect to your tomcat using that proxy.

For test and QA purposes, it is sometimes easier to send a curl like command.

This tool aims to be to AJP13 what curl is to HTTP.

To get help, use the -h flag:


```bash
./ajprequest.py -h
usage: ajprequest.py [-h] [-H HEADER] [-r REMOTE_USER]
                     [-X {GET,POST,HEAD,OPTIONS,PROPFIND}] [-l {INFO,DEBUG}]
                     [-d DATA]
                     requesturl [passurl]

A python AJP client

positional arguments:
  requesturl            The request to the proxy front end, e.g. http://localh
                        ost/alfresco/faces/jsp/dashboards/container.jsp
  passurl               The proxy pass url (default:
                        ajp://localhost:8009/alfresco)

optional arguments:
  -h, --help            show this help message and exit
  -H HEADER, --header HEADER
                        adds a header
  -r REMOTE_USER, --remote_user REMOTE_USER
                        Sets the remote_user CGI variable
  -X {GET,POST,HEAD,OPTIONS,PROPFIND}
                        Sets the method (default: GET).
  -l {INFO,DEBUG}, --log_level {INFO,DEBUG}
                        Sets the log level. Logs are sent to STDERR.
  -d DATA, --data DATA  The data to POST

The AJPv13 protocol is documented at: http://tomcat.apache.org/connectors-doc-
archive/jk2/common/AJPv13.html
```

This script has been used to log several Alfresco Jiras.

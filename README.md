# yLog4j

This is Y-Sec's @PortSwigger Burp Plugin for the Log4j [CVE-2021-44228](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228) vulnerability. The focus of yLog4j is to support mass-scanning of the Log4j vulnerability CVE-2021-44228.

Please see our [Blog post](https://www.y-security.de/news-en/blind-detection-of-the-log4j-vulnerability-en-scale/index.html) for details and backgrounds.

# Requirements
* PortSwigger Burp Professional
* Jython 2.x

It is recommended, but not required, to use a dedicated [Scanning Profile](https://portswigger.net/burp/documentation/enterprise/working/scans/scan-configs). See [Y-Security-Log4j-Scan.json](Y-Security-Log4j-Scan.json) as an example.

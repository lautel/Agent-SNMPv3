#!/usr/bin/python
# -*- coding: utf-8 -*-

# Information about XML in Python here: https://docs.python.org/2/library/xml.dom.html#module-xml.dom

from lxml import etree as ET
from pysnmp.proto import error, rfc1902
import pysnmp.smi.error
from pysnmp.entity import engine, config
import ast

def verifyAccess(self, name, idx, viewType,
                       snmpEngine, securityModel, securityName,
                        securityLevel, contextName
                       ):
    print "Verifying Access ..."
    try:
        vacmID = 3
        # http://www.rfc-base.org/txt/rfc-2575.txt
        statusInformation = snmpEngine.accessControlModel[vacmID].isAccessAllowed(
            snmpEngine, securityModel, securityName,
            securityLevel, viewType, contextName, name)
        return 0
    except error.StatusInformation, statusInformation:
        errorIndication = statusInformation['errorIndication']
        print "ERROR: ", errorIndication

        if errorIndication == 'noSuchView' or \
            errorIndication == 'noAccessEntry' or \
            errorIndication == 'noGroupName':
            #print "Verify at 1"
            raise pysnmp.smi.error.AuthorizationError(name=name, idx=idx)
        elif errorIndication == 'noSuchContext':
            # no MIB view found because of no entry in the vacmContextTable for specified contextName
            snmpUnknownContexts, = snmpEngine.msgAndPduDsp.mibInstrumController.mibBuilder.importSymbols('__SNMP-TARGET-MIB', 'snmpUnknownContexts')
            snmpUnknownContexts.syntax += 1
            # Request REPORT generation
            raise pysnmp.smi.error.GenError(
                name=name, idx=idx,
                oid=snmpUnknownContexts.name,
                val=snmpUnknownContexts.syntax)
        elif errorIndication == 'otherError':
            #print "Verify at 2"
            raise pysnmp.smi.error.GenError(name=name, idx=idx)
        elif errorIndication == 'notInView':
            #print "Verify at 3"
            return 1 #A MIB view was found but access is denied. The variableName is not in the configured MIB view for the specified viewType
        else:
            raise error.ProtocolError('Unknown ACM error %s' % errorIndication)

# MIB instance:
def createMibTree(self):
    doc="""<?xml version="1.0" encoding="utf-8"?>
    <OidTree>
        <o1 NAME= "iso" SYNTAX="none" MAX-ACCESS="not-accessible">
            <o1o3 NAME= "org" SYNTAX="none" MAX-ACCESS="not-accessible">
                <o1o3o6 NAME= "dod" SYNTAX="none" MAX-ACCESS="not-accessible">
                    <o1o3o6o1 NAME= "internet" SYNTAX="none" MAX-ACCESS="not-accessible">
                        <o1o3o6o1o4 NAME= "private" SYNTAX="none" MAX-ACCESS="not-accessible">
                            <o1o3o6o1o4o1 NAME= "enterprises" SYNTAX="none" MAX-ACCESS="not-accessible">
                                    ...
                                    ...
                                    ...
                            </o1o3o6o1o4o1>
                        </o1o3o6o1o4>
                    </o1o3o6o1>
                </o1o3o6>
            </o1o3>
        </o1>
    </OidTree>
    """
    self.mib_xml = ET.fromstring(doc)

def xml_validator(xmlparser, xmlfilename):
    try:
        with open(xmlfilename, 'r') as f:
            ET.fromstring(f.read(), xmlparser)
        return True
    except ET.XMLSchemaError:
        return False

def get_snmp(self,oid_o):
    # An OID, a value, a data type and (if) errors are returned
    ...
    ...
    return [oid_s, value, type_v]

def set_snmp(self,oid_o,value_set):
    # An OID, a value, a data type and (if) errors are returned
    ...
    ...
    return [oid_s, value, type_v]

def get_next_snmp(self,oid_o):
    # Go down through the tree and return the first item with access
    ...
    ...
    return [oid_s, value, type_v]

def mib_list_str(mib_xml0, oid_o):
    # Return the list and if the requested oid is not is the list yet, include it
    ...
    ...
    return s_list

def usmVacmSetup(self,file_name):
    # VACM: View-based Access Control Model
    tree = ET.parse(file_name)
    root = tree.getroot()
    self.iniFile = root

    ### Users
    ...
    ...
    config.addVacmUser(self.snmpEngine, 3, name, level)

    ### Groups
    ...
    ...
    config.addVacmGroup(self.snmpEngine, gpName, 3, securityName_gr)

    ### Views
    ...
    ...
    config.addVacmView(self.snmpEngine, viewName, "included", ast.literal_eval(oid), "")

    ### Access
    ...
    ...
    config.addVacmAccess(self.snmpEngine, groupName, "", 3, level, "exact", read, write, notify)


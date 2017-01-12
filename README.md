# Agent-SNMPv3

Implementation of an SNMPv3 agent in Python for accesing CPU usage information in OS Debian. 

NOTE: In order to preserve the privacy, the MIB tree, initialization xml file and its schema of namespaces have not been uploaded (named as *ini_file.xml* and *XMLSchema.xsd*)

*agentV3_r1.py* is the main file. The SNMPv3 agent is defined here, as well as its functionalities: GetCommandResponder, SetCommandResponder, NextCommandResponder.

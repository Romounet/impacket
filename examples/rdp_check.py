#!/usr/bin/env python
# SECUREAUTH LABS. Copyright 2018 SecureAuth Corporation. All rights reserved.
#
# This software is provided under under a slightly modified version
# of the Apache Software License. See the accompanying LICENSE file
# for more information.
#
# Author:
#  Alberto Solino (@agsolino)
#
# Description: [MS-RDPBCGR] and [MS-CREDSSP] partial implementation 
#              just to reach CredSSP auth. This example test whether
#              an account is valid on the target host.
#
# ToDo:
#    [x] Manage to grab the server's SSL key so we can finalize the whole
#        authentication process (check [MS-CSSP] section 3.1.5)
#

from impacket.examples import logger
from impacket.spnego import asn1encode, SPNEGOCipher
from impacket.credssp import *

if __name__ == '__main__':

    import socket
    import argparse
    import sys
    import logging
    from binascii import a2b_hex
    from impacket import ntlm, version
    try:
        from OpenSSL import SSL, crypto
    except:
        logging.critical("pyOpenSSL is not installed, can't continue")
        sys.exit(1)
    

    def check_rdp(host, username, password, domain, hashes = None):

       if hashes is not None:
           lmhash, nthash = hashes.split(':')
           lmhash = a2b_hex(lmhash)
           nthash = a2b_hex(nthash)

       else:
           lmhash = ''
           nthash = ''

       tpkt = TPKT()
       tpdu = TPDU()
       rdp_neg = RDP_NEG_REQ()
       rdp_neg['Type'] = TYPE_RDP_NEG_REQ
       rdp_neg['requestedProtocols'] = PROTOCOL_HYBRID | PROTOCOL_SSL
       tpdu['VariablePart'] = rdp_neg.getData()
       tpdu['Code'] = TDPU_CONNECTION_REQUEST
       tpkt['TPDU'] = tpdu.getData()
   
       s = socket.socket()
       s.connect((host,3389))
       s.sendall(tpkt.getData())
       pkt = s.recv(8192)
       tpkt.fromString(pkt)
       tpdu.fromString(tpkt['TPDU'])
       cr_tpdu = CR_TPDU(tpdu['VariablePart'])
       if cr_tpdu['Type'] == TYPE_RDP_NEG_FAILURE:
           rdp_failure = RDP_NEG_FAILURE(tpdu['VariablePart'])
           rdp_failure.dump()
           logging.error("Server doesn't support PROTOCOL_HYBRID, hence we can't use CredSSP to check credentials")
           return
       else:
           rdp_neg.fromString(tpdu['VariablePart'])

       # Since we were accepted to talk PROTOCOL_HYBRID, below is its implementation

       # 1. The CredSSP client and CredSSP server first complete the TLS handshake, 
       # as specified in [RFC2246]. After the handshake is complete, all subsequent 
       # CredSSP Protocol messages are encrypted by the TLS channel. 
       # The CredSSP Protocol does not extend the TLS wire protocol. As part of the TLS 
       # handshake, the CredSSP server does not request the client's X.509 certificate 
       # (thus far, the client is anonymous). Also, the CredSSP Protocol does not require 
       # the client to have a commonly trusted certification authority root with the 
       # CredSSP server. Thus, the CredSSP server MAY use, for example, 
       # a self-signed X.509 certificate.

       # Switching to TLS now
       ctx = SSL.Context(SSL.TLSv1_2_METHOD)
       ctx.set_cipher_list('RC4,AES')
       tls = SSL.Connection(ctx,s)
       tls.set_connect_state()
       tls.do_handshake()

       # If you want to use Python internal ssl, uncomment this and comment 
       # the previous lines
       #tls = ssl.wrap_socket(s, ssl_version=ssl.PROTOCOL_TLSv1, ciphers='RC4')

       # 2. Over the encrypted TLS channel, the SPNEGO handshake between the client 
       # and server completes mutual authentication and establishes an encryption key 
       # that is used by the SPNEGO confidentiality services, as specified in [RFC4178]. 
       # All SPNEGO tokens as well as the underlying encryption algorithms are opaque to 
       # the calling application (the CredSSP client and CredSSP server). 
       # The wire protocol for SPNEGO is specified in [MS-SPNG].
       # The SPNEGO tokens exchanged between the client and the server are encapsulated 
       # in the negoTokens field of the TSRequest structure. Both the client and the 
       # server use this structure as many times as necessary to complete the SPNEGO 
       # exchange.<9>
       #
       # Note During this phase of the protocol, the OPTIONAL authInfo field is omitted 
       # from the TSRequest structure by the client and server; the OPTIONAL pubKeyAuth 
       # field is omitted by the client unless the client is sending the last SPNEGO token. 
       # If the client is sending the last SPNEGO token, the TSRequest structure MUST have 
       # both the negoToken and the pubKeyAuth fields filled in.

       # NTLMSSP stuff
       auth = ntlm.getNTLMSSPType1('','',True, use_ntlmv2 = True)

       ts_request = TSRequest()
       ts_request['NegoData'] = auth.getData()

       tls.send(ts_request.getData())
       buff = tls.recv(4096)
       ts_request.fromString(buff)

   
       # 3. The client encrypts the public key it received from the server (contained 
       # in the X.509 certificate) in the TLS handshake from step 1, by using the 
       # confidentiality support of SPNEGO. The public key that is encrypted is the 
       # ASN.1-encoded SubjectPublicKey sub-field of SubjectPublicKeyInfo from the X.509 
       # certificate, as specified in [RFC3280] section 4.1. The encrypted key is 
       # encapsulated in the pubKeyAuth field of the TSRequest structure and is sent over 
       # the TLS channel to the server. 
       #
       # Note During this phase of the protocol, the OPTIONAL authInfo field is omitted 
       # from the TSRequest structure; the client MUST send its last SPNEGO token to the 
       # server in the negoTokens field (see step 2) along with the encrypted public key 
       # in the pubKeyAuth field.

       # Last SPNEGO token calculation
       #ntlmChallenge = ntlm.NTLMAuthChallenge(ts_request['NegoData'])
       type3, exportedSessionKey = ntlm.getNTLMSSPType3(auth, ts_request['NegoData'], username, password, domain, lmhash, nthash, use_ntlmv2 = True)

       # Get server public key
       server_cert =  tls.get_peer_certificate()
       pkey = server_cert.get_pubkey()
       dump = crypto.dump_privatekey(crypto.FILETYPE_ASN1, pkey)

       # Fix up due to PyOpenSSL lack for exporting public keys
       dump = dump[7:]
       dump = b'\x30'+ asn1encode(dump)

       cipher = SPNEGOCipher(type3['flags'], exportedSessionKey)
       signature, cripted_key = cipher.encrypt(dump)
       ts_request['NegoData'] = type3.getData()
       ts_request['pubKeyAuth'] = signature.getData() + cripted_key

       try:
           # Sending the Type 3 NTLM blob
           tls.send(ts_request.getData())
           # The other end is waiting for the pubKeyAuth field, but looks like it's
           # not needed to check whether authentication worked.
           # If auth is unsuccessful, it throws an exception with the previous send().
           # If auth is successful, the server waits for the pubKeyAuth and doesn't answer 
           # anything. So, I'm sending garbage so the server returns an error. 
           # Luckily, it's a different error so we can determine whether or not auth worked ;)
           buff = tls.recv(1024)
       except Exception as err:
           if str(err).find("denied") > 0:
               logging.error("Access Denied")
           else:
               logging.error(err)
           return

       # 4. After the server receives the public key in step 3, it first verifies that 
       # it has the same public key that it used as part of the TLS handshake in step 1. 
       # The server then adds 1 to the first byte representing the public key (the ASN.1 
       # structure corresponding to the SubjectPublicKey field, as described in step 3) 
       # and encrypts the binary result by using the SPNEGO encryption services. 
       # Due to the addition of 1 to the binary data, and encryption of the data as a binary 
       # structure, the resulting value may not be valid ASN.1-encoded values. 
       # The encrypted binary data is encapsulated in the pubKeyAuth field of the TSRequest 
       # structure and is sent over the encrypted TLS channel to the client. 
       # The addition of 1 to the first byte of the public key is performed so that the 
       # client-generated pubKeyAuth message cannot be replayed back to the client by an 
       # attacker.
       #
       # Note During this phase of the protocol, the OPTIONAL authInfo and negoTokens 
       # fields are omitted from the TSRequest structure.

       ts_request = TSRequest(buff)

       # Now we're decrypting the certificate + 1 sent by the server. Not worth checking ;)
       signature, plain_text = cipher.decrypt(ts_request['pubKeyAuth'][16:])

       # 5. After the client successfully verifies server authenticity by performing a 
       # binary comparison of the data from step 4 to that of the data representing 
       # the public key from the server's X.509 certificate (as specified in [RFC3280], 
       # section 4.1), it encrypts the user's credentials (either password or smart card 
       # PIN) by using the SPNEGO encryption services. The resulting value is 
       # encapsulated in the authInfo field of the TSRequest structure and sent over 
       # the encrypted TLS channel to the server.
       # The TSCredentials structure within the authInfo field of the TSRequest 
       # structure MAY contain either a TSPasswordCreds or a TSSmartCardCreds structure, 
       # but MUST NOT contain both.
       #
       # Note During this phase of the protocol, the OPTIONAL pubKeyAuth and negoTokens 
       # fields are omitted from the TSRequest structure.
       tsp = TSPasswordCreds()
       tsp['domainName'] = domain
       tsp['userName']   = username
       tsp['password']   = password
       tsc = TSCredentials()
       tsc['credType'] = 1 # TSPasswordCreds
       tsc['credentials'] = tsp.getData()

       signature, cripted_creds = cipher.encrypt(tsc.getData())
       ts_request = TSRequest()
       ts_request['authInfo'] = signature.getData() + cripted_creds
       tls.send(ts_request.getData())
       tls.close()
       logging.info("Access Granted")

    # Init the example's logger theme
    logger.init()
    print(version.BANNER)

    parser = argparse.ArgumentParser(add_help = True, description = "Test whether an account is valid on the target "
                                                                    "host using the RDP protocol.")

    parser.add_argument('target', action='store', help='[[domain/]username[:password]@]<targetName or address>')

    group = parser.add_argument_group('authentication')

    group.add_argument('-hashes', action="store", metavar = "LMHASH:NTHASH", help='NTLM hashes, format is LMHASH:NTHASH')
    if len(sys.argv)==1:
        parser.print_help()
        sys.exit(1)
 
    options = parser.parse_args()

    import re
    domain, username, password, address = re.compile('(?:(?:([^/@:]*)/)?([^@:]*)(?::([^@]*))?@)?(.*)').match(options.target).groups('')

    #In case the password contains '@'
    if '@' in address:
        password = password + '@' + address.rpartition('@')[0]
        address = address.rpartition('@')[2]

    if domain is None:
        domain = ''

    if password == '' and username != '' and options.hashes is None:
        from getpass import getpass
        password = getpass("Password:")

    check_rdp(address, username, password, domain, options.hashes)

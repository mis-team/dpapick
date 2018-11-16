#!/usr/bin/env python
#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
## certs2pfx combine outline decrypted RSAkeys with certificate file       ##
## to pfx certificate                                                      ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from DPAPI.Core import masterkey
import sys
from DPAPI import probe
from DPAPI.Probes import certificate
from DPAPI.Core import eater, credhist, crypto
from pyasn1.type import univ, namedtype
from pyasn1.codec.der import encoder

import hashlib
import os
import OpenSSL
import sys
import binascii
import base64

from optparse import OptionParser

class Cert(probe.DPAPIProbe):
    PROP_PROVIDER = 2
    PROP_CERTIFICATE = 0x20

    PROPS = {2: "Provider", 3: "SHA-1", 4: "MD5", 15: "Signature hash",
             20: "Key identifier", 25: "Subject MD5 hash",
             69: "Backed up", 92: "Pubkey bitlength", 32: "ASN.1 certificate"}

    class CertProvider(probe.DPAPIProbe):
        def parse(self, data):
            raw = data.remain()
            ofs_keyname, ofs_provider = data.eat("2L")
            self.provider_type = data.eat("L")
            self.flags = data.eat("L")
            self.nb_params = data.eat("L")
            ofs_params = data.eat("L")
            self.key_specs = data.eat("L")
            self.keyname = raw[ofs_keyname:]
            end = self.keyname.find("\x00\x00\x00")
            if end & 1:
                end += 1
            self.keyname = self.keyname[:end].decode("UTF-16LE").rstrip("\x00")
            self.provider = raw[ofs_provider:]
            end = self.provider.find("\x00\x00\x00")
            if end & 1:
                end += 1
            self.provider = self.provider[:end].decode("UTF-16LE").rstrip("\x00")

        def __str__(self, indent=""):
            rv = ["%s+ Cert Provider" % indent]
            rv.append("%s  - Key name: %s" % (indent, self.keyname))
            rv.append("%s  - Provider: %s" % (indent, self.provider))
            return "\n".join(rv)


    def parse(self, data):
        self.props = {}
        while data:
            cert_id, n, size = data.eat("3L")
            self.props[cert_id] = []
            for _ in xrange(n):
                if cert_id == self.PROP_PROVIDER:
                    provider = self.CertProvider()
                    provider.parse(data.eat_sub(size))
                    self.props[cert_id].append(provider)
                    self.name = provider.keyname
                elif cert_id == self.PROP_CERTIFICATE:
                    self.certificate = data.eat_string(size)
                else:
                    self.props[cert_id].append(data.eat_string(size))

    def __str__(self):
        rv = ["+ Microsoft Certificate"]
        for k, v in self.props.iteritems():
            rv.append("  + %s (%d)" % (self.PROPS.get(k, "Unknown"), k))
            for p in v:
                if isinstance(p, str):
                    rv.append("     - %s" % p.encode("hex"))
                else:
                    rv.append(p.__str__(indent="    "))
        return "\n".join(rv)

class RSAKey(eater.DataStruct):
    """This subclass represents the RSA privatekey BLOB, beginning with the
    magic value "RSA2"
    """


    class RSAKeyASN1(univ.Sequence):
    
        """subclass for ASN.1 sequence representing the RSA key pair.
        Mainly useful to export the key to OpenSSL
        """
        componentType = namedtype.NamedTypes(
            namedtype.NamedType('version', univ.Integer()),
            namedtype.NamedType('modulus', univ.Integer()),
            namedtype.NamedType('pubexpo', univ.Integer()),
            namedtype.NamedType('privexpo', univ.Integer()),
            namedtype.NamedType('prime1', univ.Integer()),
            namedtype.NamedType('prime2', univ.Integer()),
            namedtype.NamedType('exponent1', univ.Integer()),
            namedtype.NamedType('exponent2', univ.Integer()),
            namedtype.NamedType('coefficient', univ.Integer())
        )

    def __init__(self, raw=None):
        """Constructs a DPAPIProbe object.
            If raw is set, automatically builds a DataStruct with that
            and calls parse() method with this.

        """
        self.dpapiblob = None
        self.cleartext = None
        self.entropy = None
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.magic = data.eat("4s")  # RSA2
        len1 = data.eat("L")
        self.bitlength = data.eat("L")
        chunk = self.bitlength / 16
        self.unk = data.eat("L")
        self.pubexp = data.eat("L")
        self.modulus = data.eat("%is" % len1)[:2 * chunk]
        self.prime1 = data.eat("%is" % (len1 / 2))[:chunk]
        self.prime2 = data.eat("%is" % (len1 / 2))[:chunk]
        self.exponent1 = data.eat("%is" % (len1 / 2))[:chunk]
        self.exponent2 = data.eat("%is" % (len1 / 2))[:chunk]
        self.coefficient = data.eat("%is" % (len1 / 2))[:chunk]
        self.privExponent = data.eat("%is" % len1)[:2 * chunk]
        self.asn1 = self.RSAKeyASN1()
        ll = lambda x: long(x[::-1].encode('hex'), 16)
        self.asn1.setComponentByName('version', 0)
        self.asn1.setComponentByName('modulus', ll(self.modulus))
        self.asn1.setComponentByName('pubexpo', self.pubexp)
        self.asn1.setComponentByName('privexpo', ll(self.privExponent))
        self.asn1.setComponentByName('prime1', ll(self.prime1))
        self.asn1.setComponentByName('prime2', ll(self.prime2))
        self.asn1.setComponentByName('exponent1', ll(self.exponent1))
        self.asn1.setComponentByName('exponent2', ll(self.exponent2))
        self.asn1.setComponentByName('coefficient', ll(self.coefficient))

    def __repr__(self):
        s = ["RSA key pair",
             "\tPublic exponent = %d" % self.pubexp,
             "\tModulus (n)     = %s" % self.modulus.encode('hex'),
             "\tPrime 1 (p)     = %s" % self.prime1.encode('hex'),
             "\tPrime 2 (q)     = %s" % self.prime2.encode('hex'),
             "\tExponent 1      = %s" % self.exponent1.encode('hex'),
             "\tExponent 2      = %s" % self.exponent2.encode('hex'),
             "\tCoefficient     = %s" % self.coefficient.encode('hex'),
             "\tPrivate exponent= %s" % self.privExponent.encode('hex')]
        return "\n".join(s)

    def export(self):
        """This functions exports the RSA key pair in PEM format"""
        import base64
        s = ['-----BEGIN RSA PRIVATE KEY-----']
        text = base64.encodestring(encoder.encode(self.asn1))
        s.append(text.rstrip("\n"))
        s.append('-----END RSA PRIVATE KEY-----')
        return "\n".join(s)


if __name__ == "__main__":
    parser = OptionParser()

    parser.add_option("--rsafile", metavar="FILE", dest="rsafile", help="Decrypted RSA key (RSA2....)")
    parser.add_option("--certfile", metavar="FILE", dest="certfile",  help="Microsoft certificate file (DER, cer)")
    parser.add_option("--pfxdir", metavar="DIRECTORY", dest="pfxdir", help="PFX output directory")
    parser.add_option("--log", metavar="FILE", dest="log")

    (options, args) = parser.parse_args()

    if options.pfxdir:
        pfxpref = options.pfxdir
    else:
        pfxpref = "./"

    if options.rsafile and options.certfile:
        with open(options.rsafile, "rb") as rsakey:
            rsablob = rsakey.read()
            rsakey=RSAKey(rsablob)


        with open(options.certfile, "rb") as certfile:
            certblob = certfile.read()
            cert=Cert(certblob)

        p12 = OpenSSL.crypto.PKCS12()
        p12.set_privatekey(OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, rsakey.export()))
        p12.set_certificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, cert.certificate))

        with open("%s/%s.pfx" % (pfxpref, cert.name), "wb") as pfx_out:
            try:
                pfx_out.write(p12.export())
            except:
                print "Error reassembling certificate and private key : %s-%s.pfx" % (cert.name, options.rsafile)
        #print "Successfully reassembled certificate and private key : %s-%s.pfx" % (cert.name, options.rsafile)


    exit()
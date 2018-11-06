#!/usr/bin/env python2

#############################################################################
##                                                                         ##
## This file is part of DPAPIck                                            ##
## Windows DPAPI decryption & forensic toolkit                             ##
##                                                                         ##
##                                                                         ##
## Copyright (C) 2010, 2011 Cassidian SAS. All rights reserved.            ##
## This document is the property of Cassidian SAS, it may not be copied or ##
## circulated without prior licence                                        ##
##                                                                         ##
##  Author: Jean-Michel Picod <jmichel.p@gmail.com>                        ##
##                                                                         ##
## This program is distributed under GPLv3 licence (see LICENCE.txt)       ##
##                                                                         ##
#############################################################################

from DPAPI.Core import masterkey
import sys
#sys.path.insert(0, '/opt/dapi/jmichel-dpapick/DPAPI/Core')
#import masterkey
#sys.path.insert(0, '/opt/dapi/jmichel-dpapick/DPAPI/Probes')
#import certificate
from DPAPI import probe
from DPAPI.Probes import certificate

import hashlib
import os
import OpenSSL
import sys
import binascii

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



if __name__ == "__main__":
    parser = OptionParser()
    parser.add_option("--sid", metavar="SID", dest="sid")
    parser.add_option("--masterkey", metavar="DIRECTORY", dest="masterkeydir")
    parser.add_option("--credhist", metavar="FILE", dest="credhist")
    parser.add_option("--password", metavar="PASSWORD", dest="password")
    parser.add_option("--hash", metavar="HASH", dest="h")
    parser.add_option("--private_keys", metavar="DIRECTORY", dest="privkeys")
    parser.add_option("--certificates", metavar="DIRECTORY", dest="certs")
    parser.add_option("--domainkey", metavar="FILE", dest="domkey")
    parser.add_option("--log", metavar="FILE", dest="log")
    parser.add_option("--rsaout", metavar="DIRECTORY", dest="rsaout") #output decdrypted blobs  to comp. files
    parser.add_option("--pfxdir", metavar="DIRECTORY", dest="pfxdir")



    (options, args) = parser.parse_args()

    if options.pfxdir:    
        pfxpref = options.pfxdir
    else:
        pfxpref = "./"

    if options.rsaout:    
        rsapref = options.rsaout
    else:
        rsapref = "./"



    if options.password and options.h:
        print >> sys.stderr, "Choose either password or hash option"
        sys.exit(1)
    if options.password:
        options.h = hashlib.sha1(options.password.encode("UTF-16LE")).hexdigest()
	options.h = options.h.decode('hex')

    if options.log:
            log_out = open(options.log, "a")

    if options.masterkeydir and options.domkey: 
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        decrn = mkp.try_domain(options.domkey)
        print "Decrypted masterkeys: "+str(decrn)
        if options.log:
            log_out.write("Decrypted masterkeys: "+str(decrn)+"\n")
        #print mkp

    if options.masterkeydir and options.password and options.sid:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        decrn = mkp.try_credential(options.sid,options.password)
        print "Decrypted masterkeys: "+str(decrn)
        if options.log:
            log_out.write("Decrypted masterkeys: "+str(decrn)+"\n")

    
    keys = {}
    certs = {}
    for privkey_item in os.listdir(options.privkeys):
        try:
            with open(os.path.join(options.privkeys, privkey_item), "rb") as pkey:
                datablob = certificate.PrivateKeyBlob(pkey.read())
                if datablob.try_decrypt_with_hash(options.h, mkp, options.sid):
                    print "Decrypted private key %s from %s" % (datablob.description, os.path.join(options.privkeys, privkey_item))
                    if options.rsaout:
                        #print "Debug writing rsa. Name: "+datablob.description 
                        with open("%s/%s.rsa" % (str(rsapref),str(datablob.description).rstrip("\x00")), "wb") as rsa_out:
                            rsa_out.write(datablob.export())
                            rsa_out.close()
                    if options.log:
                        log_out.write("Decrypted private key %s from %s\n" % (datablob.description, os.path.join(options.privkeys, privkey_item)))
                    #keys[datablob.description.rstrip("\x00")] = datablob
                    datablob.description=datablob.description.rstrip("\x00")
                    keys[privkey_item] = datablob

        except Exception as ex:
            print "ERROR while reading private key %s: %s" % (os.path.join(options.privkeys, privkey_item), ex)
            if options.log:
                log_out.write("ERROR while reading private key %s: %s\n" % (os.path.join(options.privkeys, privkey_item), ex))
    
    for cert_file in os.listdir(options.certs):
        try:
            with open(os.path.join(options.certs, cert_file), "rb") as cert:
                c = Cert(cert.read())
                if hasattr(c, "name") and hasattr(c, "certificate"):
                    certs[c.name] = c.certificate
                    print "Found certificate associated with key %s: %s" % (c.name, os.path.join(options.certs, cert_file))
                    if options.log:
                        log_out.write("Found certificate associated with key %s: %s\n" % (c.name, os.path.join(options.certs, cert_file)))
        except Exception as ex:
            print "ERROR while reading certificate %s: %s" % (os.path.join(options.certs, cert_file), ex)
            if options.log:
                log_out.write("ERROR while reading certificate %s: %s\n" % (os.path.join(options.certs, cert_file), ex))

    
    #print "Private Keys:"
    #print keys
    
    #print "Certs:"
    #print certs

    print "trying reassemdble PFX..."
    if options.log:
        log_out.write("trying reassemdble PFX...\n")


    for name in keys:
        for crt in certs:
            #print "current cert:"
            #print str(crt)
            if str(keys[name].description).rstrip("\x00") == str(crt).rstrip("\x00"):
            #if name in certs:
            #if 1 == 1:
                try:
                    p12 = OpenSSL.crypto.PKCS12()
                    p12.set_privatekey(OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, keys[name].export()))
                    #p12.set_certificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, certs[name]))
                    p12.set_certificate(OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_ASN1, certs[keys[name].description]))
                    with open("%s/%s-%s.pfx" % (pfxpref,keys[name].description,name), "wb") as pfx_out:
                        pfx_out.write(p12.export())
                    print "Successfully reassembled private key and certificate: %s-%s.pfx" % (keys[name].description,name)
                    if options.log:
                        log_out.write("Successfully reassembled private key and certificate: %s-%s.pfx\n" % (keys[name].description,name))

                except:
                    print "Error with reassembling private key and certificate: %s.pfx" % name
                    if options.log:
                        log_out.write("Error with reassembling private key and certificate: %s.pfx\n" % name)

            #else:
                #print "ERROR cannot associate private key %s with a matching certificate" % name

# vim:ts=4:expandtab:sw=4

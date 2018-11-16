#!/usr/bin/env python
# vim:ts=4:expandtab:sw=4
from DPAPI import probe
from DPAPI.Core import blob
from DPAPI.Core import masterkey

import argparse
import base64
import hashlib

import binascii

class GenericDecryptor(probe.DPAPIProbe):

    def parse(self, data):
        self.dpapiblob = blob.DPAPIBlob(data.remain())

    def __getattr__(self, name):
        return getattr(self.dpapiblob, name)

    def __repr__(self):
        s = ["Generic password decryptor"]
        if self.dpapiblob is not None and self.dpapiblob.decrypted:
            s.append("        password = %s" % self.cleartext)
        s.append("    %r" % self.dpapiblob)
        return "\n".join(s)


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument("--sid", metavar="SID", dest="sid")
    parser.add_argument("--masterkey", required=True, metavar="DIRECTORY", dest="masterkeydir")
    parser.add_argument("--credhist", required=False, metavar="FILE", dest="credhist")
    parser.add_argument("--password", required=False, metavar="PASSWORD", dest="password")
    parser.add_argument("--hash", required=False, metavar="PASSWORD", dest="hash")
    parser.add_argument("--inputfile", required=True, metavar="FILE", dest="inputfile")
    parser.add_argument("--base64file", required=False, metavar="FILE", dest="b64file")
    parser.add_argument("--syskey", required=False, metavar="PASSWORD", dest="syskey", help="DPAPI_SYSTEM string. 01000000...")
    parser.add_argument("--pkey", required=False, metavar="Private domain KEY", dest="pkey")
                      #help="lines with base64-encoded password blobs")

    options = parser.parse_args()

    #print mkp

    if options.credhist != None:
        mkp.addCredhistFile(options.sid, options.credhist)

    if options.pkey:
        decrn = mkp.try_domain(options.pkey)
        if decrn > 0:
            print "Decrypted: "+str(decrn)
            for mkl in mkp.keys.values(): #mkl - list with mk, mkbackup, mkdomain
             for mk in mkl:
                print mk.guid
                #print mk.masterkey

    if options.masterkeydir and options.password and options.sid:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        decrn = mkp.try_credential(options.sid,options.password)
        print "Decrypted masterkeys: "+str(decrn)

    if options.masterkeydir and options.hash and options.sid:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        options.hash = options.hash.decode('hex')
        #mkp.addSystemCredential(binascii.unhexlify("01000000ab83644559741d8526767223d8e159b8ffbb79c30412d7717ef85e651b493abfcefce61d79f3b521"))
        decrn = mkp.try_credential_hash(options.sid, options.hash)
        print "Decrypted masterkeys: " + str(decrn)
        #print mkp

    if options.masterkeydir and options.syskey:
        mkp = masterkey.MasterKeyPool()
        mkp.loadDirectory(options.masterkeydir)
        mkp.addSystemCredential(binascii.unhexlify(options.syskey))
        decrn = mkp.try_credential_hash(None, None)
        print "Decrypted masterkeys: " + str(decrn)

    #if options.password:
    #    options.hash = hashlib.sha1(options.password.encode("UTF-16LE")).hexdigest()
    #    options.hash = options.hash.decode('hex')

    if options.inputfile:
        with open(options.inputfile, "rb") as file:
            data=file.read()
        probe = GenericDecryptor(data)
        #if probe.try_decrypt_with_password(options.password, mkp, options.sid):
        if probe.try_decrypt_with_hash(options.hash, mkp, options.sid):
            print("Decrypted clear: %s" % probe.cleartext)
            print("Decrypted hex: %s" % binascii.hexlify(probe.cleartext))

    if options.b64file:
        with open(options.b64file, 'r') as f:
            lines = f.readlines()

        for line in lines:
            probe = GenericDecryptor(base64.b64decode(line))
            print(probe)

            if probe.try_decrypt_with_password(options.password, mkp, options.sid):
                print("Decrypted clear: %s" % probe.cleartext)
                print("Decrypted hex: %s" % binascii.hexlify(probe.cleartext))
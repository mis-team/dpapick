#!/usr/bin/env python
# vim:ts=4:expandtab:sw=4
from DPAPI import probe
from DPAPI.Core import blob
from DPAPI.Core import masterkey

import argparse
import base64


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
    parser.add_argument("--inputfile", required=True, metavar="FILE", dest="inputfile")
    parser.add_argument("--pkey", required=False, metavar="Private domain KEY", dest="pkey")
                      #help="lines with base64-encoded password blobs")

    options = parser.parse_args()

    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
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


    with open(options.inputfile, 'r') as f:
        lines = f.readlines()

    for line in lines:
        probe = GenericDecryptor(base64.b64decode(line))
        print probe

        if probe.try_decrypt_with_password(options.password, mkp, options.sid):
            print("Decrypted: %s" % probe.cleartext)

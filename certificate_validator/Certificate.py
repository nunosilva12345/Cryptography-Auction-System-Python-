import datetime
import os
import re

from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.x509 import NameOID, ExtensionOID
import pem

crl_dir = "certificate_validator/crl/"

def verify_crl(eval_pem, crl, folder):
    with open(folder, "rb") as file:
        bad_pems = x509.load_der_x509_crl(file.read(), backend=default_backend())
        #get_revoked_certificate_by_serial_number(serial_number)
        if not bad_pems.get_revoked_certificate_by_serial_number(eval_pem.serial_number):
            print("Not revoked!")
            if eval_pem.not_valid_before < datetime.datetime.now() and eval_pem.not_valid_after > datetime.datetime.now():
                print("Not outdated!")
                return True
        return False

def verify_signature(lower, upper):
    sign = lower.signature

    issuer_public_key = upper.public_key()
    cert_to_check = lower

    try:
        issuer_public_key.verify(
            cert_to_check.signature,
            cert_to_check.tbs_certificate_bytes,
            # Depends on the algorithm used to create the certificate
            padding.PKCS1v15(),

            cert_to_check.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False


class Certificate_Knot():
    def __init__(self, der):
        try:
            self.der = x509.load_der_x509_certificate(der, backend=default_backend())
        except ValueError:
            self.der = x509.load_pem_x509_certificate(der, backend=default_backend())
        self.nextUp = None

        self.build_certificate_path()

    def build_certificate_path(self):
        cc = re.compile("Cartão de Cidadão \d{3}")
        ec = re.compile("EC de Autenticação do Cartão de Cidadão \d{4}")

        issuer = self.der.issuer
        pems = pem.parse_file("/etc/ssl/certs/PTEID.pem")
        for x in pems:
            current = x509.load_pem_x509_certificate(x.as_bytes(), backend=default_backend())
            if issuer == current.subject:
                #PTeID found!
                commonName = self.der.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value

                basic_constraints = current.extensions.get_extension_for_oid(ExtensionOID.BASIC_CONSTRAINTS)
                certif_authority_val = basic_constraints.value
                if certif_authority_val.ca:
                    print("CA Basic Constraints flag set to True, all is well.")
                else:
                    print("CA CONSTRAINT FLAG IS FALSE")
                    break

                if cc.match(commonName):
                    print("EC: ", commonName)
                    num = commonName[-3:]
                    if not verify_crl(current, num, crl_dir + "cc_ec_cidadao_crl{}_crl.crl".format(num)):
                        print("Didn't work...")
                        return
                elif ec.match(commonName):
                    print("CC: ", commonName)
                    num = commonName[-4:]

                    with os.scandir(crl_dir) as it:
                        for entry in it:
                            if not entry.name.startswith("cc_sub-ec_cidadao_autenticacao_crl{}".format(num)) \
                                    and entry.is_file():
                                print(entry.name)
                                if not verify_crl(current, num, crl_dir + entry.name):
                                    print("Didn't work...")
                                    return
                else:
                    print("00: ", commonName)

                if verify_signature(self.der, current):
                    print("Signature OK!")

                self.nextUp = Certificate_Knot(x.as_bytes())

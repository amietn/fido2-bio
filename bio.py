# Copyright (c) 2020 Yubico AB
# All rights reserved.
#
#   Redistribution and use in source and binary forms, with or
#   without modification, are permitted provided that the following
#   conditions are met:
#
#    1. Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#    2. Redistributions in binary form must reproduce the above
#       copyright notice, this list of conditions and the following
#       disclaimer in the documentation and/or other materials provided
#       with the distribution.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
# "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
# LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS
# FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE
# COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT,
# INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
# BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
# CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
# LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
# ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.


import argparse
import sys
from getpass import getpass

from fido2.ctap2 import Ctap2, FPBioEnrollment, CaptureError
from fido2.ctap2.bio import BioEnrollment
from fido2.ctap2.pin import ClientPin
from fido2.hid import CtapHidDevice


def get_parser():
    prog_name = "bio"
    arg_parser = argparse.ArgumentParser(
        prog=prog_name,
        description="Manage FIDO2 fingerprints",
    )
    arg_parser.add_argument(
        "--list",
        action="store_true",
        dest="list",
        help=f"List registered fingerprints",
    )
    arg_parser.add_argument(
        "--add",
        action="store_true",
        dest="add",
        help="Enroll a new fingerprint",
    )

    return arg_parser


def enroll():
    ctap = get_dev()

    # Authenticate with PIN
    print("Preparing to enroll a new fingerprint.")
    pin = getpass("Please enter PIN: ")
    client_pin = ClientPin(ctap)
    pin_token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.BIO_ENROLL)
    bio = FPBioEnrollment(ctap, client_pin.protocol, pin_token)

    # Start enrollment
    enroller = bio.enroll()
    template_id = None
    while template_id is None:
        print("Press your fingerprint against the sensor now...")
        try:
            template_id = enroller.capture()
            print(enroller.remaining, "more scans needed.")
        except CaptureError as e:
            print(e)
    bio.set_name(template_id, "Fingerprint")

    print("Fingerprint registered successfully with ID:", template_id)


def list_fingerprints():
    ctap = get_dev()

    # Authenticate with PIN
    print("Preparing to enroll a new fingerprint.")
    pin = getpass("Please enter PIN: ")
    client_pin = ClientPin(ctap)
    pin_token = client_pin.get_pin_token(pin, ClientPin.PERMISSION.BIO_ENROLL)
    bio = FPBioEnrollment(ctap, client_pin.protocol, pin_token)

    print(bio.enumerate_enrollments())


def get_dev():
    for dev in CtapHidDevice.list_devices():
        try:
            ctap = Ctap2(dev)
            if BioEnrollment.is_supported(ctap.info):
                break
        except Exception:  # nosec
            continue
    else:
        print("No Authenticator supporting bioEnroll found")
        sys.exit(1)
    if not ctap.info.options.get("clientPin"):
        print("PIN not set for the device!")
        sys.exit(1)
    return ctap


if __name__ == '__main__':
    parser = get_parser()
    args = parser.parse_args()

    if args.list:
        list_fingerprints()
    elif args.add:
        enroll()
    else:
        parser.print_usage()

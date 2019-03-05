#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2016 Johannes Bauer
#
#	This file is part of joeecc.
#
#	joeecc is free software; you can redistribute it and/or modify
#	it under the terms of the GNU General Public License as published by
#	the Free Software Foundation; this program is ONLY licensed under
#	version 3 of the License, later versions are explicitly excluded.
#
#	joeecc is distributed in the hope that it will be useful,
#	but WITHOUT ANY WARRANTY; without even the implied warranty of
#	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#	GNU General Public License for more details.
#
#	You should have received a copy of the GNU General Public License
#	along with joeecc; if not, write to the Free Software
#	Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
#
#	Johannes Bauer <JohannesBauer@gmx.de>
#

import unittest
import tempfile
import uuid
import os
from ..ECPrivateKey import ECPrivateKey
from ..ECPublicKey import ECPublicKey
from ..Exceptions import NoSuchCurveException, UnsupportedFieldException
from ..ASN1 import have_asn1_support
from .. import getcurvebyname

class _Tempfile(object):
	def __init__(self, content):
		self._content = content
		self._filename = None

	def __enter__(self):
		assert(self._filename is None)
		self._filename = tempfile.gettempdir() + "/tmp_joeecc_" + str(uuid.uuid4())
		with open(self._filename, "w") as f:
			print(self._content, file = f)
		return self._filename

	def __exit__(self, *args):
		assert(self._filename is not None)
		os.unlink(self._filename)


@unittest.skipIf(not have_asn1_support(), "ASN.1 support not available")
class KeyLoadStoreTests(unittest.TestCase):
	_PRIVKEY_PEM_OID = _Tempfile("""-----BEGIN EC PARAMETERS-----
BgUrgQQAHQ==
-----END EC PARAMETERS-----
-----BEGIN EC PRIVATE KEY-----
MEQCAQEEEArzxc2vyxUaQdXEj9bdkHmgBwYFK4EEAB2hJAMiAATKd4WyFLzs86V0
TTQRwZ1rda0gr5vCWg+t15qmrmSevA==
-----END EC PRIVATE KEY-----
""")

	_PRIVKEY_PEM_EXPLICIT = _Tempfile("""-----BEGIN EC PRIVATE KEY-----
MIHXAgEBBBAK88XNr8sVGkHVxI/W3ZB5oIGZMIGWAgEBMBwGByqGSM49AQECEQD/
///9////////////////MDsEENYDGZjRs7v+v1nMm7/5ruEEEF7u/KOA0CkZ3Cxl
WLttil0DFQAATWluZ2h1YVF1EtjwNDH85juI9AQhBHtqpdheVymD5vsyp83rwUAn
tpFqiU067nEG/oBfw0tEAhA/////f////74AJHIGE7WjAgEEoSQDIgAEyneFshS8
7POldE00EcGda3WtIK+bwloPrdeapq5knrw=
-----END EC PRIVATE KEY-----
""")

	_PRIVKEY_PEM_F2M_OID = _Tempfile("""-----BEGIN EC PRIVATE KEY-----
MEcCAQEEEQFnPiX+TOQzUFepnIjE1d3QoAcGBSuBBAAWoSYDJAAEAtQX7xbkBCiu
HuYYzjcKY64EuBxr4Es8/Is+UnZZ3oV+zQ==
-----END EC PRIVATE KEY-----
""")

	_PRIVKEY_PEM_F2M_EXPLICIT = _Tempfile("""-----BEGIN EC PRIVATE KEY-----
MIHoAgEBBBEBZz4l/kzkM1BXqZyIxNXd0KCBpzCBpAIBATAlBgcqhkjOPQECMBoC
AgCDBgkqhkjOPQECAwMwCQIBAgIBAwIBCDA9BBEHoRsJp2tWIURBj/P/jCVwuAQR
AhfAVhCIS2O5xscpFnj500EDFQBNaW5naHVhUXWYW9OtutohtDqX4gQjBACBuvkf
35gzxA+cGBNDY4OZB4xufqOMAB9zyBNLG0754VACEQQAAAAAAAAAAjEjlTqUZLVN
AgECoSYDJAAEAtQX7xbkBCiuHuYYzjcKY64EuBxr4Es8/Is+UnZZ3oV+zQ==
-----END EC PRIVATE KEY-----
""")

	_PUBKEY_PEM_OID = _Tempfile("""-----BEGIN PUBLIC KEY-----
MDIwEAYHKoZIzj0CAQYFK4EEAAYDHgAEF+RQ5RcwZ36icW199nTPE8AvIMZr4uRk
vKaJtw==
-----END PUBLIC KEY-----
""")

	_PUBKEY_PEM_EXPLICIT = _Tempfile("""-----BEGIN PUBLIC KEY-----
MIG6MIGXBgcqhkjOPQIBMIGLAgEBMBoGByqGSM49AQECDwDbfCq/YuNeZoB2vq0g
izA3BA7bfCq/YuNeZoB2vq0giAQOZZ74ugQ5Fu7eiRFwKyIDFQAA9QsCjk1pbmdo
dWFRdSkEcng/sQQdBAlIcjmZWl7na1X5wvCYqJzlr4ckwKI+Dg/3dQACDwDbfCq/
YuNedijfrGVhxQIBAQMeAAQX5FDlFzBnfqJxbX32dM8TwC8gxmvi5GS8pom3
-----END PUBLIC KEY-----
""")


	def test_load_privkey_fp_oid(self):
		with self._PRIVKEY_PEM_OID as filename:
			key = ECPrivateKey.load_pem(filename)
		self.assertEqual(key.scalar, 0x0af3c5cdafcb151a41d5c48fd6dd9079)
		self.assertEqual(key.pubkey.point.x, 0xca7785b214bcecf3a5744d3411c19d6b)
		self.assertEqual(key.pubkey.point.y, 0x75ad20af9bc25a0fadd79aa6ae649ebc)

	def test_load_privkey_fp_explicit(self):
		with self._PRIVKEY_PEM_EXPLICIT as filename:
			key = ECPrivateKey.load_pem(filename)
		self.assertEqual(key.scalar, 0x0af3c5cdafcb151a41d5c48fd6dd9079)
		self.assertEqual(key.pubkey.point.x, 0xca7785b214bcecf3a5744d3411c19d6b)
		self.assertEqual(key.pubkey.point.y, 0x75ad20af9bc25a0fadd79aa6ae649ebc)
		self.assertEqual(key.curve, getcurvebyname("secp128r2"))

	def test_load_privkey_f2m_oid(self):
		with self._PRIVKEY_PEM_F2M_OID as filename:
			with self.assertRaises(NoSuchCurveException):
				# No such OID in database
				ECPrivateKey.load_pem(filename)

	def test_load_privkey_f2m_explicit(self):
		with self._PRIVKEY_PEM_F2M_EXPLICIT as filename:
			with self.assertRaises(UnsupportedFieldException):
				# Unsupported field F(2^m)
				ECPrivateKey.load_pem(filename)

	def test_load_pubkey_fp_oid(self):
		with self._PUBKEY_PEM_OID as filename:
			key = ECPublicKey.load_pem(filename)
			self.assertEqual(key.point.x, 0x17e450e51730677ea2716d7df674)
			self.assertEqual(key.point.y, 0xcf13c02f20c66be2e464bca689b7)
			self.assertEqual(key.point.curve, getcurvebyname("secp112r1"))

	def test_load_pubkey_fp_explicit(self):
		with self._PUBKEY_PEM_EXPLICIT as filename:
			key = ECPublicKey.load_pem(filename)
			self.assertEqual(key.point.x, 0x17e450e51730677ea2716d7df674)
			self.assertEqual(key.point.y, 0xcf13c02f20c66be2e464bca689b7)
			self.assertEqual(key.point.curve, getcurvebyname("secp112r1"))


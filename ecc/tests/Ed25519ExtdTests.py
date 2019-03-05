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
import random
from .. import FieldElement, getcurvebyname, ECPrivateKey, ECPublicKey, AffineCurvePoint

class Testcase(object):
	def __init__(self, name, params):
		self._name = name
		self._params = params

	@property
	def name(self):
		return self._name

	@staticmethod
	def parse_Bytes(value):
		return bytes.fromhex(value)

	@staticmethod
	def parse_Int(value):
		return int(value)

	def dump(self):
		for key in sorted(list(self._params.keys())):
			value = self._params[key]
			if isinstance(value, bytes):
				value = "(%d) " % (len(value)) + "".join("%02x" % (c) for c in value)
			else:
				value = str(value)
			print("%-20s: %s" % (key, value))

	def __getitem__(self, key):
		return self._params[key]

	def __str__(self):
		return "Testcase<%s [%s]>" % (self.name, ", ".join(sorted(list(self._params.keys()))))

def tcs_from_file(filename):
	with open(filename, "r") as f:
		for line in f:
			line = line.rstrip("\r\n")
			line = line.split("|")

			tcname = line[0]
			prototypes = [ arg.split(":") for arg in line[1].split(",") ]
			values = line[2:]

			assert(len(prototypes) == len(values))
			parsed_values = { }
			for ((vartype, varname), value) in zip(prototypes, values):
				parser = getattr(Testcase, "parse_" + vartype)
				value = parser(value)
				parsed_values[varname] = value
			yield Testcase(tcname, parsed_values)

class Ed25519ExtdTests(unittest.TestCase):
	_TEST_SCOPE = "minimal"

	@classmethod
	def set_test_scope(cls, scope):
		cls._TEST_SCOPE = scope

	def setUp(self):
		self._basedir = "testdata/curve25519/"
		self._curve = getcurvebyname("ed25519")

	def _run_EncodePoint(self, tc):
		point = AffineCurvePoint(tc["X"], tc["Y"], self._curve)
		encoded = point.eddsa_encode()
		self.assertTrue(isinstance(encoded, bytes))
		self.assertTrue(len(encoded) == 32)
		self.assertEqual(encoded, tc["EncodedPoint"])
		self.assertEqual(AffineCurvePoint.eddsa_decode(self._curve, tc["EncodedPoint"]), point)

	def _run_SignData(self, tc):
		pubkey = AffineCurvePoint.eddsa_decode(self._curve, tc["EncodedPubKey"])
		keypair = ECPrivateKey.eddsa_decode(self._curve, tc["EncodedPrivKey"])
		self.assertEqual(keypair.pubkey.point, pubkey)
		signature = keypair.eddsa_sign(tc["Message"])
		self.assertEqual(signature.encode(), tc["Signature"])
		self.assertTrue(keypair.pubkey.eddsa_verify(tc["Message"], signature))
		self.assertFalse(keypair.pubkey.eddsa_verify(tc["Message"] + b"x", signature))

	def test_encodepoint(self):
		for testcase in tcs_from_file(self._basedir + "encodepoint.txt"):
			handlername = "_run_" + testcase.name
			handler = getattr(self, handlername)
			handler(testcase)

	def test_djb_sigs(self):
		for testcase in tcs_from_file(self._basedir + "djb.txt"):
			# Skip lots of tests randomly for time reasons
			if (self._TEST_SCOPE == "minimal") and (random.randrange(100) > 0):
				continue

			handlername = "_run_" + testcase.name
			handler = getattr(self, handlername)
			handler(testcase)


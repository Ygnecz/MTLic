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
from .. import FieldElement, getcurvebyname, ECPublicKey, ECPrivateKey

class Ed25519BasicTests(unittest.TestCase):
	def test_sign_verify(self):
		curve = getcurvebyname("ed25519")
		privkey = ECPrivateKey.eddsa_generate(curve)

		msg = b"foobar"
		signature = privkey.eddsa_sign(msg)

		self.assertTrue(privkey.pubkey.eddsa_verify(msg, signature))
		self.assertFalse(privkey.pubkey.eddsa_verify(msg + b"x", signature))

	def test_sig_encode_decode(self):
		curve = getcurvebyname("ed25519")
		privkey = ECPrivateKey.eddsa_generate(curve)
		msg = b"foobar"
		signature = privkey.eddsa_sign(msg)

		encoded_signature = signature.encode()
		decoded_signature = ECPrivateKey.EDDSASignature.decode(curve, encoded_signature)
		self.assertEqual(decoded_signature, signature)
		self.assertTrue(privkey.pubkey.eddsa_verify(msg, signature))
		self.assertTrue(privkey.pubkey.eddsa_verify(msg, decoded_signature))

	def test_seeding_signing(self):
		curve = getcurvebyname("ed25519")
		seed = bytes.fromhex("5da0ed08799092411e90140e7b86058276fe293efd40afa816bc0ccc3f43492e")

		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)
		self.assertEqual(privkey.seed, seed)
		self.assertEqual(privkey.scalar, 55506792121812326601863127824214732996787216741471646079326674346494898512112)

		pubkey = privkey.pubkey
		self.assertEqual(pubkey.point.x, 0x7de7bc3e0b0c077c2a104623a8e66cb7d9ffb3b1a594969bb55997dbe66d4264)
		self.assertEqual(pubkey.point.y, 0x704f7339f697f88d190052a76091805f24c77aa232acf69b19082fa036967744)

		msg = b"Foobar!"
		signature = privkey.eddsa_sign(msg)

		self.assertEqual(signature.R.x, 0x7fc3a9aca15bb635bc471c6fd410f12e3658e0b226452f025992c931ab61fc18)
		self.assertEqual(signature.R.y, 0x3a5902651bf0eb71dfbb604d3e20511821f7e720b5814e8a9b744aede20e7986)
		self.assertEqual(signature.s, 1517157819819635474038904401642496669072502937558957834094270557835510822428)


	def test_key_encoding(self):
		curve = getcurvebyname("ed25519")
		seed = bytes.fromhex("5da0ed08799092411e90140e7b86058276fe293efd40afa816bc0ccc3f43492e")

		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)

		self.assertEqual(privkey.eddsa_encode(), bytes.fromhex("5da0ed08799092411e90140e7b86058276fe293efd40afa816bc0ccc3f43492e"))
		self.assertEqual(privkey.pubkey.eddsa_encode(), bytes.fromhex("44779636a02f08199bf6ac32a27ac7245f809160a75200198df897f639734f70"))

	def test_key_decoding(self):
		curve = getcurvebyname("ed25519")
		seed = bytes.fromhex("5da0ed08799092411e90140e7b86058276fe293efd40afa816bc0ccc3f43492e")

		privkey = ECPrivateKey.eddsa_decode(curve, bytes.fromhex("5da0ed08799092411e90140e7b86058276fe293efd40afa816bc0ccc3f43492e"))
		self.assertEqual(privkey.seed, seed)
		self.assertEqual(privkey.scalar, 55506792121812326601863127824214732996787216741471646079326674346494898512112)

		pubkey = ECPublicKey.eddsa_decode(curve, bytes.fromhex("44779636a02f08199bf6ac32a27ac7245f809160a75200198df897f639734f70"))
		self.assertEqual(pubkey.point, privkey.pubkey.point)


	def test_sig_encoding(self):
		curve = getcurvebyname("ed25519")
		seed = bytes.fromhex("5da0ed08799092411e90140e7b86058276fe293efd40afa816bc0ccc3f43492e")

		privkey = ECPrivateKey.eddsa_generate(curve, seed = seed)

		msg = b"Foobar!"
		signature = privkey.eddsa_sign(msg)

		self.assertEqual(signature.encode(), bytes.fromhex("86790ee2ed4a749b8a4e81b520e7f7211851203e4d60bbdf71ebf01b6502593a1c36ca859621a386dfaa79c5a24bb6eef1111c76bfb7fc0c48491b2b4fae5a03"))

	def test_sig_decoding(self):
		curve = getcurvebyname("ed25519")
		encoded_sig = bytes.fromhex("86790ee2ed4a749b8a4e81b520e7f7211851203e4d60bbdf71ebf01b6502593a1c36ca859621a386dfaa79c5a24bb6eef1111c76bfb7fc0c48491b2b4fae5a03")

		signature = ECPrivateKey.EDDSASignature.decode(curve, encoded_sig)
		self.assertEqual(signature.R.x, 0x7fc3a9aca15bb635bc471c6fd410f12e3658e0b226452f025992c931ab61fc18)
		self.assertEqual(signature.R.y, 0x3a5902651bf0eb71dfbb604d3e20511821f7e720b5814e8a9b744aede20e7986)
		self.assertEqual(signature.s, 1517157819819635474038904401642496669072502937558957834094270557835510822428)

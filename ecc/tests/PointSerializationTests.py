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
from .. import getcurvebyname
from ..AffineCurvePoint import AffineCurvePoint

class PointSerializationTests(unittest.TestCase):
	def _test_curve_point(self, point):
		Pser = point.serialize_uncompressed()
		Pdeser = AffineCurvePoint.deserialize_uncompressed(Pser, point.curve)
		self.assertEqual(Pdeser, point)

	def _test_curve_points(self, curve, expect_points):
		for (scalar, expect_encoding) in expect_points.items():
			P = scalar * curve.G
			Pser = P.serialize_uncompressed()
			self.assertEqual(Pser, expect_encoding)
			deserialized = AffineCurvePoint.deserialize_uncompressed(Pser, curve)
			self.assertEqual(deserialized, P)

	def _get_low_point(self, curve):
		for i in range(1, 1000):
			P = curve.getpointwithx(i)
			if P is not None:
				return P[0]

	def _get_random_point(self, curve):
		for i in range(1, 1000):
			P = curve.getpointwithx(random.randint(1, curve.p))
			if P is not None:
				return P[0]

	def test_secp112r1(self):
		expect_points = {
			0x38b320d1a8c75a275a8c6c6d8df3: bytes.fromhex("040020b65a4224192dab5255eee17d470a3471917b1672ed341a571b73"),
			0x65cd8dbdbd38d7a98a064e4cf741: bytes.fromhex("04000024021cce683926bf0c6ac6b0cd71d968563e2646d9382e27b801"),
		}
		curve = getcurvebyname("secp112r1")
		self._test_curve_points(curve, expect_points)

	def test_secp160r1(self):
		# secp160r1 has 160 bit (20 byte) p, but 161 bit (21 bytes) n
		expect_points = {
			0x415bb31e0096c6255f26618752583f6cb43b5950: bytes.fromhex("0400b80c796da4b9712f52b0a4c18b0dd269d00b473259900e73bc0b8b281dd36dfa0ad36c36f04a99"),
			0x29d5dfd3c7dac354209648ed852bc09f99fdc5e1: bytes.fromhex("0400655731f18c3345cc57e5d1a0d2109e82622896d3ea2928bfab8b74b060a4984d25413a37d232f1"),
			0x1c7929dab7fb01329952d4705608312505d3a5f8: bytes.fromhex("04007ade8f2dbc473b82ff37bab7443eaf7be5e15e2cf24fef5cc3f0e5f3533327c99814c595c44080"),
		}
		curve = getcurvebyname("secp160r1")
		self._test_curve_points(curve, expect_points)

	def test_random_serialization_deserialization(self):
		curve = getcurvebyname("secp112r1")
		for i in range(100):
			P = self._get_random_point(curve)
			self.assertTrue(P.oncurve())
			self._test_curve_point(P)

	def test_low_point(self):
		for curvename in [ "secp112r1", "secp160r1" ]:
			curve = getcurvebyname(curvename)
			self._test_curve_point(self._get_low_point(curve))



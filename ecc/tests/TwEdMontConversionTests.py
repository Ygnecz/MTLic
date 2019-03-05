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

class TwEdMontConversionTests(unittest.TestCase):
	def setUp(self):
		self._mont = getcurvebyname("curve25519")
		self._twed = getcurvebyname("ed25519")

	def test_generator(self):
		Ge = self._twed.G
		self.assertEqual(Ge.convert(self._mont), self._mont.G)

		Gm = self._mont.G
		self.assertEqual(Gm.convert(self._twed), self._twed.G)

	def test_neutral(self):
		Oe = self._twed.neutral()
		self.assertEqual(Oe.convert(self._mont), self._mont.neutral())

		Om = self._mont.neutral()
		self.assertEqual(Om.convert(self._twed), self._twed.neutral())

	def test_scalar_conv_twed_to_mont(self):
		for i in range(2, 1000, 17):
			Pe = self._twed.G * i
			Pm = self._mont.G * i
			self.assertEqual(Pe.convert(self._mont), Pm)

	def test_scalar_conv_mont_to_twed(self):
		for i in range(2, 1000, 17):
			Pe = self._twed.G * i
			Pm = self._mont.G * i
			self.assertEqual(Pm.convert(self._twed), Pe)

	def test_random_ptadds(self):
		P = self._twed.G
		scalar = 1
		self.assertEqual(P, self._twed.G * scalar)
		for i in range(20):
			P = P.convert(self._mont)
			self.assertEqual(P, self._mont.G * scalar)

			r = random.randint(2 ** 32, 2 ** 64)
			Q = self._mont.G * r
			P = P + Q
			scalar += r
			self.assertEqual(P, self._mont.G * scalar)

			P = P.convert(self._twed)
			self.assertEqual(P, self._twed.G * scalar)

			r = random.randint(2 ** 32, 2 ** 64)
			Q = self._twed.G * r
			P = P + Q
			scalar += r
			self.assertEqual(P, self._twed.G * scalar)

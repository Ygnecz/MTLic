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
from ..FieldElement import FieldElement

class FieldElementSqrtTests(unittest.TestCase):
	_PRIME_1_MOD_4 = [
		10153776240248910961,
		13313520292754238121,
		15378050022937467689,
		15438372505554348001,
		15476752070461085857,
		17875746998751974477,
		18057875082506157121,
	]

	_PRIME_3_MOD_4 = [
		10164036603611688719,
		11802848526449265743,
		12398748969631217971,
		12821403563901948251,
		12871176861409354567,
		13022588269702988959,
		13784119435837260871,
	]

	def test_integrity(self):
		for p in self._PRIME_3_MOD_4:
			self.assertEqual(p % 4, 3)

	def _test_primes(self, primeset, testcnt = 30):
		for p in primeset:
			rootable = False
			for i in range(testcnt):
				qsqr = FieldElement(random.randrange(p), p)
				q = qsqr.sqrt()
				if q is not None:
					rootable = True
					(a, b) = q
					self.assertEqual(a * a, qsqr)
					self.assertEqual(b * b, qsqr)
			self.assertTrue(rootable)

	def test_basic(self):
		self._test_primes(self._PRIME_3_MOD_4)

	def test_extd(self):
		self._test_primes(self._PRIME_1_MOD_4)

	def test_small_body(self):
		p = 263
		for i in range(1, p):
			i = FieldElement(i, p)
			q = i.sqr()
			r = q.sqrt()
			self.assertEqual(r[0] * r[0], q)
			self.assertEqual(r[1] * r[1], q)


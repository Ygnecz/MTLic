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

class TwEdMontDomainTests(unittest.TestCase):
	def setUp(self):
		self._mont = getcurvebyname("curve25519")
		self._twed = getcurvebyname("ed25519")

	def test_twed_to_mont(self):
		mont = self._twed.to_montgomery(b = int(self._mont.b))
		self.assertEqual(mont.domainparams, self._mont.domainparams)

	def test_mont_to_twed(self):
		twed = self._mont.to_twistededwards(a = int(self._twed.a))
		self.assertEqual(twed.domainparams, self._twed.domainparams)

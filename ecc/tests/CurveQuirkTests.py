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
from ..CurveQuirks import CurveQuirkEdDSASetPrivateKeyMSB, CurveQuirkEdDSAEnsurePrimeOrderSubgroup

class CurveQuirkTests(unittest.TestCase):
	def test_basic(self):
		s = set([ CurveQuirkEdDSASetPrivateKeyMSB(), CurveQuirkEdDSASetPrivateKeyMSB() ])
		self.assertEqual(len(s), 1)
		self.assertTrue(CurveQuirkEdDSASetPrivateKeyMSB() in s)

		s.add(CurveQuirkEdDSAEnsurePrimeOrderSubgroup())
		self.assertEqual(len(s), 2)

		s.add(CurveQuirkEdDSAEnsurePrimeOrderSubgroup())
		self.assertEqual(len(s), 2)


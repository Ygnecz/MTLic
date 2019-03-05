#
#	joeecc - A small Elliptic Curve Cryptography Demonstration.
#	Copyright (C) 2011-2015 Johannes Bauer
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
from ..Polynomial import Polynomial

class PolyTests(unittest.TestCase):
	def test_intialization(self):
		x = Polynomial(101)
		terms = dict(x)
		self.assertEqual(len(terms), 1)
		self.assertEqual(terms[1], 1)

	def test_add1(self):
		x = Polynomial(101)
		p1 = (50 * x)
		terms = dict(p1)
		self.assertEqual(len(terms), 1)
		self.assertEqual(p1[1], 50)

		p2 = (75 * x**2)
		terms = dict(p2)
		self.assertEqual(len(terms), 1)
		self.assertEqual(p2[2], 75)

	def test_add2(self):
		x = Polynomial(101)
		p = (50 * x) + (75 * x**2) + (99 * x**3)
		terms = dict(p)
		self.assertEqual(len(terms), 3)
		self.assertEqual(p[0], 0)
		self.assertEqual(p[1], 50)
		self.assertEqual(p[2], 75)
		self.assertEqual(p[3], 99)

	def test_mul1(self):
		x = Polynomial(101)
		p = (50 * x) + (75 * x**2) + (99 * x**3)
		q = Polynomial(101, 1)

		terms = dict(p * q)
		self.assertEqual(len(terms), 3)
		self.assertEqual(p[0], 0)
		self.assertEqual(p[1], 50)
		self.assertEqual(p[2], 75)
		self.assertEqual(p[3], 99)

	def test_mod1(self):
		x = Polynomial(101)

		poly = (35 * x**7) + (50 * x**5) + (75 * x**2)
		modpoly = (4 * x**3) + 1
		result = poly % modpoly
		terms = dict(result)
		self.assertEqual(len(terms), 2)
		self.assertEqual(terms[2], 12)
		self.assertEqual(terms[1], 59)

	def test_mod2(self):
		x = Polynomial(101)

		poly = x**10
		modpoly = x**3 + 1
		result = poly % modpoly
		terms = dict(result)
		self.assertEqual(len(terms), 1)
		self.assertEqual(terms[1], 100)

	def test_mod3(self):
		 x = Polynomial(17, 123)
		 y = Polynomial(17, 3)
		 r = x % y
		 self.assertTrue(r.is_constant)
		 self.assertEqual(r.get_constant(), 0)

	def test_pow(self):
		x = Polynomial(101)

		poly = ((35 * x**7) + (50 * x**5) + (75 * x**2)) ** 2
		terms = dict(poly)
		self.assertEqual(len(terms), 6)
		self.assertEqual(terms[14], 13)
		self.assertEqual(terms[12], 66)
		self.assertEqual(terms[10], 76)
		self.assertEqual(terms[9], 99)
		self.assertEqual(terms[7], 26)
		self.assertEqual(terms[4], 70)

	def test_powmod_simple(self):
		x = Polynomial(101)

		poly = (35 * x**7) + (50 * x**5) + (75 * x**2)
		modpoly = (4 * x**4) + 1

		result = poly.powmod(123456, modpoly)

		terms = dict(result)
		self.assertEqual(len(terms), 4)
		self.assertEqual(terms[3], 63)
		self.assertEqual(terms[2], 42)
		self.assertEqual(terms[1], 33)
		self.assertEqual(terms[0], 89)

	def test_powmod_complex(self):
		x = Polynomial(4451685225093714772084598273548427)

		modpoly = x**3 - 3*x + 2061118396808653202902996166388514
		result = x.powmod(x.modulus, modpoly)

		terms = dict(result)
		self.assertEqual(len(terms), 3)
		self.assertEqual(terms[2], 2793233646981728153184490628609256)
		self.assertEqual(terms[1], 3668388619890319418084877212924997)
		self.assertEqual(terms[0], 3316903156223973237800215289878342)

	def test_gcd(self):
		x = Polynomial(101)

		p1 = 74*x**303 + 80*x**302 + 98*x**301 + 79*x**23 + 39*x**22 + 20*x**21 + 90*x**13 + 70*x**12 + 10*x**11
		p2 = 9*x**3 + 7*x**2 + x
		expect_gcd = x**3 + 12*x**2 + 45*x
		expect_div1 = 74*x**300 + 79*x**20 + 90*x**10
		expect_div2 = 9

		gcd1 = p1.gcd(p2)
		gcd2 = p2.gcd(p1)
		self.assertEqual(gcd1, gcd2)
		self.assertEqual(gcd1, expect_gcd)

		self.assertEqual(expect_div1 * expect_gcd, p1)
		self.assertEqual(expect_div2 * expect_gcd, p2)

	def test_parse(self):
		poly = Polynomial.parse_poly("55*x^4 + 99*x^2 - 37*x^1 + x^3 + 2*x + 4", 101)

		terms = dict(poly)
		self.assertEqual(len(terms), 5)
		self.assertEqual(terms[4], 55)
		self.assertEqual(terms[3], 1)
		self.assertEqual(terms[2], 99)
		self.assertEqual(terms[1], -37 + 2)
		self.assertEqual(terms[0], 4)

	def test_div(self):
		x = Polynomial(101)
		p1 = 4*x**9 + 30*x**2 + 9
		p2 = x**4 + 9*x**2 + 10*x + 2

		q = p1 // p2
		r = p1 % p2

		self.assertEqual((q * p2) + r, p1)


	def test_subs(self):
		x = Polynomial(101)
		p = 4*x**9 + 30*x**2 + 9

		self.assertEqual(p.substitute(0), 9)
		self.assertEqual(p.substitute(1), 4 + 30 + 9)
		self.assertEqual(p.substitute(2), (4 * (2 ** 9) + 30 * (2 ** 2)  + 9) % 101)


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

from . import Tools
from .FieldElement import FieldElement
from .Exceptions import UnsupportedPointFormatException

class PointOpEDDSAEncoding(object):
	def eddsa_encode(self):
		"""Performs serialization of the point as required by EdDSA."""
		bitlen = self.curve.p.bit_length()
		enc_value = int(self.y)
		enc_value &= ((1 << bitlen) - 1)
		enc_value |= (int(self.x) & 1) << bitlen
		return Tools.inttobytes_le(enc_value, self.curve.B // 8)

	@staticmethod
	def __eddsa_recoverx(curve, y):
		xx = (y * y - 1) // (curve.d * y * y + 1)
		x = xx ** ((curve.p + 3) // 8)
		if x * x != xx:
			I = FieldElement(-1, curve.p).sqrt()[0]
			x = x * I
		if (int(x) % 2) != 0:
			x = -x
		return int(x)

	@classmethod
	def eddsa_decode(cls, curve, data):
		"""Performs deserialization of the point as required by EdDSA."""
		assert(curve.curvetype == "twistededwards")
		bitlen = curve.p.bit_length()
		enc_value = Tools.bytestoint_le(data)
		y = enc_value & ((1 << bitlen) - 1)
		x = PointOpEDDSAEncoding.__eddsa_recoverx(curve, y)
		hibit = (enc_value >> bitlen) & 1
		if (x & 1) != hibit:
			x = curve.p - x
		return cls(x, y, curve)

class PointOpCurveConversion(object):
	@staticmethod
	def __pconv_twed_mont_scalefactor(twedcurve, montcurve):
		native_b = 4 // (twedcurve.a - twedcurve.d)
		if native_b == montcurve.b:
			# Scaling is not necessary, already native curve format
			scale_factor = 1
		else:
			# Scaling of montgomery y component (v) is needed
			if twedcurve.hasgenerator and montcurve.hasgenerator:
				# Convert the generator point of the twisted edwards source
				# point to unscaled Montgomery space
				Gv = (1 + twedcurve.G.y) // ((1 - twedcurve.G.y) * twedcurve.G.x)

				# And calculate a multiplicative scaling factor so that the
				# point will result in the target curve's generator point Y
				scale_factor = montcurve.G.y // Gv

			elif native_b.is_qr:
				# If b is a quadradic residue mod p then any other
				# quadratic residue can serve as a surrgate b coefficient
				# to yield an isomorphous curve. Only y coordinate of the
				# resulting points needs to be scaled. Calculate a scaling
				# ratio.
				scale_factors = (montcurve.b // native_b).sqrt()

				# At least one of the curves lacks a generator point,
				# select just any scale factor
				scale_factor = scale_factors[0].inverse()

			else:
				# Native B is a quadratic non-residue module B; Not sure
				# how to handle this case
				# TODO: Implement this
				raise Exception(NotImplemented)
		return scale_factor

	def convert(self, targetcurve):
		"""Convert the affine curve point to a point on a birationally
		equivalent target curve."""

		if self.is_neutral:
			return targetcurve.neutral()

		if (self.curve.curvetype == "twistededwards") and (targetcurve.curvetype == "montgomery"):
			# (x, y) are Edwards coordinates
			# (u, v) are Montgomery coordonates
			(x, y) = (self.x, self.y)
			u = (1 + y) // (1 - y)
			v = (1 + y) // ((1 - y) * x)

			# Montgomery coordinates are unscaled to the actual B coefficient
			# of the curve right now. Calculate scaling factor and scale v
			# appropriately
			scaling_factor = self.__pconv_twed_mont_scalefactor(self.curve, targetcurve)
			v = v * scaling_factor

			point = self.__class__(int(u), int(v), targetcurve)
		elif (self.curve.curvetype == "montgomery") and (targetcurve.curvetype == "twistededwards"):
			# (x, y) are Edwards coordinates
			# (u, v) are Montgomery coordonates
			(u, v) = (self.x, self.y)
			y = (u - 1) // (u + 1)
			x = -(1 + y) // (v * (y - 1))

			# Twisted Edwards coordinates are unscaled to the actual B
			# coefficient of the curve right now. Calculate scaling factor and
			# scale x appropriately
			scaling_factor = self.__pconv_twed_mont_scalefactor(targetcurve, self.curve)
			x = x * scaling_factor

			point = self.__class__(int(x), int(y), targetcurve)
		else:
			raise Exception(NotImplemented)

		assert(point.oncurve())
		return point

class PointOpNaiveOrderCalculation(object):
	def naive_order_calculation(self):
		"""Calculates the order of the point naively, i.e. by walking through
		all points until the given neutral element is hit. Note that this only
		works for smallest of curves and is not computationally feasible for
		anything else."""
		curpt = self
		order = 1
		while not curpt.is_neutral:
			order += 1
			curpt += self
		return order


class PointOpSerialization(object):
	def serialize_uncompressed(self):
		"""Serializes the point into a bytes object in uncompressed form."""
		length = (self.curve.p.bit_length() + 7) // 8
		serialized = bytes([ 0x04 ]) + Tools.inttobytes(int(self.x), length) + Tools.inttobytes(int(self.y), length)
		return serialized

	@classmethod
	def deserialize_uncompressed(cls, data, curve = None):
		"""Deserializes a curve point which is given in uncompressed form. A
		curve may be passed with the 'curve' argument in which case an
		AffineCurvePoint is returned from this method. Otherwise the affine X
		and Y coordinates are returned as a tuple."""
		if data[0] != 0x04:
			raise UnsupportedPointFormatException("Generator point of explicitly encoded curve is given in unsupported form (0x%x)." % (data[0]))
		data = data[1:]
		assert((len(data) % 2) == 0)
		Px = Tools.bytestoint(data[ : len(data) // 2])
		Py = Tools.bytestoint(data[len(data) // 2 : ])
		if curve is not None:
			return cls(Px, Py, curve)
		else:
			return (Px, Py)


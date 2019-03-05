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

from .FieldElementTests import FieldElementTests
from .FieldElementSqrtTests import FieldElementSqrtTests
from .ECTests import ECTests
from .CryptoOpsTests import CryptoOpsTests
from .CurveTests import CurveTests
from .Ed25519BasicTests import Ed25519BasicTests
from .Ed25519ExtdTests import Ed25519ExtdTests
from .TwEdMontConversionTests import TwEdMontConversionTests
from .TwEdMontDomainTests import TwEdMontDomainTests

Ed25519ExtdTests.set_test_scope("full")

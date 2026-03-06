"""Tests for securechat.utils.math_utils."""

from __future__ import annotations

import pytest

from securechat.utils.math_utils import (
    Matrix,
    extended_gcd,
    gcd,
    matrix_determinant,
    matrix_identity,
    matrix_inverse,
    matrix_multiply,
    matrix_size,
    matrix_vector_multiply,
    mod_inverse,
)


# ---------------------------------------------------------------------------
# GCD
# ---------------------------------------------------------------------------


class TestGCD:
    def test_basic(self) -> None:
        assert gcd(12, 8) == 4

    def test_coprime(self) -> None:
        assert gcd(17, 13) == 1

    def test_one_zero(self) -> None:
        assert gcd(0, 5) == 5
        assert gcd(5, 0) == 5

    def test_both_zero(self) -> None:
        assert gcd(0, 0) == 0

    def test_negative(self) -> None:
        assert gcd(-12, 8) == 4
        assert gcd(12, -8) == 4

    def test_same(self) -> None:
        assert gcd(7, 7) == 7

    def test_one(self) -> None:
        assert gcd(1, 100) == 1


# ---------------------------------------------------------------------------
# Extended GCD
# ---------------------------------------------------------------------------


class TestExtendedGCD:
    def test_basic(self) -> None:
        g, x, y = extended_gcd(35, 15)
        assert g == 5
        assert 35 * x + 15 * y == g

    def test_coprime(self) -> None:
        g, x, y = extended_gcd(17, 13)
        assert g == 1
        assert 17 * x + 13 * y == 1

    def test_identity(self) -> None:
        g, x, y = extended_gcd(1, 1)
        assert g == 1
        assert 1 * x + 1 * y == 1

    def test_zero(self) -> None:
        g, x, y = extended_gcd(0, 5)
        assert g == 5
        assert 0 * x + 5 * y == 5


# ---------------------------------------------------------------------------
# Modular inverse
# ---------------------------------------------------------------------------


class TestModInverse:
    def test_basic(self) -> None:
        inv = mod_inverse(3, 7)
        assert (3 * inv) % 7 == 1

    def test_mod_256(self) -> None:
        # 3 is coprime with 256
        inv = mod_inverse(3, 256)
        assert (3 * inv) % 256 == 1

    def test_all_coprime_mod_256(self) -> None:
        """Every odd number < 256 should have an inverse mod 256."""
        for a in range(1, 256, 2):
            inv = mod_inverse(a, 256)
            assert (a * inv) % 256 == 1, f"Failed for a={a}"

    def test_no_inverse(self) -> None:
        with pytest.raises(ValueError, match="Modular inverse does not exist"):
            mod_inverse(2, 4)

    def test_no_inverse_mod_256(self) -> None:
        # Even numbers don't have inverse mod 256
        with pytest.raises(ValueError):
            mod_inverse(2, 256)

    def test_one(self) -> None:
        assert mod_inverse(1, 256) == 1


# ---------------------------------------------------------------------------
# Matrix utilities
# ---------------------------------------------------------------------------


class TestMatrixSize:
    def test_2x2(self) -> None:
        assert matrix_size([[1, 2], [3, 4]]) == (2, 2)

    def test_3x2(self) -> None:
        assert matrix_size([[1, 2], [3, 4], [5, 6]]) == (3, 2)

    def test_empty(self) -> None:
        assert matrix_size([]) == (0, 0)


class TestMatrixMultiply:
    def test_2x2_identity(self) -> None:
        a: Matrix = [[1, 2], [3, 4]]
        identity = matrix_identity(2)
        result = matrix_multiply(a, identity, 256)
        assert result == a

    def test_2x2(self) -> None:
        a: Matrix = [[1, 2], [3, 4]]
        b: Matrix = [[5, 6], [7, 8]]
        # [[1*5+2*7, 1*6+2*8], [3*5+4*7, 3*6+4*8]]
        # = [[19, 22], [43, 50]]
        result = matrix_multiply(a, b, 256)
        assert result == [[19, 22], [43, 50]]

    def test_mod(self) -> None:
        a: Matrix = [[200, 100], [150, 50]]
        b: Matrix = [[3, 0], [0, 3]]
        # [[600, 300], [450, 150]] mod 256 = [[88, 44], [194, 150]]
        result = matrix_multiply(a, b, 256)
        assert result == [[600 % 256, 300 % 256], [450 % 256, 150 % 256]]

    def test_dimension_mismatch(self) -> None:
        a: Matrix = [[1, 2, 3]]
        b: Matrix = [[1, 2], [3, 4]]
        with pytest.raises(ValueError, match="Cannot multiply"):
            matrix_multiply(a, b, 256)


class TestMatrixVectorMultiply:
    def test_2x2(self) -> None:
        mat: Matrix = [[1, 2], [3, 4]]
        vec = [5, 6]
        # [1*5+2*6, 3*5+4*6] = [17, 39]
        result = matrix_vector_multiply(mat, vec, 256)
        assert result == [17, 39]

    def test_mod(self) -> None:
        mat: Matrix = [[200, 100], [150, 50]]
        vec = [2, 3]
        # [400+300, 300+150] = [700, 450] mod 256 = [188, 194]
        result = matrix_vector_multiply(mat, vec, 256)
        assert result == [700 % 256, 450 % 256]

    def test_dimension_mismatch(self) -> None:
        mat: Matrix = [[1, 2, 3]]
        vec = [1, 2]
        with pytest.raises(ValueError, match="Cannot multiply"):
            matrix_vector_multiply(mat, vec, 256)


class TestMatrixDeterminant:
    def test_1x1(self) -> None:
        assert matrix_determinant([[5]], 256) == 5

    def test_2x2(self) -> None:
        # det([[1,2],[3,4]]) = 1*4 - 2*3 = -2 mod 256 = 254
        assert matrix_determinant([[1, 2], [3, 4]], 256) == 254

    def test_3x3(self) -> None:
        mat: Matrix = [[6, 1, 1], [4, -2, 5], [2, 8, 7]]
        # det = 6*(-2*7 - 5*8) - 1*(4*7 - 5*2) + 1*(4*8 - (-2)*2)
        # = 6*(-14-40) - 1*(28-10) + 1*(32+4)
        # = 6*(-54) - 18 + 36 = -324 - 18 + 36 = -306
        # -306 mod 256 = 206
        assert matrix_determinant(mat, 256) == (-306) % 256

    def test_identity(self) -> None:
        assert matrix_determinant(matrix_identity(3), 256) == 1

    def test_non_square(self) -> None:
        with pytest.raises(ValueError, match="square matrix"):
            matrix_determinant([[1, 2, 3], [4, 5, 6]], 256)


class TestMatrixInverse:
    def test_2x2_mod_256(self) -> None:
        # [[3, 1], [5, 7]], det = 3*7 - 1*5 = 16 — not coprime with 256!
        # Use a matrix with odd determinant: [[3, 2], [1, 1]], det = 3-2 = 1
        mat: Matrix = [[3, 2], [1, 1]]
        inv = matrix_inverse(mat, 256)
        product = matrix_multiply(mat, inv, 256)
        assert product == matrix_identity(2)

    def test_3x3_mod_256(self) -> None:
        # [[1, 0, 1], [0, 1, 0], [1, 0, 3]], det = 1*(3-0) - 0 + 1*(0-1) = 3-1 = 2
        # gcd(2, 256) != 1 — not invertible.
        # Use [[1, 2, 0], [0, 1, 0], [0, 0, 1]], det = 1
        mat: Matrix = [[1, 2, 0], [0, 1, 0], [0, 0, 1]]
        inv = matrix_inverse(mat, 256)
        product = matrix_multiply(mat, inv, 256)
        assert product == matrix_identity(3)

    def test_inverse_of_identity(self) -> None:
        identity = matrix_identity(3)
        inv = matrix_inverse(identity, 256)
        assert inv == identity

    def test_non_invertible(self) -> None:
        # det = 0 mod 256
        mat: Matrix = [[2, 4], [1, 2]]
        with pytest.raises(ValueError, match="not invertible"):
            matrix_inverse(mat, 256)

    def test_even_det_not_invertible_mod_256(self) -> None:
        # [[1, 1], [1, 3]], det = 3-1 = 2, gcd(2,256)=2 !=1
        mat: Matrix = [[1, 1], [1, 3]]
        with pytest.raises(ValueError, match="not invertible"):
            matrix_inverse(mat, 256)

    def test_non_square(self) -> None:
        with pytest.raises(ValueError, match="square matrix"):
            matrix_inverse([[1, 2, 3]], 256)

    def test_round_trip_various(self) -> None:
        """Test several known-invertible matrices mod 256."""
        # Matrices with det coprime to 256 (odd determinant)
        test_matrices: list[Matrix] = [
            [[1, 0], [0, 1]],
            [[3, 2], [1, 1]],  # det = 1
            [[5, 2], [2, 1]],  # det = 1
            [[7, 2], [3, 1]],  # det = 1
            [[1, 2], [0, 3]],  # det = 3
        ]
        for mat in test_matrices:
            n = len(mat)
            inv = matrix_inverse(mat, 256)
            product = matrix_multiply(mat, inv, 256)
            assert product == matrix_identity(n), f"Failed for matrix {mat}"

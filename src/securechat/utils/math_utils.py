"""Mathematical utilities for classical cryptography.

Provides GCD, extended GCD, modular inverse, and matrix operations mod n.
All matrix operations work on list-of-lists representation with integer entries.
No external dependencies (no numpy).
"""

from __future__ import annotations


def gcd(a: int, b: int) -> int:
    """Compute the greatest common divisor of two integers using Euclid's algorithm."""
    a, b = abs(a), abs(b)
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """Compute the extended GCD of a and b.

    Returns (g, x, y) such that a*x + b*y == g == gcd(a, b).
    """
    if a == 0:
        return b, 0, 1
    g, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return g, x, y


def mod_inverse(a: int, m: int) -> int:
    """Compute the modular multiplicative inverse of a mod m.

    Returns x such that (a * x) % m == 1.

    Raises:
        ValueError: If the inverse does not exist (gcd(a, m) != 1).
    """
    a = a % m
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"Modular inverse does not exist: gcd({a}, {m}) = {g}")
    return x % m


# ---------------------------------------------------------------------------
# Matrix operations (list-of-lists, mod n)
# ---------------------------------------------------------------------------

Matrix = list[list[int]]


def matrix_size(mat: Matrix) -> tuple[int, int]:
    """Return (rows, cols) of a matrix."""
    rows = len(mat)
    cols = len(mat[0]) if rows > 0 else 0
    return rows, cols


def matrix_multiply(a: Matrix, b: Matrix, mod: int) -> Matrix:
    """Multiply two matrices mod `mod`.

    Raises:
        ValueError: If inner dimensions don't match.
    """
    rows_a, cols_a = matrix_size(a)
    rows_b, cols_b = matrix_size(b)
    if cols_a != rows_b:
        raise ValueError(f"Cannot multiply matrices: {rows_a}x{cols_a} and {rows_b}x{cols_b}")
    result: Matrix = [[0] * cols_b for _ in range(rows_a)]
    for i in range(rows_a):
        for j in range(cols_b):
            total = 0
            for k in range(cols_a):
                total += a[i][k] * b[k][j]
            result[i][j] = total % mod
    return result


def matrix_vector_multiply(mat: Matrix, vec: list[int], mod: int) -> list[int]:
    """Multiply a matrix by a column vector mod `mod`.

    Raises:
        ValueError: If dimensions don't match.
    """
    rows, cols = matrix_size(mat)
    if cols != len(vec):
        raise ValueError(f"Cannot multiply {rows}x{cols} matrix by vector of length {len(vec)}")
    result: list[int] = []
    for i in range(rows):
        total = 0
        for j in range(cols):
            total += mat[i][j] * vec[j]
        result.append(total % mod)
    return result


def matrix_determinant(mat: Matrix, mod: int) -> int:
    """Compute the determinant of a square matrix mod `mod`.

    Uses cofactor expansion along the first row (Laplace expansion).

    Raises:
        ValueError: If the matrix is not square.
    """
    rows, cols = matrix_size(mat)
    if rows != cols:
        raise ValueError(f"Determinant requires a square matrix, got {rows}x{cols}")
    n = rows

    if n == 1:
        return mat[0][0] % mod

    if n == 2:
        return (mat[0][0] * mat[1][1] - mat[0][1] * mat[1][0]) % mod

    det = 0
    for j in range(n):
        # Build the (n-1)x(n-1) minor by removing row 0 and column j
        minor: Matrix = []
        for i in range(1, n):
            row: list[int] = []
            for k in range(n):
                if k != j:
                    row.append(mat[i][k])
            minor.append(row)
        cofactor = ((-1) ** j) * mat[0][j] * matrix_determinant(minor, mod)
        det += cofactor

    return det % mod


def matrix_identity(n: int) -> Matrix:
    """Return the n x n identity matrix."""
    return [[1 if i == j else 0 for j in range(n)] for i in range(n)]


def matrix_inverse(mat: Matrix, mod: int) -> Matrix:
    """Compute the inverse of a square matrix mod `mod`.

    Uses the adjugate (matrix of cofactors transposed) method:
        A^{-1} = det(A)^{-1} * adj(A)   (mod `mod`)

    Raises:
        ValueError: If the matrix is not square or not invertible mod `mod`.
    """
    rows, cols = matrix_size(mat)
    if rows != cols:
        raise ValueError(f"Inverse requires a square matrix, got {rows}x{cols}")
    n = rows

    det = matrix_determinant(mat, mod)
    if gcd(det, mod) != 1:
        raise ValueError(f"Matrix is not invertible mod {mod}: gcd(det={det}, {mod}) != 1")

    det_inv = mod_inverse(det, mod)

    # Compute the matrix of cofactors
    cofactors: Matrix = [[0] * n for _ in range(n)]
    for i in range(n):
        for j in range(n):
            # Minor: remove row i, column j
            minor: Matrix = []
            for r in range(n):
                if r == i:
                    continue
                row: list[int] = []
                for c in range(n):
                    if c == j:
                        continue
                    row.append(mat[r][c])
                minor.append(row)

            minor_det = matrix_determinant(minor, mod)
            cofactors[i][j] = (((-1) ** (i + j)) * minor_det) % mod

    # Adjugate = transpose of cofactors
    adjugate: Matrix = [[cofactors[j][i] for j in range(n)] for i in range(n)]

    # A^{-1} = det_inv * adjugate (mod m)
    inverse: Matrix = [[(det_inv * adjugate[i][j]) % mod for j in range(n)] for i in range(n)]

    return inverse

from typing import List, Optional
from gf256 import GF256


class MatrixGF256:
    """
    Матрица над полем GF(2^8)
    """
    
    rows: int
    cols: int
    data: List[List[int]]
    
    def __init__(self, rows: int, cols: int, data: Optional[List[List[int]]] = None):
        """Создание матрицы"""
        self.rows = rows
        self.cols = cols
        
        if data is not None:
            self.data = [row[:] for row in data]
        else:
            self.data = [[0] * cols for _ in range(rows)]
    
    def get(self, i: int, j: int) -> int:
        """Получить элемент [i][j]"""
        return self.data[i][j]
    
    def set(self, i: int, j: int, value: int):
        """Установить элемент [i][j]"""
        self.data[i][j] = value
    
    def get_row(self, i: int) -> List[int]:
        """Получить i-ю строку"""
        return self.data[i][:]
    
    def get_submatrix(self, row_indices: List[int]) -> 'MatrixGF256':
        """Получить подматрицу из указанных строк"""
        new_data = [self.data[i][:] for i in row_indices]
        return MatrixGF256(len(row_indices), self.cols, new_data)
    
    @staticmethod
    def vandermonde(n: int, m: int) -> 'MatrixGF256':
        """
        Создание матрицы Вандермонда n x m
        """
        if n > 255:
            raise ValueError("n не может превышать 255 для GF(2^8)")
        
        matrix = MatrixGF256(n, m)
        
        for i in range(n):
            x = i + 1  # x_i = 1, 2, 3, ..., n
            for j in range(m):
                matrix.set(i, j, GF256.pow(x, j))
        
        return matrix
    
    def mul_vector(self, vector: List[int]) -> List[int]:
        """Умножение матрицы на вектор-столбец"""
        if len(vector) != self.cols:
            raise ValueError(f"Размерности не совпадают: {self.cols} != {len(vector)}")
        
        result = [0] * self.rows
        for i in range(self.rows):
            for j in range(self.cols):
                result[i] = GF256.add(result[i], GF256.mul(self.data[i][j], vector[j]))
        
        return result
    
    def inverse(self) -> 'MatrixGF256':
        """Вычисление обратной матрицы методом Гаусса-Жордана"""
        if self.rows != self.cols:
            raise ValueError("Матрица должна быть квадратной")
        
        n = self.rows
        
        # Расширенная матрица [A|I]
        augmented = MatrixGF256(n, 2 * n)
        for i in range(n):
            for j in range(n):
                augmented.set(i, j, self.data[i][j])
            augmented.set(i, n + i, 1)
        
        # Прямой ход
        for col in range(n):
            # Поиск ненулевого элемента
            pivot_row = -1
            for row in range(col, n):
                if augmented.get(row, col) != 0:
                    pivot_row = row
                    break
            
            if pivot_row == -1:
                raise ValueError("Матрица вырождена")
            
            # Перестановка строк
            if pivot_row != col:
                augmented.data[col], augmented.data[pivot_row] = \
                    augmented.data[pivot_row], augmented.data[col]
            
            # Нормализация
            pivot = augmented.get(col, col)
            pivot_inv = GF256.inv(pivot)
            for j in range(2 * n):
                augmented.set(col, j, GF256.mul(augmented.get(col, j), pivot_inv))
            
            # Обнуление столбца
            for row in range(n):
                if row != col and augmented.get(row, col) != 0:
                    factor = augmented.get(row, col)
                    for j in range(2 * n):
                        val = GF256.add(
                            augmented.get(row, j),
                            GF256.mul(factor, augmented.get(col, j))
                        )
                        augmented.set(row, j, val)
        
        # Извлечение обратной матрицы
        inv_matrix = MatrixGF256(n, n)
        for i in range(n):
            for j in range(n):
                inv_matrix.set(i, j, augmented.get(i, n + j))
        
        return inv_matrix

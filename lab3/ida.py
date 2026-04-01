from typing import List
from gf256 import GF256
from matrix_gf256 import MatrixGF256


class IDA:
    """
    Реализация алгоритма Information Dispersal Algorithm
    """
    
    n: int                      # Общее количество фрагментов
    m: int                      # Минимум фрагментов для восстановления
    matrix: MatrixGF256         # Матрица Вандермонда
    
    def __init__(self, n: int, m: int):
        """
        Инициализация IDA
        """
        if m > n:
            raise ValueError("m должно быть <= n")
        if n > 255:
            raise ValueError("n не может превышать 255 для GF(2^8)")
        if m < 1:
            raise ValueError("m должно быть >= 1")
        
        self.n = n
        self.m = m
        self.matrix = MatrixGF256.vandermonde(n, m)
        
    
    def dispersal(self, data: bytes) -> List[bytes]:
        """
        Алгоритм распределения данных на n фрагментов
        """
        # Дополнение до кратности m
        padded = self._pad(data)
        
        num_cols = len(padded) // self.m
        
        # Строим матрицу M размера m x num_cols
        M = []
        for i in range(self.m):
            row = []
            for j in range(num_cols):
                row.append(padded[j * self.m + i])
            M.append(row)
        
        # Вычисляем A * M
        fragments = []
        for i in range(self.n):
            fragment = []
            for j in range(num_cols):
                # Скалярное произведение i-й строки A и j-го столбца M
                val = 0
                for k in range(self.m):
                    val = GF256.add(val, GF256.mul(self.matrix.get(i, k), M[k][j]))
                fragment.append(val)
            fragments.append(bytes(fragment))
        
        return fragments
    
    def recovery(self, indices: List[int], fragments: List[bytes]) -> bytes:
        """
        Алгоритм восстановления из m фрагментов
        """
        if len(indices) != self.m or len(fragments) != self.m:
            raise ValueError(f"Требуется ровно {self.m} фрагментов")
        
        # Подматрица Вандермонда
        submatrix = self.matrix.get_submatrix(indices)
        
        # Обратная матрица
        inv = submatrix.inverse()
        
        num_cols = len(fragments[0])
        
        # M = A'^(-1) * F
        M = [[0] * num_cols for _ in range(self.m)]
        
        for j in range(num_cols):
            col = [fragments[i][j] for i in range(self.m)]
            
            for i in range(self.m):
                val = 0
                for k in range(self.m):
                    val = GF256.add(val, GF256.mul(inv.get(i, k), col[k]))
                M[i][j] = val
        
        # Собираем данные
        recovered = []
        for j in range(num_cols):
            for i in range(self.m):
                recovered.append(M[i][j])
        
        result = self._unpad(bytes(recovered))
        return result
    
    def _pad(self, data: bytes) -> bytes:
        """Дополнение данных до кратности m"""
        # Формат: [4 байта длины][данные][padding]
        length = len(data)
        length_bytes = length.to_bytes(4, 'big')
        
        total = 4 + len(data)
        remainder = total % self.m
        if remainder != 0:
            padding_len = self.m - remainder
        else:
            padding_len = 0
        
        return length_bytes + data + bytes(padding_len)
    
    def _unpad(self, data: bytes) -> bytes:
        """Удаление паддинга"""
        length = int.from_bytes(data[:4], 'big')
        return data[4:4 + length]

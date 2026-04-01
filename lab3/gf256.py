from typing import List


class GF256:
    """
    Реализация арифметики в поле Галуа GF(2^8)
    """
    
    IRREDUCIBLE_POLY = 0x11B
    
    _exp_table: List[int] = []
    _log_table: List[int] = []
    _initialized: bool = False
    
    @classmethod
    def _init_tables(cls):
        """Инициализация таблиц экспонент и логарифмов для быстрых вычислений"""
        if cls._initialized:
            return
            
        cls._exp_table = [0] * 512
        cls._log_table = [0] * 256
        
        x = 1
        primitive = 0x03
        
        for i in range(255):
            cls._exp_table[i] = x
            cls._log_table[x] = i
            
            x = cls._mul_no_table(x, primitive)
        
        for i in range(255, 512):
            cls._exp_table[i] = cls._exp_table[i - 255]
        
        cls._log_table[0] = 0
        cls._initialized = True
    
    @classmethod
    def _mul_no_table(cls, a: int, b: int) -> int:
        """Умножение без таблиц (для инициализации)"""
        result = 0
        while b:
            if b & 1:
                result ^= a
            a <<= 1
            if a & 0x100:
                a ^= cls.IRREDUCIBLE_POLY
            b >>= 1
        return result
    
    @classmethod
    def add(cls, a: int, b: int) -> int:
        """Сложение - это XOR"""
        return a ^ b
    
    @classmethod
    def sub(cls, a: int, b: int) -> int:
        """Вычитание - тоже XOR"""
        return a ^ b
    
    @classmethod
    def mul(cls, a: int, b: int) -> int:
        """Умножение через таблицы логарифмов"""
        cls._init_tables()
        
        if a == 0 or b == 0:
            return 0
        
        log_sum = cls._log_table[a] + cls._log_table[b]
        return cls._exp_table[log_sum]
    
    @classmethod
    def div(cls, a: int, b: int) -> int:
        """Деление"""
        cls._init_tables()
        
        if b == 0:
            raise ValueError("Деление на ноль")
        if a == 0:
            return 0
        
        log_diff = cls._log_table[a] - cls._log_table[b] + 255
        return cls._exp_table[log_diff]
    
    @classmethod
    def inv(cls, a: int) -> int:
        """Мультипликативный обратный элемент"""
        cls._init_tables()
        
        if a == 0:
            raise ValueError("Ноль не имеет обратного")
        
        return cls._exp_table[255 - cls._log_table[a]]
    
    @classmethod
    def pow(cls, a: int, n: int) -> int:
        """Возведение в степень"""
        cls._init_tables()
        
        if n == 0:
            return 1
        if a == 0:
            return 0
        
        log_result = (cls._log_table[a] * n) % 255
        return cls._exp_table[log_result]

from FieldElement import FieldElement


class Point:

    def __init__(self, x, y, a, b):
        self.a = a
        self.b = b
        self.x = x
        self.y = y

        if self.x is None and self.y is None:  # <1>
            return

        if self.y**2 != self.x**3 + a * x + b:  # <1>
            raise ValueError("({}, {}) is not on the curve".format(x, y))

    def __eq__(self, other):  # <2>
        return (
            self.x == other.x
            and self.y == other.y
            and self.a == other.a
            and self.b == other.b
        )

    def __ne__(self, other):
        return not (self == other)

    def __repr__(self):
        if self.x is None:
            return "Point(infinity)"
        else:
            return "Point({},{})_{}_{}".format(self.x, self.y, self.a, self.b)

    def __add__(self, other):  # <2>
        if self.a != other.a or self.b != other.b:
            raise TypeError(
                "Points {}, {} are not on the same curve".format(self, other)
            )

        if self.x is None:  # <3>
            return other
        if other.x is None:  # <4>
            return self

        if self.x == other.x and self.y != other.y:
            return self.__class__(None, None, self.a, self.b)

        if self.x != other.x:
            s = (other.y - self.y) / (other.x - self.x)
            x = s**2 - self.x - other.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other:
            s = (3 * self.x**2 + self.a) / (2 * self.y)
            x = s**2 - 2 * self.x
            y = s * (self.x - x) - self.y
            return self.__class__(x, y, self.a, self.b)

        if self == other and self.y == 0 * self.x:
            return self.__class__(None, None, self.a, self.y)

    def __rmul__(self, coefficient):
        coef = coefficient
        current = self
        result = self.__class__(None, None, self.a, self.b)  # <2>
        while coef:
            if coef & 1:  # <3>
                result += current
            current += current  # <4>
            coef >>= 1  # <5>
        return result


prime = 223
x = FieldElement(15, prime)
y = FieldElement(86, prime)
a = FieldElement(0, prime)
b = FieldElement(7, prime)
p1 = Point(x, y, a, b)
p2 = Point(x, y, a, b)
# print(3*p1) # 15,86
# print(10*p1) # 15,86

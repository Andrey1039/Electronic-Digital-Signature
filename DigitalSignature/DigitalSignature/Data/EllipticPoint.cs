using System;
using System.Numerics;

namespace DigitalSignature.Data
{
    internal class EllipticPoint
    {
        BigInteger A { get; }
        BigInteger B { get; }
        public BigInteger X { get; }
        BigInteger Y { get; }
        BigInteger P { get; }

        public EllipticPoint(BigInteger a, BigInteger b, BigInteger p, BigInteger x, BigInteger y)
        {
            this.A = a;
            this.B = b;
            this.P = p;
            this.X = x;
            this.Y = y;
        }

        public static EllipticPoint operator +(EllipticPoint point1, EllipticPoint point2)
        {
            if (point1.A != point2.A || point1.B != point2.B || point1.P != point2.P)
                throw new Exception("Сложение точек разных кривых");

            BigInteger lambda;

            if (point1 != point2)
            {
                BigInteger delta_y = (point2.Y - point1.Y) > 0 ? point2.Y - point1.Y : point2.Y - point1.Y + point1.P;
                BigInteger delta_x = (point2.X - point1.X) > 0 ? point2.X - point1.X : point2.X - point1.X + point1.P;

                if (delta_x == 0)
                    throw new Exception("При сложении точек получили точку О");

                lambda = delta_y * Mathematics.Ext_Euclidian(delta_x, point1.P);
            }
            else
            {
                lambda = (3 * (point1.X * point1.X) + point1.A) * Mathematics.Ext_Euclidian(2 * point1.Y, point1.P);
            }

            BigInteger X = Mathematics.Mod(lambda * lambda - point1.X - point2.X, point1.P);
            BigInteger Y = Mathematics.Mod(lambda * (point1.X - X) - point1.Y, point1.P);

            return new EllipticPoint(point1.A, point1.B, point1.P, X, Y);
        }

        public static EllipticPoint operator *(EllipticPoint point, BigInteger k)
        {
            EllipticPoint result = point;
            k -= 1;

            while (k > 0)
            {
                if (k % 2 != 0)
                {
                    result = result + point;
                    --k;
                }
                else
                {
                    k = k / 2;
                    point = point + point;
                }

            }

            return result;
        }

        public static EllipticPoint operator *(BigInteger k, EllipticPoint point)
        {
            return point * k;
        }

        public static bool operator ==(EllipticPoint point1, EllipticPoint point2)
        {
            if (point1.A != point2.A || point1.B != point2.B || point1.P != point2.P)
                throw new Exception("Сравнение точек разных кривых");

            if ((point1.X == point2.X) && (point1.Y == point2.Y))
                return true;

            return false;
        }

        public static bool operator !=(EllipticPoint point1, EllipticPoint point2)
        {
            if (point1.A != point2.A || point1.B != point2.B || point1.P != point2.P)
                throw new Exception("Сравнение точек разных кривых");

            if ((point1.X != point2.X) || (point1.Y != point2.Y))
                return true;

            return false;
        }
    }
}

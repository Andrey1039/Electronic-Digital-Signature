using System.Numerics;

namespace DigitalSignature.Data
{
    internal class Mathematics
    {
        public static BigInteger Mod(BigInteger n, BigInteger d)
        {
            BigInteger result = n % d;
            
            if (result < 0)
                result += d;

            return result;
        }


        public static BigInteger Ext_Euclidian(BigInteger a, BigInteger b)
        {
            BigInteger r = new BigInteger();
            BigInteger x = new BigInteger();
            BigInteger x1 = new BigInteger(0);
            BigInteger x2 = new BigInteger(1);
            BigInteger q = new BigInteger();
            BigInteger reserve_b = b;

            if (a < 1)
                a += reserve_b;

            while (b != 0)
            {
                q = a / b;
                r = a - q * b;
                x = x2 - q * x1;
                a = b;
                b = r;
                x2 = x1;
                x1 = x;
            }

            while (x2 < 0)
                x2 += reserve_b;

            return x2;
        }
    }
}

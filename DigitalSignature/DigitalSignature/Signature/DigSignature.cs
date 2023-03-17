using System;
using System.Numerics;
using DigitalSignature.Hash;
using DigitalSignature.Data;
using System.Security.Cryptography;

namespace DigitalSignature.Signature
{
    internal class DigSignature
    {
        BigInteger q;
        int hash_length;
        EllipticPoint point;

        public DigSignature(EllipticPoint point, BigInteger q)
        {
            this.point = point;
            this.q = q;

            if (q > BigInteger.Pow(2, 254) && q < BigInteger.Pow(2, 256))
                hash_length = 256;
            else
                if (q > BigInteger.Pow(2, 508) && q < BigInteger.Pow(2, 512))
                hash_length = 512;
            else
                throw new Exception("Неверное значение q");
        }
        
        // Генерация случайных чисел
        private BigInteger GetRandomNumber(int length)
        {
            using (var generator = RandomNumberGenerator.Create())
            {
                var randomBytes = new byte[length];
                generator.GetBytes(randomBytes);
                BigInteger result = new BigInteger(randomBytes);

                return BigInteger.Abs(result);
            }
        }

        // Генерация закрытого ключа
        public BigInteger GeneratePrivateKey(int length)
        {
            BigInteger d = new BigInteger();

            do
            {
                d = GetRandomNumber(length);
            }
            while (d < 1 || d > q);

            return d;
        }

        // Генерация открытого ключа
        public EllipticPoint GeneratePublicKey(BigInteger d)
        {
            return point * d;
        }

        // Вычисление хэша
        private byte[] Hash(string message)
        {
            Streebog streebog = new Streebog();
            byte[] hash = Array.Empty<byte>();

            if (hash_length == 256)
                hash = streebog.GetHash256(message);
            else
                hash = streebog.GetHash512(message);

            return hash;
        }

        // Вычисление значения k
        private BigInteger GetK()
        {
            BigInteger k;

            do
            {
                k = GetRandomNumber(hash_length / 8);
            }
            while (k < 1 || k > q);

            return k;
        }

        // Формирование ЭЦП
        public byte[] GetSignature(string message, BigInteger d)
        {
            byte[] hash = Hash(message);

            BigInteger alpha = new BigInteger(hash);
            BigInteger e = Mathematics.Mod(alpha, q) == 0 ? 1 : Mathematics.Mod(alpha, q);

            BigInteger k;
            BigInteger r;
            BigInteger s;

            do
            {
                do
                {
                    k = GetK();
                    
                    EllipticPoint C = point * k;
                    r = Mathematics.Mod(C.X, q);
                }
                while (r == 0);

                s = Mathematics.Mod(r * d + k * e, q);
            }
            while (s == 0);

            byte[] signature = new byte[hash_length / 4];

            Array.Copy(r.ToByteArray(), 0, signature, 0, hash_length / 8);
            Array.Copy(s.ToByteArray(), 0, signature, hash_length / 8, hash_length / 8);

            return signature;
        }

        // Проверка ЭЦП
        public bool CheckSignature(string message, byte[] signature, EllipticPoint Q)
        {
            byte[] byte_r = new byte[hash_length / 8];
            byte[] byte_s = new byte[hash_length / 8];

            Array.Copy(signature, 0, byte_r, 0, hash_length / 8);
            Array.Copy(signature, hash_length / 8, byte_s, 0, hash_length / 8);

            BigInteger r = new BigInteger(byte_r);
            BigInteger s = new BigInteger(byte_s);

            if (r < 1 || r > q - 1 || s < 1 || s > q - 1)
                return false;

            byte[] hash = Hash(message);

            BigInteger alpha = new BigInteger(hash);
            BigInteger e = Mathematics.Mod(alpha, q) == 0 ? 1 : Mathematics.Mod(alpha, q);

            BigInteger v = Mathematics.Ext_Euclidian(e, q);

            BigInteger z1 = Mathematics.Mod(s * v, q);
            BigInteger z2 = Mathematics.Mod(-(r * v), q);

            EllipticPoint C = z1 * point + z2 * Q;

            BigInteger R = Mathematics.Mod(C.X, q);

            if (R == r)
                return true;

            return false;
        }
    }
}

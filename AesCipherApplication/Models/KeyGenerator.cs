using System;
using System.Security.Cryptography;

namespace AesCipherApplication.Models
{
    public class KeyGenerator
    {
        private static KeyGenerator instance;

        public const int SALT_SIZE = 0; // size in bytes
        public const int HASH_SIZE = 16; // size in bytes
        public const int ITERATIONS = 1000; // number of pbkdf2 iterations
        public byte[,] Key { get; set; }
        public CheckPassword Check { get; set; }
        public static KeyGenerator GetInstance()
        {
            if (instance is null)
            {
                instance = new KeyGenerator();
            }
            return instance;
        }

        public bool CreateKey(string input)
        {
            if (!Check.Validate(input))
                return false;
            // Generate a salt
            RNGCryptoServiceProvider provider = new RNGCryptoServiceProvider();
            byte[] salt = new byte[SALT_SIZE];
            provider.GetBytes(salt);

            // Generate the hash
            Rfc2898DeriveBytes pbkdf2 = new Rfc2898DeriveBytes(input, salt, ITERATIONS);
            var bytes = pbkdf2.GetBytes(HASH_SIZE);
            int rows = 4;
            int columns = bytes.Length / rows;
            Key = new byte[columns, rows];

            Buffer.BlockCopy(bytes, 0, Key, 0, sizeof(byte) * bytes.Length);
            return true;
        }
        private KeyGenerator()
        {
            Check = new CheckPassword() { Latins = true, Cyrillics = true, Digits = true, MinLength = 8 };
        }
    }
}

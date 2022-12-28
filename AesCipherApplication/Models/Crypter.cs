using aes;
using System;
using System.Collections.Generic;
using System.Text;

namespace AesCipherApplication.Models
{
    public enum CipherMode
    {
        ECB,
        CBC,
        CFB,
        OFB
    }
    public class Crypter
    {
        public AES algorithm;
        public static CipherMode CipherMode { get; set; } = CipherMode.ECB;
        public Crypter(byte[,] cipherKey)
        {
            algorithm = new AES(cipherKey);
        }

        public string EncryptStringToString(string source)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(source);
            var result = EncryptBytesToString(bytes);
            return result;
        }

        public string DecryptStringToString(string source)
        {
            var bytesList = new List<byte>();
            for (int i = 0; i < source.Length; i += 2)
            {
                var temp = Convert.ToByte(source.Substring(i, 2), 16);
                bytesList.Add(temp);
            }
            var result = DecryptBytesToString(bytesList.ToArray());
            return result;
        }

        public byte[] EncryptStringToBytes(string source)
        {
            byte[] bytes = Encoding.UTF8.GetBytes(source);
            var result = EncryptBytesToBytes(bytes);
            return result;
        }

        public byte[] DecryptStringToBytes(string source)
        {
            var bytesList = new List<byte>();
            for (int i = 0; i < source.Length; i += 2)
            {
                var temp = Convert.ToByte(source.Substring(i, 2), 16);
                bytesList.Add(temp);
            }
            var result = DecryptBytesToBytes(bytesList.ToArray());
            return result;
        }

        public byte[] EncryptBytesToBytes(byte[] bytes)
        {
            switch (CipherMode)
            {
                case CipherMode.CBC:
                    return algorithm.EncryptCBC(bytes);
                case CipherMode.CFB:
                    return algorithm.EncryptCFB(bytes);
                case CipherMode.OFB:
                    return algorithm.EncryptOFB(bytes);
                case CipherMode.ECB:
                default:
                    return algorithm.EncryptECB(bytes);
            }
        }

        public string EncryptBytesToString(byte[] bytes)
        {
            var result = EncryptBytesToBytes(bytes);
            return Convert.ToHexString(result);
        }

        public byte[] DecryptBytesToBytes(byte[] bytes)
        {
            switch (CipherMode)
            {
                case CipherMode.CBC:
                    return algorithm.DecryptCBC(bytes);
                case CipherMode.CFB:
                    return algorithm.DecryptCFB(bytes);
                case CipherMode.OFB:
                    return algorithm.DecryptOFB(bytes);
                case CipherMode.ECB:
                default:
                    return algorithm.DecryptECB(bytes);
            }
        }

        public string DecryptBytesToString(byte[] bytes)
        {
            var result = DecryptBytesToBytes(bytes);
            return Encoding.UTF8.GetString(result);
        }
    }
}

using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Security.Encryptions
{
    /// <summary>
    /// HwAes (Hardware Accelerated AES) by using the AesCryptoServiceProvider
    /// </summary>
    public sealed class HwAes : IDisposable
    {
        private AesCryptoServiceProvider AES;

        public byte[] Key
        {
            get { return AES.Key; }
            set { AES.Key = value; }
        }
        public byte[] IV
        {
            get
            {
                return AES.IV;
            }
            set
            {
                AES.IV = value;
            }
        }

        public bool DynamicKey { get; private set; }
        private FastRandom Rnd = new FastRandom(DateTime.Now.Millisecond);


        public HwAes(byte[] Key, byte[] IV, int KeySize, CipherMode cipherMode, PaddingMode padding)
        {
            this.AES = new AesCryptoServiceProvider();
            this.AES.Padding = padding;
            this.AES.Mode = cipherMode;
            this.AES.KeySize = KeySize;
            this.DynamicKey = DynamicKey;
            ApplyKey(Key, IV);
        }

        public byte[] Encrypt(byte[] Data, int Offset, int Length)
        {
            using (ICryptoTransform Encryptor = AES.CreateEncryptor())
            {
                return Encryptor.TransformFinalBlock(Data, Offset, Length);
            }
        }

        public byte[] Decrypt(byte[] Data, int Offset, int Length)
        {
            using (ICryptoTransform Decryptor = AES.CreateDecryptor())
            {
                return Decryptor.TransformFinalBlock(Data, Offset, Length);
            }
        }

        private byte[] KeyExtender(byte[] Input, int TargetLen)
        {
            int temp = 0xFF28423;
            for (int i = 0; i < Input.Length; i++)
                temp += Input[i];

            int oldLen = Input.Length;
            FastRandom rnd = new FastRandom(temp);
            Array.Resize(ref Input, TargetLen);
            rnd.NextBytes(Input, oldLen, TargetLen);
            return Input;
        }

        public void ApplyKey(byte[] Key, byte[] IV)
        {
            this.AES.Key = KeyExtender(Key, 32);
            this.IV = IV;
        }

        public void Dispose()
        {
            AES.Clear();
        }
    }
}
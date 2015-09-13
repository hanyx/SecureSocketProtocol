using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Obfuscation;
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
        private FastRandom Frandom = new FastRandom();
        private DataConfuser IvConfuser;

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

        public HwAes(Connection connection, byte[] Key, int KeySize, CipherMode cipherMode, PaddingMode padding)
        {
            this.AES = new AesCryptoServiceProvider();
            this.AES.Padding = padding;
            this.AES.Mode = cipherMode;
            this.AES.KeySize = KeySize;
            this.IvConfuser = new DataConfuser(connection.PrivateSeed, 16);
            ApplyKey(Key);
        }

        public byte[] Encrypt(byte[] Data, int Offset, int Length)
        {
            lock(AES)
            {
                byte[] NewIV = new byte[16];
                Frandom.NextBytes(NewIV);
                this.IV = NewIV;

                //mask the IV to make it harder to grab the IV while packet sniffing / MITM
                IvConfuser.Obfuscate(ref NewIV, 0);

                using (ICryptoTransform Encryptor = AES.CreateEncryptor())
                {
                    using(PayloadWriter pw = new PayloadWriter(new System.IO.MemoryStream()))
                    {
                        pw.WriteBytes(NewIV);
                        pw.WriteBytes(Encryptor.TransformFinalBlock(Data, Offset, Length));
                        return pw.ToByteArray();
                    }
                }
            }
        }

        public byte[] Decrypt(byte[] Data, int Offset, int Length)
        {
            lock(AES)
            {
                if (Length < 16)
                    return Data;

                //Copy the IV
                byte[] newIV = new byte[16];
                Array.Copy(Data, Offset, newIV, 0, 16);
                IvConfuser.Deobfuscate(ref newIV, 0); //unmask the new IV
                this.IV = newIV;

                using (ICryptoTransform Decryptor = AES.CreateDecryptor())
                {
                    return Decryptor.TransformFinalBlock(Data, Offset + 16, Length - 16);
                }
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

        public void ApplyKey(byte[] Key)
        {
            this.AES.Key = KeyExtender(Key, 32);
        }

        public void Dispose()
        {
            AES.Clear();
        }
    }
}
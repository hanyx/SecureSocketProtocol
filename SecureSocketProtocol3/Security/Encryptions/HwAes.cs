using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Obfuscation;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Text;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
*/

namespace SecureSocketProtocol3.Security.Encryptions
{
    /// <summary>
    /// HwAes (Hardware Accelerated AES) by using the AesCryptoServiceProvider
    /// </summary>
    public sealed class HwAes : IDisposable
    {
        private AesCryptoServiceProvider AES;
        private RNGCryptoServiceProvider rngProvider;
        private DataConfuser IvConfuser;

        public byte[] Key
        {
            get { return AES.Key; }
            set { AES.Key = value; }
        }
        public byte[] IV
        {
            get { return AES.IV; }
            set { AES.IV = value; }
        }

        public HwAes(Connection connection, byte[] Key, int KeySize, CipherMode cipherMode, PaddingMode padding)
        {
            this.AES = new AesCryptoServiceProvider();
            this.AES.Padding = padding;
            this.AES.Mode = cipherMode;
            this.AES.KeySize = KeySize;
            this.IvConfuser = new DataConfuser(connection.PrivateSeed, 16);
            this.rngProvider = new RNGCryptoServiceProvider();
            ApplyKey(Key);
        }

        public byte[] Encrypt(byte[] Data, int Offset, int Length)
        {
            lock(AES)
            {
                byte[] NewIV = new byte[16];
                rngProvider.GetBytes(NewIV);
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
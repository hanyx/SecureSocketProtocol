using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
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
    public class RSAEncryption
    {
        private RSACryptoServiceProvider rsa;

        public string PrivateKey { get; internal set; }
        public string PublicKey { get; internal set; }
        public int EncChunkSize { get; private set; }
        public int DecChunkSize { get; private set; }
        public bool PkcsPadding { get; set; }
        public int KeySize { get; private set; }

        public RSAParameters? PrivateParameters
        {
            get
            {
                try
                {
                    return rsa.ExportParameters(true);
                }
                catch { return null;  }
            }
        }

        public RSAParameters? PublicParameters
        {
            get
            {
                try
                {
                    return rsa.ExportParameters(false);
                }
                catch { return null; }
            }
        }

        public string PublicParamsXml
        {
            get
            {
                if (!PublicParameters.HasValue)
                    return "";

                RSAParameters param = PublicParameters.Value;
                StringBuilder sb = new StringBuilder();

                sb.AppendLine("<RSAKeyValue>");
                sb.AppendLine("<Modulus>" + Convert.ToBase64String(param.Modulus) + "</Modulus>");
                sb.AppendLine("<Exponent>" + Convert.ToBase64String(param.Exponent) + "</Exponent>");
                sb.AppendLine("</RSAKeyValue>");

                return sb.ToString();
            }
        }

        public string PublicFingerprintSha1
        {
            get
            {
                if (!PublicParameters.HasValue)
                    return "";

                string fingerPrint = Convert.ToBase64String(PublicParameters.Value.Modulus);
                fingerPrint = BitConverter.ToString(SHA1.Create().ComputeHash(ASCIIEncoding.ASCII.GetBytes(fingerPrint)));
                return fingerPrint.Replace('-', ':');
            }
        }

        public string PublicFingerprintSha256
        {
            get
            {
                if (!PublicParameters.HasValue)
                    return "";

                string fingerPrint = Convert.ToBase64String(PublicParameters.Value.Modulus);
                fingerPrint = BitConverter.ToString(SHA256.Create().ComputeHash(ASCIIEncoding.ASCII.GetBytes(fingerPrint)));
                return fingerPrint.Replace('-', ':');
            }
        }

        public string PublicFingerprintSha512
        {
            get
            {
                if (!PublicParameters.HasValue)
                    return "";

                string fingerPrint = Convert.ToBase64String(PublicParameters.Value.Modulus);
                fingerPrint = BitConverter.ToString(SHA512.Create().ComputeHash(ASCIIEncoding.ASCII.GetBytes(fingerPrint)));
                return fingerPrint.Replace('-', ':');
            }
        }

        public string PublicFingerprintMd5
        {
            get
            {
                if (!PublicParameters.HasValue)
                    return "";

                string fingerPrint = Convert.ToBase64String(PublicParameters.Value.Modulus);
                fingerPrint = BitConverter.ToString(MD5.Create().ComputeHash(ASCIIEncoding.ASCII.GetBytes(fingerPrint)));
                return fingerPrint.Replace('-', ':');
            }
        }

        public string RsaXml
        {
            get { return rsa.ToXmlString(true); }
            set { rsa.FromXmlString(value); }
        }

        public string PublicRsaXml
        {
            get { return rsa.ToXmlString(false); }
            set { rsa.FromXmlString(value); }
        }

        public RSAEncryption(int KeySize, bool PkcsPadding = true)
        {
            this.rsa = new System.Security.Cryptography.RSACryptoServiceProvider(KeySize);
            this.PkcsPadding = PkcsPadding;
            this.KeySize = KeySize;
            this.DecChunkSize = (KeySize / 8);
            this.EncChunkSize = DecChunkSize / 2;
        }

        public RSAEncryption(int KeySize, string RsaXml, bool PkcsPadding = true)
        {
            this.rsa = new System.Security.Cryptography.RSACryptoServiceProvider(KeySize);
            this.RsaXml = RsaXml;
            this.PkcsPadding = PkcsPadding;
            this.KeySize = KeySize;
            this.DecChunkSize = (KeySize / 8);
            this.EncChunkSize = DecChunkSize / 2;
        }
        public RSAEncryption(int KeySize, string PublicKey, string PrivateKey, bool PkcsPadding = true)
        {
            this.rsa = new System.Security.Cryptography.RSACryptoServiceProvider(KeySize);
            this.PublicKey = PublicKey;
            this.PrivateKey = PrivateKey;
            this.PkcsPadding = PkcsPadding;
            this.KeySize = KeySize;
            this.DecChunkSize = (KeySize / 8);
            this.EncChunkSize = DecChunkSize / 2;
        }
        public RSAEncryption(int KeySize, byte[] Modulus, byte[] Exponent, bool PkcsPadding = true)
        {
            RSAParameters parameters = new RSAParameters();
            parameters.Exponent = Exponent;
            parameters.Modulus = Modulus;
            this.rsa = new RSACryptoServiceProvider(KeySize);
            this.rsa.ImportParameters(parameters);
            this.PkcsPadding = PkcsPadding;

            this.KeySize = KeySize;
            this.DecChunkSize = (KeySize / 8);
            this.EncChunkSize = DecChunkSize / 2;
        }

        public void LoadPrivateKey(string PrivateKey)
        {
            this.PrivateKey = PrivateKey;
            rsa.FromXmlString(PrivateKey);
        }

        public void LoadPublicKey(string PublicKey)
        {
            this.PublicKey = PublicKey;
            rsa.FromXmlString(PublicKey);
        }

        public string GeneratePrivateKey()
        {
            this.PrivateKey = rsa.ToXmlString(true);
            return this.PrivateKey;
        }

        public string GeneratePublicKey()
        {
            this.PublicKey = rsa.ToXmlString(false);
            return this.PublicKey;
        }

        public byte[] Encrypt(byte[] Data, int Offset, int Length)
        {
            lock (rsa)
            {
                int ExpectedSize = (KeySize / 8) * (Length / EncChunkSize);
                using (MemoryStream stream = new MemoryStream(Data.Length + ExpectedSize))
                {
                    int LengthLeft = Length;

                    for (int i = Offset; i < Length; i += EncChunkSize)
                    {
                        int size = i + EncChunkSize < Length ? EncChunkSize : LengthLeft;

                        //byte[] temp = new byte[size];
                        //Array.Copy(Data, i, temp, 0, size);
                        byte[] encrypted = rsa.Encrypt(Data, PkcsPadding);

                        stream.Write(encrypted, 0, encrypted.Length);

                        if (LengthLeft >= EncChunkSize)
                            LengthLeft -= size;
                    }
                    return stream.ToArray();
                }
            }
        }

        public byte[] Decrypt(byte[] Data, int Offset, int Length)
        {
            if (Length % DecChunkSize != 0)
                throw new Exception("Invalid length");

            using (MemoryStream stream = new MemoryStream(Data.Length))
            {
                int LengthLeft = Length;

                for (int i = Offset; i < Length; i += DecChunkSize)
                {
                    //byte[] temp = new byte[DecChunkSize];
                    //Array.Copy(Data, i, temp, 0, DecChunkSize);

                    byte[] decrypted = rsa.Decrypt(Data, PkcsPadding);
                    stream.Write(decrypted, 0, decrypted.Length);

                    if (LengthLeft >= DecChunkSize)
                        LengthLeft -= DecChunkSize;
                }
                return stream.ToArray();
            }
        }

        public byte[] SignData(byte[] OriginalData)
        {
            return rsa.SignData(OriginalData, new SHA256CryptoServiceProvider());
        }

        public bool VerifyData(byte[] OriginalData, byte[] SignedData)
        {
            return rsa.VerifyData(OriginalData, new SHA256CryptoServiceProvider(), SignedData);
        }
    }
}

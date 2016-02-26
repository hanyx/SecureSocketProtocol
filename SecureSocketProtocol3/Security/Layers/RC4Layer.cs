using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public class RC4Layer : ILayer
    {
        private byte[] Key;

        public RC4Layer()
        {

        }

        public LayerType Type
        {
            get { return LayerType.Encryption; }
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            RC4(ref InData, InOffset, InLen, this.Key);
            OutData = InData;
            OutOffset = InOffset;
            OutLen = InLen;
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            RC4(ref InData, InOffset, InLen, this.Key);
            OutData = InData;
            OutOffset = InOffset;
            OutLen = InLen;
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {
            this.Key = Key;
        }

        //Credits to: http://dotnet-snippets.com/snippet/rc4-encryption/577
        //Modified by AnguisCaptor
        private void RC4(ref byte[] bytes, int Offset, int Length, byte[] key)
        {
            byte[] s = new byte[256];
            byte[] k = new byte[256];
            Byte temp;
            int i, j;

            for (i = 0; i < 256; i++)
            {
                s[i] = (Byte)i;
                k[i] = key[i % key.Length];
            }

            j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + s[i] + k[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
            }

            i = j = 0;
            for (int x = Offset; x < Length; x++)
            {
                i = (i + 1) % 256;
                j = (j + s[i]) % 256;
                temp = s[i];
                s[i] = s[j];
                s[j] = temp;
                int t = (s[i] + s[j]) % 256;
                bytes[x] ^= s[t];
            }
        }


    }
}

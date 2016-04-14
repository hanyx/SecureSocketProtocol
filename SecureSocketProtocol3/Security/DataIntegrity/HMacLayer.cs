using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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

namespace SecureSocketProtocol3.Security.DataIntegrity
{
    public class HMacLayer : IDataIntegrityLayer
    {
        private HMAC hMac;
        private SSPClient Client;

        public HMacLayer(SSPClient Client, HMAC hMac)
        {
            this.hMac = hMac;
            this.Client = Client;
        }

        public HMacLayer(SSPClient Client)
        {
            hMac = new HMACSHA1(Client.Connection.NetworkKey);
            this.Client = Client;
        }

        public byte[] ComputeHash(SSPClient Client, byte[] Data, int Offset, int Length)
        {
            lock (hMac)
            {
                return hMac.ComputeHash(Data, Offset, Length);
            }
        }

        public bool Verify(SSPClient Client, byte[] DataIntegrityLayerData, byte[] Data, int Offset, int Length)
        {
            lock (hMac)
            {
                if (DataIntegrityLayerData == null || (DataIntegrityLayerData != null && DataIntegrityLayerData.Length < FixedLength))
                    return false;

                byte[] ComputedHash = hMac.ComputeHash(Data, Offset, Length);

                for (int i = 0; i < ComputedHash.Length; i++)
                {
                    if (ComputedHash[i] != DataIntegrityLayerData[i])
                        return false;
                }
                return true;
            }
        }

        public int FixedLength
        {
            get { return hMac.HashSize / 8; } //  divide by 8 to get byte length
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {
            lock(hMac)
            {
                FastRandom rnd = new FastRandom(Client.Connection.PrivateSeed);

                byte[] VerifyKey = new byte[32];
                rnd.NextBytes(VerifyKey);

                for (int i = 0; i < Key.Length; i++)
                {
                    VerifyKey[i % (VerifyKey.Length - 1)] += Key[i];
                    VerifyKey[i % (VerifyKey.Length - 1)] += Salt[i % (Salt.Length - 1)];
                }

                hMac.Key = VerifyKey;
            }
        }
    }
}
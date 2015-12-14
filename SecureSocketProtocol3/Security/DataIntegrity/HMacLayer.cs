using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

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
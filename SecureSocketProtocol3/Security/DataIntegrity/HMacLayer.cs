using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
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
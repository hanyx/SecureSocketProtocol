using SecureSocketProtocol3.Hashers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Security.DataIntegrity
{
    public class Sha1Layer : IDataIntegrityLayer
    {
        private SHA1Managed sha1;

        public Sha1Layer()
        {
            this.sha1 = new SHA1Managed();
        }

        public byte[] ComputeHash(SSPClient Client, byte[] Data, int Offset, int Length)
        {
            return sha1.ComputeHash(Data, Offset, Length);
        }

        public bool Verify(SSPClient Client, byte[] DataIntegrityLayerData, byte[] Data, int Offset, int Length)
        {
            if (DataIntegrityLayerData == null || (DataIntegrityLayerData != null && DataIntegrityLayerData.Length < FixedLength))
                return false;

            byte[] ComputedHash = sha1.ComputeHash(Data, Offset, Length);

            for (int i = 0; i < ComputedHash.Length; i++)
            {
                if (ComputedHash[i] != DataIntegrityLayerData[i])
                    return false;
            }
            return true;
        }


        public int FixedLength
        {
            get { return 20; }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }
    }
}
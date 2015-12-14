using SecureSocketProtocol3.Hashers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.DataIntegrity
{
    public class CRC32Layer : IDataIntegrityLayer
    {
        private CRC32 crc;

        public CRC32Layer()
        {
            this.crc = new CRC32();
        }

        public byte[] ComputeHash(SSPClient Client, byte[] Data, int Offset, int Length)
        {
            return crc.ComputeHash(Data, Offset, Length);
        }

        public bool Verify(SSPClient Client, byte[] DataIntegrityLayerData, byte[] Data, int Offset, int Length)
        {
            if (DataIntegrityLayerData == null || (DataIntegrityLayerData != null && DataIntegrityLayerData.Length < FixedLength))
                return false;

            byte[] ComputedHash = crc.ComputeHash(Data, Offset, Length);

            if (BitConverter.ToInt32(DataIntegrityLayerData, 0) != BitConverter.ToInt32(ComputedHash, 0))
                return false;
            return true;
        }


        public int FixedLength
        {
            get { return 4; }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }
    }
}
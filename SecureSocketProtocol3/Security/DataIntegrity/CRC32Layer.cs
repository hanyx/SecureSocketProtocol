using SecureSocketProtocol3.Hashers;
using System;
using System.Collections.Generic;
using System.Linq;
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
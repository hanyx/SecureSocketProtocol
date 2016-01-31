﻿using SecureSocketProtocol3.Hashers;
using System;
using System.Collections.Generic;
using System.Linq;
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
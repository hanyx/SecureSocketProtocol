using SecureSocketProtocol3.Hashers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Headers
{
    public abstract class Header
    {
        internal byte HeaderId;

        public abstract Version Version { get; }
        public abstract string HeaderName { get; }

        public Header()
        {

        }

        internal byte GetHeaderId(Header header)
        {
            CRC32 hasher = new CRC32();
            uint name = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(HeaderName)), 0);
            uint version = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Version.ToString())), 0);
            return (byte)(name ^ version);
        }
    }
}
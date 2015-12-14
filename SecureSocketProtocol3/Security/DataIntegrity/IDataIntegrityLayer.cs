using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.DataIntegrity
{
    public interface IDataIntegrityLayer
    {
        byte[] ComputeHash(SSPClient Client, byte[] Data, int Offset, int Length);

        bool Verify(SSPClient Client, byte[] DataIntegrityLayerData, byte[] Data, int Offset, int Length);

        //Most likely not even required for a Data Integrity Layer, but it sure would be handy for HMAC
        void ApplyKey(byte[] Key, byte[] Salt);

        int FixedLength { get; }
    }
}
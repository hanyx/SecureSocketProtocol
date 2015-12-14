using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public interface ILayer
    {
        LayerType Type { get; }

        void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen);
        void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen);

        void ApplyKey(byte[] Key, byte[] Salt);
    }
}

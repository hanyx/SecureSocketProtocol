using SecureSocketProtocol3.Compressions;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public class QuickLzLayer : ILayer
    {
        private UnsafeQuickLZ quickLZ;

        public LayerType Type
        {
            get { return LayerType.Compression; }
        }

        public QuickLzLayer()
        {
            this.quickLZ = new UnsafeQuickLZ();
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            if (InData != null)
            {
                OutData = quickLZ.compress(InData, (uint)InOffset, (uint)InLen);
                OutOffset = 0;

                if (OutData == null)
                {
                    OutData = InData;
                    OutOffset = InOffset;
                    OutLen = InLen;
                }
                else
                {
                    OutLen = OutData.Length;
                }
            }
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            if (InData != null)
            {
                OutData = quickLZ.decompress(InData, (uint)InOffset);
                OutOffset = 0;

                if (OutData == null)
                {
                    OutData = InData;
                    OutOffset = InOffset;
                    OutLen = InLen;
                }
                else
                {
                    OutLen = OutData.Length;
                }
            }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }
    }
}
using SecureSocketProtocol3.Security.Layers;
using SevenZip;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace ExtraLayers.LZMA
{
    public class LzmaLayer : ILayer
    {
        public SecureSocketProtocol3.LayerType Type
        {
            get { return SecureSocketProtocol3.LayerType.Compression; }
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            LZMACompressor comp = new LZMACompressor();
            using (MemoryStream ms = new MemoryStream())
            {
                comp.CompressLZMA(new MemoryStream(InData, InOffset, InLen), ms);
                OutData = ms.ToArray();
                OutOffset = 0;
                OutLen = OutData.Length;
            }
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            LZMACompressor comp = new LZMACompressor();
            using (MemoryStream ms = new MemoryStream())
            {
                comp.DecompressLZMA(new MemoryStream(InData, InOffset, InLen), ms);
                OutData = ms.ToArray();
                OutOffset = 0;
                OutLen = OutData.Length;
            }
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }
    }
}

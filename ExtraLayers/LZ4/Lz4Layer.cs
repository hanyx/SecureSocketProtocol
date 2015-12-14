using SecureSocketProtocol3.Security.Layers;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace ExtraLayers.LZ4
{
    public class Lz4Layer : ILayer
    {

        public SecureSocketProtocol3.LayerType Type
        {
            get { return SecureSocketProtocol3.LayerType.Compression; }
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            OutData = new byte[InLen + (1024 * 16)]; //16KB extra space, should be enough
            OutOffset = 0;
            OutLen = LZ4.Compress(InData, InOffset, InLen, OutData, 0);
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            //this should do for now as LZ4 does not contain a "Offset" parameter
            byte[] TempInData = new byte[InLen];
            Array.Copy(InData, InOffset, TempInData, 0, TempInData.Length);

            OutData = new byte[InLen + (1024 * 16)]; //16KB extra space, should be enough
            OutOffset = 0;
            OutLen = LZ4.Decompress(TempInData, OutData);
        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }
    }
}
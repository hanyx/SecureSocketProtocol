using System;
using System.Collections.Generic;
using System.Text;

namespace ExtraLayers.LZ4
{
    public static class LZ4DecompressorFactory
    {
        public static ILZ4Decompressor CreateNew()
        {
            if (IntPtr.Size == 4)
                return new LZ4Decompressor32();
            return new LZ4Decompressor64();
        }
    }
}

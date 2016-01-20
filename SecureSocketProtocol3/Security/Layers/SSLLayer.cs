using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net.Security;
using System.Text;

namespace SecureSocketProtocol3.Security.Layers
{
    public class SSLLayer : ILayer
    {
        private SSPClient client;

        public SSLLayer(SSPClient Client)
        {
            this.client = Client;
        }

        public LayerType Type
        {
            get { return LayerType.Encryption; }
        }

        public void ApplyLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {
            
        }

        public void RemoveLayer(byte[] InData, int InOffset, int InLen, ref byte[] OutData, ref int OutOffset, ref int OutLen)
        {

        }

        public void ApplyKey(byte[] Key, byte[] Salt)
        {

        }

        private class InnerStream : Stream
        {

            public override bool CanRead
            {
                get { return true; }
            }

            public override bool CanSeek
            {
                get { return false; }
            }

            public override bool CanWrite
            {
                get { return true; }
            }

            public override void Flush()
            {

            }

            public override long Length
            {
                get
                {
                    return 0;
                }
            }

            public override long Position
            {
                get
                {
                    return 0;
                }
                set
                {

                }
            }

            public override int Read(byte[] buffer, int offset, int count)
            {
                return count;
            }

            public override long Seek(long offset, SeekOrigin origin)
            {
                return 0;
            }

            public override void SetLength(long value)
            {

            }

            public override void Write(byte[] buffer, int offset, int count)
            {
                
            }
        }
    }
}
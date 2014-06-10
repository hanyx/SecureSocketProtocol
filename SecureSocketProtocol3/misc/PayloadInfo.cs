using SecureSocketProtocol3.Network.Headers;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Misc
{
    internal class PayloadInfo
    {
        public byte[] Payload { get; private set; }
        public Header Header { get; private set; }

        public PayloadInfo(byte[] payload, Header header)
        {
            this.Payload = payload;
            this.Header = header;
        }
    }
}
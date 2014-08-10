using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Misc
{
    internal class SystemPacket
    {
        public Header Header { get; private set; }
        public IMessage Message { get; private set; }

        public SystemPacket(Header header, IMessage message)
        {
            this.Header = header;
            this.Message = message;
        }
    }
}
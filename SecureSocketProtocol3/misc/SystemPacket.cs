using SecureSocketProtocol3.Network;
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
        public ushort ConnectionId { get; private set; }
        public OperationalSocket OpSocket { get; private set; }

        public SystemPacket(Header header, IMessage message, ushort ConnectionId, OperationalSocket OpSocket)
        {
            this.Header = header;
            this.Message = message;
            this.ConnectionId = ConnectionId;
            this.OpSocket = OpSocket;
        }
    }
}
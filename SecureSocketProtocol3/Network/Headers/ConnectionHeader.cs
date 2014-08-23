using ProtoBuf;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Headers
{
    /// <summary>
    /// The header information for establishing a connection
    /// </summary>
    [ProtoContract]
    internal sealed class ConnectionHeader : Header
    {
        public override Version Version
        {
            get { return new Version(0, 0, 0, 1); }
        }

        public override string HeaderName
        {
            get { return "Connection Header"; }
        }

        [ProtoMember(1)]
        public int ConnectionId;

        public ConnectionHeader(int ConnectionId)
            : base()
        {
            this.ConnectionId = ConnectionId;
        }
        public ConnectionHeader()
            : base()
        {

        }
    }
}
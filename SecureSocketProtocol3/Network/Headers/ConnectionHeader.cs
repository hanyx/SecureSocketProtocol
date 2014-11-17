using ProtoBuf;
using System;
using System.Collections.Generic;
using System.IO;
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
            get { return new Version(0, 0, 0, 3); }
        }

        public override string HeaderName
        {
            get { return "Connection Header"; }
        }

        [ProtoMember(1)]
        public byte[] HeaderPayload;

        [ProtoMember(2)]
        public ushort HeaderPayloadId;

        [ProtoMember(3)]
        public int FeatureId;

        public ConnectionHeader(Header header, OperationalSocket OpSocket, int FeatureId)
            : base()
        {
            this.HeaderPayload = Headers.Header.Serialize(header);

            this.HeaderPayloadId = OpSocket.Headers.GetHeaderId(header);
            this.FeatureId = FeatureId;
        }

        public ConnectionHeader()
            : base()
        {

        }

        public Header DeserializeHeader(OperationalSocket OpSocket)
        {
            Type HeaderType = OpSocket.Headers.GetHeaderType(HeaderPayloadId);
            if(HeaderType == null)
                return null;
            return Headers.Header.DeSerialize(HeaderType, new Utils.PayloadReader(HeaderPayload));
        }
    }
}
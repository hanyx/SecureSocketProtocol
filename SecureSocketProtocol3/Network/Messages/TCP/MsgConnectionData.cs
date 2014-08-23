using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgConnectionData : IMessage
    {
        [ProtoMember(1)]
        public bool isData;

        [ProtoMember(2)]
        public byte[] Payload;

        [ProtoMember(3)]
        public uint MessageId;

        [ProtoMember(4)]
        public byte[] HeaderPayload;

        [ProtoMember(5)]
        public ushort HeaderId;

        public MsgConnectionData(OperationalSocket OpSocket, byte[] Data, Headers.Header header)
            : base()
        {
            this.isData = true;
            this.Payload = Data;
            this.MessageId = 0;
            this.HeaderPayload = Headers.Header.Serialize(header);
            this.HeaderId = OpSocket.Headers.GetHeaderId(header);
        }
        public MsgConnectionData(OperationalSocket OpSocket, IMessage Message, Headers.Header header)
            : base()
        {
            this.isData = false;
            this.Payload = IMessage.Serialize(Message);
            this.MessageId = OpSocket.messageHandler.GetMessageId(Message.GetType());
            this.HeaderPayload = Headers.Header.Serialize(header);
            this.HeaderId = OpSocket.Headers.GetHeaderId(header);
        }

        public MsgConnectionData()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client)
        {
            ConnectionHeader header = Header as ConnectionHeader;
            if (header != null)
            {
                OperationalSocket OpSocket = null;
                lock (client.Connection.OperationalSockets)
                {
                    if (client.Connection.OperationalSockets.TryGetValue(header.ConnectionId, out OpSocket))
                    {
                        //de-serialize the header
                        Type HeaderType = OpSocket.Headers.GetHeaderType(HeaderId);

                        if(HeaderType == null)
                        {
                            //drop client ?
                            return;
                        }

                        Header p_header = Headers.Header.DeSerialize(HeaderType, new PayloadReader(HeaderPayload));

                        if (isData)
                        {
                            OpSocket.onReceiveData(Payload, p_header);
                        }
                        else
                        {
                            IMessage msg = OpSocket.messageHandler.HandleMessage(new PayloadReader(new MemoryStream(Payload)), MessageId);
                            OpSocket.onReceiveMessage(msg, p_header);
                        }
                    }
                    else
                    {
                        //drop client ?
                    }
                }
            }
        }
    }
}
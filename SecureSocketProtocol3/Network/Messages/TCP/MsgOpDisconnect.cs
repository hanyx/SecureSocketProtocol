using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgOpDisconnect : IMessage
    {
        [ProtoMember(1)]
        public ushort ConnectionId { get; set; }

        public MsgOpDisconnect(ushort ConnectionId)
            : base()
        {
            this.ConnectionId = ConnectionId;
        }
        public MsgOpDisconnect()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket OpSocket)
        {
            RequestHeader reqHeader = Header as RequestHeader;
            if (reqHeader != null)
            {
                lock (client.Connection.OperationalSockets)
                {
                    if (!client.Connection.OperationalSockets.TryGetValue(ConnectionId, out OpSocket))
                    {
                        return;
                    }
                }


                if(!OpSocket.isConnected)
                {
                    return;
                }

                OpSocket.InternalSendMessage(new MsgOpDisconnectResponse(ConnectionId), new RequestHeader(reqHeader.RequestId, true));
                OpSocket.isConnected = false;

                lock (client.Connection.OperationalSockets)
                {
                    if (client.Connection.OperationalSockets.ContainsKey(OpSocket.ConnectionId))
                    {
                        client.Connection.OperationalSockets.Remove(OpSocket.ConnectionId);
                    }
                }

                try
                {
                    OpSocket.onDisconnect(DisconnectReason.UserDisconnection);
                    client.onOperationalSocket_Disconnected(OpSocket, DisconnectReason.UserDisconnection);
                }
                catch (Exception ex)
                {
                    SysLogger.Log(ex.Message, SysLogType.Error);
                }
            }
        }
    }
}
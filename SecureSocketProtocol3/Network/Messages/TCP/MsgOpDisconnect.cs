using ProtoBuf;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Security.Serialization;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

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
                    SysLogger.Log(ex.Message, SysLogType.Error, ex);
                }
            }
        }
    }
}
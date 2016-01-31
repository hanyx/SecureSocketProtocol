﻿using ProtoBuf;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Security.Serialization;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

/*
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
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
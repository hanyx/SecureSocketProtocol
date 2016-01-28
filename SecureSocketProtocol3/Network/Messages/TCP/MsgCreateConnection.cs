using ProtoBuf;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Security.Serialization;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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
    internal class MsgCreateConnection : IMessage
    {
        [ProtoMember(1)]
        public ulong Identifier;

        public MsgCreateConnection(ulong Identifier)
            : base()
        {
            this.Identifier = Identifier;
        }
        public MsgCreateConnection()
            : base()
        {

        }

        public override void ProcessPayload(SSPClient client, OperationalSocket _OpSocket)
        {
            RequestHeader reqHeader = Header as RequestHeader;
            if (reqHeader != null)
            {
                Type type = null;
                lock (client.Connection.RegisteredOperationalSockets)
                {
                    client.Connection.RegisteredOperationalSockets.TryGetValue(Identifier, out type);
                }
                
                if(type != null)
                {
                    bool SendedSuccess = false;
                    try
                    {
                        OperationalSocket OpSocket = (OperationalSocket)Activator.CreateInstance(type, client);

                        OpSocket.isConnected = true;

                        lock (client.Connection.OperationalSockets)
                        {
                            FastRandom rnd = new FastRandom();
                            OpSocket.ConnectionId = (ushort)rnd.Next(1, 65535);
                            while(client.Connection.OperationalSockets.ContainsKey(OpSocket.ConnectionId))
                                OpSocket.ConnectionId = (ushort)rnd.Next(1, 65535);

                            client.Connection.OperationalSockets.Add(OpSocket.ConnectionId, OpSocket);
                        }


                        try
                        {
                            OpSocket.onBeforeConnect();
                            client.onOperationalSocket_BeforeConnect(OpSocket);
                        }
                        catch (Exception ex)
                        {
                            SysLogger.Log(ex.Message, SysLogType.Error, ex);
                            OpSocket.onException(ex, ErrorType.UserLand);
                        }

                        client.Connection.SendMessage(new MsgCreateConnectionResponse(OpSocket.ConnectionId, true), new RequestHeader(reqHeader.RequestId, true));
                        SendedSuccess = true;
                        OpSocket.onConnect();
                        client.onOperationalSocket_Connected(OpSocket);
                    }
                    catch (Exception ex)
                    {
                        SysLogger.Log(ex.Message, SysLogType.Error, ex);

                        if (!SendedSuccess)
                        {
                            client.Connection.SendMessage(new MsgCreateConnectionResponse(0, false), new RequestHeader(reqHeader.RequestId, true));
                        }
                    }
                }
                else
                {
                    client.Connection.SendMessage(new MsgCreateConnectionResponse(0, false), new RequestHeader(reqHeader.RequestId, true));
                }
            }
        }
    }
}
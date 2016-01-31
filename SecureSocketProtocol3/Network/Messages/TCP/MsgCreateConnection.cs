using ProtoBuf;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Security.Serialization;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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
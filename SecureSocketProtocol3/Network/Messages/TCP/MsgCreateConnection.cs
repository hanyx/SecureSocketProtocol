using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;

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
                        }
                        catch (Exception ex)
                        {
                            SysLogger.Log(ex.Message, SysLogType.Error);
                            OpSocket.onException(ex, ErrorType.UserLand);
                        }

                        client.Connection.SendMessage(new MsgCreateConnectionResponse(OpSocket.ConnectionId, true), new RequestHeader(reqHeader.RequestId, true));
                        SendedSuccess = true;
                        OpSocket.onConnect();
                    }
                    catch (Exception ex)
                    {
                        SysLogger.Log(ex.Message, SysLogType.Error);

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
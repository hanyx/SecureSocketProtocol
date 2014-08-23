using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
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

        public override void ProcessPayload(SSPClient client)
        {
            if (!client.IsServerSided)
                return; //weird... send nothing back

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
                    try
                    {
                        OperationalSocket OpSocket = (OperationalSocket)Activator.CreateInstance(type, client);
                        OpSocket.isConnected = true;

                        lock (client.Connection.OperationalSockets)
                        {
                            Random rnd = new Random();
                            OpSocket.ConnectionId = rnd.Next();
                            while(client.Connection.OperationalSockets.ContainsKey(OpSocket.ConnectionId))
                                OpSocket.ConnectionId = rnd.Next();
                        }

                        client.Connection.OperationalSockets.Add(OpSocket.ConnectionId, OpSocket);

                        OpSocket.onBeforeConnect();
                        client.Connection.SendMessage(new MsgCreateConnectionResponse(OpSocket.ConnectionId, true), new RequestHeader(reqHeader.RequestId, true));
                        OpSocket.Connect();
                    }
                    catch
                    {
                        client.Connection.SendMessage(new MsgCreateConnectionResponse(0, false), new RequestHeader(reqHeader.RequestId, true));
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
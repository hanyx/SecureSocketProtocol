using ProtoBuf;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Messages.TCP
{
    [ProtoContract]
    internal class MsgCreateConnection : IMessage
    {
        public MsgCreateConnection()
            : base()
        {

        }


    }
}
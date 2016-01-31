using ProtoBuf;
using SecureSocketProtocol3.Attributes;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestServer.Sockets.Messages
{
    [ProtoContract]
    [Serialization(typeof(ProtobufSerialization))]
    public class TestMessage : IMessage
    {
        [ProtoMember(1)]
        public byte[] Buffer;

        [ProtoMember(2)]
        public string StringTest;

        [ProtoMember(3)]
        public byte ByteTest;

        [ProtoMember(4)]
        public int IntTest;

        [ProtoMember(5)]
        public uint UIntTest;

        [ProtoMember(6)]
        public long LongTest;

        [ProtoMember(7)]
        public ulong ULongTest;

        [ProtoMember(8)]
        public decimal DecimalTest;

        [ProtoMember(9)]
        public float FloatTest;

        [ProtoMember(10)]
        public List<TestO> ListTest;

        [ProtoMember(11)]
        public DateTime DateTest;

        public TestMessage()
            : base()
        {

        }

        public override void ProcessPayload(SecureSocketProtocol3.SSPClient client, OperationalSocket OpSocket)
        {

        }

        public override ISerialization onGetSerializer()
        {
            return null;
        }
    }

    [ProtoContract]
    public class TestO
    {
        [ProtoMember(1)]
        public int Num1;

        [ProtoMember(2)]
        public string Str1;
    }
}
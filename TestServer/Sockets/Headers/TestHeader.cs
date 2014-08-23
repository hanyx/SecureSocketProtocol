using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using System;
using System.Collections.Generic;
using System.Text;

namespace TestServer.Sockets.Headers
{
    [ProtoContract]
    public class TestHeader : Header
    {
        public TestHeader()
            : base()
        {

        }

        public override Version Version
        {
            get { return new Version(1, 0, 0, 1); }
        }

        public override string HeaderName
        {
            get { return "Test Header"; }
        }
    }
}

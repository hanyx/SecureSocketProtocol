using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSocketProtocol3.Network;
using System.IO;
using SecureSocketProtocol3;
using SSPTests.ServerSrc;
using SecureSocketProtocol3.Security.Serialization;
using System.Collections.Generic;

namespace SSPTests
{
    [TestClass]
    public class BasicTests
    {
        [TestMethod]
        public void Test_RunBasicServer()
        {
            //should able to run just fine, might throw error if port is already in use
            BasicServer basicServer = new BasicServer();
            basicServer.Dispose();
        }

        [TestMethod]
        public void Test_ManyConnections()
        {
            //should able to run just fine, might throw error if port is already in use
            using(BasicServer basicServer = new BasicServer())
            {
                for(int i = 0; i < 100; i++)
                {
                    BasicPeer peer = new BasicPeer("127.0.0.1", 444);
                }
            }
        }






        public class ServerProps : ServerProperties
        {

            public override ushort ListenPort
            {
                get { return 444; }
            }

            public override string ListenIp
            {
                get { return "0.0.0.0"; }
            }

            public override string ListenIp6
            {
                get { return "::"; }
            }

            public override bool UseIPv4AndIPv6
            {
                get { return true; }
            }

            public override Stream[] KeyFiles
            {
                get
                {
                    List<MemoryStream> _keyFiles = new List<MemoryStream>();
                    _keyFiles.Add(new MemoryStream(new byte[] { 1, 2, 3, 4, 5, 6, 7, 8 }));
                    _keyFiles.Add(new MemoryStream(new byte[] { 8, 7, 6, 5, 4, 3, 2, 1 }));
                    return _keyFiles.ToArray();
                }
            }

            public override byte[] NetworkKey
            {
                get
                {
                    return new byte[]
                    {
                        80, 118, 131, 114, 195, 224, 157, 246, 141, 113,
                        186, 243, 77, 151, 247, 84, 70, 172, 112, 115,
                        112, 110, 91, 212, 159, 147, 180, 188, 143, 251,
                        218, 155
                    };
                }
            }

            public override TimeSpan ClientTimeConnected
            {
                get { return new TimeSpan(1, 0, 0, 0); }
            }

            public override SecureSocketProtocol3.Security.Serialization.ISerialization DefaultSerializer
            {
                get { return new ProtobufSerialization(); }
            }
        }
    }
}
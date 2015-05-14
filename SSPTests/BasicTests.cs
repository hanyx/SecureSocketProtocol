using System;
using Microsoft.VisualStudio.TestTools.UnitTesting;
using SecureSocketProtocol3.Network;
using System.IO;
using SecureSocketProtocol3;
using SSPTests.ServerSrc;

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

            public override Stream[] KeyFiles
            {
                get { return new Stream[0]; }
            }

            public override uint Cipher_Rounds
            {
                get { return 1; }
            }

            public override CompressionAlgorithm CompressionAlgorithm
            {
                get { return SecureSocketProtocol3.CompressionAlgorithm.QuickLZ; }
            }

            public override EncAlgorithm EncryptionAlgorithm
            {
                get { return EncAlgorithm.HwAES; }
            }

            public override System.Drawing.Size Handshake_Maze_Size
            {
                get { return new System.Drawing.Size(128, 128); }
            }

            public override ushort Handshake_StepSize
            {
                get { return 5; }
            }

            public override ushort Handshake_MazeCount
            {
                get { return 1; }
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
        }
    }
}
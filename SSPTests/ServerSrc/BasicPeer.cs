using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SSPTests.ServerSrc
{
    public class BasicPeer : SSPClient
    {
        public BasicPeer()
            : base()
        {

        }
        public BasicPeer(string IP, ushort Port)
            : base(new ClientProps(IP, Port))
        {

        }

        public override void onConnect()
        {

        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {

        }

        public override void onBeforeConnect()
        {

        }

        public override void onOperationalSocket_BeforeConnect(SecureSocketProtocol3.Network.OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_Connected(SecureSocketProtocol3.Network.OperationalSocket OPSocket)
        {

        }

        public override void onOperationalSocket_Disconnected(SecureSocketProtocol3.Network.OperationalSocket OPSocket, DisconnectReason Reason)
        {

        }

        public class ClientProps : ClientProperties
        {
            private string _ip = "";
            private ushort _port = 0;

            public ClientProps(string IP, ushort Port)
            {
                this._ip = IP;
                this._port = Port;
            }

            public override uint Cipher_Rounds
            {
                get { return 1; }
            }

            public override CompressionAlgorithm CompressionAlgorithm
            {
                get { return SecureSocketProtocol3.CompressionAlgorithm.QuickLZ; }
            }

            public override int ConnectionTimeout
            {
                get { return 30000; }
            }

            public override EncAlgorithm EncryptionAlgorithm
            {
                get { return EncAlgorithm.HwAES; }
            }

            public override string HostIp
            {
                get { return _ip; }
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

            public override string Password
            {
                get { return "PassTest"; }
            }

            public override ushort Port
            {
                get { return _port; }
            }

            public override Stream[] PrivateKeyFiles
            {
                get
                {
                    List<MemoryStream> keys = new List<MemoryStream>();
                    keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
                    keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
                    return keys.ToArray();
                }
            }

            public override Stream PublicKeyFile
            {
                get
                {
                    return new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat"));
                }
            }

            public override string Username
            {
                get { return "UserTest"; }
            }

            public override ushort Handshake_MazeCount
            {
                get { return 1; }
            }

            public override System.Drawing.Size Handshake_Maze_Size
            {
                get { return new System.Drawing.Size(128, 128); }
            }

            public override ushort Handshake_StepSize
            {
                get { return 5; }
            }
        }
    }
}
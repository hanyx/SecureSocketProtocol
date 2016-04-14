using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;

namespace TestServer
{
    public class Server : SSPServer
    {
        public Server()
            : base(new ServerProps())
        {

        }

        public override SSPClient GetNewClient()
        {
            //register users if there aren't any, please use a database and not this way
            if (Program.Users.Count == 0)
            {
                List<Stream> keys = new List<Stream>();
                keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
                keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
                User user = MazeHandshake.RegisterUser(new Size(128, 128), 1, 5, "UserTest", "PassTest", keys, new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat")));

                Program.Users.Add(user.EncryptedHash, user.GetUserDbInfo());
            }
            return new Peer();
        }

        private class ServerProps : ServerProperties
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
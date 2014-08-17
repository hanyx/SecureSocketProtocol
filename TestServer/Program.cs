using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace TestServer
{
    class Program
    {
        public static SortedList<string, User.UserDbInfo> Users;

        static void Main(string[] args)
        {
            Users = new SortedList<string, User.UserDbInfo>();



            Server server = new Server();

            Process.GetCurrentProcess().WaitForExit();
        }
    }

    public class Server : SSPServer
    {
        public Server()
            : base(new ServerProps())
        {

        }

        public override SSPClient GetNewClient()
        {
            ///register users if there aren't any, please use a datbase and not this way
            if (Program.Users.Count == 0)
            {
                List<Stream> keys = new List<Stream>();
                foreach (string file in Directory.GetFiles(@"F:\", "*.*"))
                {
                    if (new FileInfo(file).Length < 5000)
                        continue;
                    if (keys.Count == 3)
                        break;
                    keys.Add(new MemoryStream(File.ReadAllBytes(file)));
                }
                User user = base.RegisterUser("UserTest", "PassTest", keys, new MemoryStream(File.ReadAllBytes(@"F:\Untitled.png")));

                Program.Users.Add(user.EncryptedHash, user.GetUserDbInfo());
            }
            return new Client();
        }

        public override User.UserDbInfo onFindUser(string EncryptedPublicKeyHash)
        {
            if (Program.Users.ContainsKey(EncryptedPublicKeyHash))
                return Program.Users[EncryptedPublicKeyHash];
            return null;
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

            public override CertificateInfo ServerCertificate
            {
                get { return new Certificate(); }
            }

            public override bool UserPassAuthenication
            {
                get { return false; }
            }

            public override Stream[] KeyFiles
            {
                get { return new Stream[0]; }
            }
        }

        private class Certificate : CertificateInfo
        {
            private DateTime validDate = DateTime.Now;

            public Certificate()
            {

            }

            public override string CommonName
            {
                get { return "Secure Socket Protocol 3"; }
            }

            public override string Country
            {
                get { return "Unknown"; }
            }

            public override string State
            {
                get { return "Unknown"; }
            }

            public override string Locality
            {
                get { return "Unknown"; }
            }

            public override DateTime ValidTo
            {
                get { return DateTime.Now.AddDays(1); }
            }

            public override DateTime ValidFrom
            {
                get { return validDate; }
            }

            public override string Organization
            {
                get { return "Unknown"; }
            }

            public override string Unit
            {
                get { return "Unknown"; }
            }

            public override string IssuerCommonName
            {
                get { return "Unknown"; }
            }

            public override string IssuerOrganization
            {
                get { return "Unknown"; }
            }

            public override string IssuerCountry
            {
                get { return "Unknown"; }
            }

            public override bool ShowProtectionMethods
            {
                get { return false; }
            }

            public override ChecksumHash Checksum
            {
                get { return ChecksumHash.SHA512; }
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
        }
    }

    public class Client : SSPClient
    {
        public Client()
            : base()
        {

        }

        protected override void onClientConnect()
        {

        }

        protected override void onDisconnect(DisconnectReason Reason)
        {

        }
    }
}

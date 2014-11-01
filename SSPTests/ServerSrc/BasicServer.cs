using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SSPTests.ServerSrc
{
    public class BasicServer : SSPServer
    {
        public SortedList<string, User.UserDbInfo> Users = new SortedList<string, User.UserDbInfo>();

        public BasicServer()
            : base(new BasicTests.ServerProps())
        {

        }

        public override SSPClient GetNewClient()
        {
            ///register users if there aren't any, please use a datbase and not this way
            if (Users.Count == 0)
            {
                List<Stream> keys = new List<Stream>();
                keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey1.dat")));
                keys.Add(new MemoryStream(File.ReadAllBytes(@".\Data\PrivateKey2.dat")));
                User user = base.RegisterUser("UserTest", "PassTest", keys, new MemoryStream(File.ReadAllBytes(@".\Data\PublicKey1.dat")));

                Users.Add(user.EncryptedHash, user.GetUserDbInfo());
            }
            return new BasicPeer();
        }

        public override User.UserDbInfo onFindUser(string EncryptedPublicKeyHash)
        {
            if (Users.ContainsKey(EncryptedPublicKeyHash))
                return Users[EncryptedPublicKeyHash];
            return null;
        }
    }
}
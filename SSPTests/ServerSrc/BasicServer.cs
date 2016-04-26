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
            return new BasicPeer();
        }
    }
}
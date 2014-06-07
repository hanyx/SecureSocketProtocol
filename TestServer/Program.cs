using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;

namespace TestServer
{
    class Program
    {
        static void Main(string[] args)
        {
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
            return new Client();
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
        }
    }

    public class Client : SSPClient
    {
        public Client()
            : base()
        {

        }

        public override void onClientConnect()
        {

        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }
    }
}

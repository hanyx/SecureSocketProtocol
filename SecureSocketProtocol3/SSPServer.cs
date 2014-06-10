using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class SSPServer : IDisposable
    {

        /// <summary> Get a new initialized client that can be used for the server </summary>
        public abstract SSPClient GetNewClient();

        internal object AuthLock = new object();
        internal Socket TcpServer { get; private set; }
        public ServerProperties serverProperties { get; private set; }
        internal SortedList<decimal, SSPClient> Clients { get; private set; }
        private RandomDecimal randomDecimal = new RandomDecimal(DateTime.Now.Millisecond);

        /// <summary>
        /// Initialize a new SSPServer
        /// </summary>
        /// <param name="serverProperties">The properties for the server</param>
        public SSPServer(ServerProperties serverProperties)
        {
            if (serverProperties == null)
                throw new ArgumentNullException("serverProperties");

            this.serverProperties = serverProperties;
            this.Clients = new SortedList<decimal, SSPClient>();

            this.TcpServer = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.TcpServer.Bind(new IPEndPoint(IPAddress.Parse(serverProperties.ListenIp), serverProperties.ListenPort));
            this.TcpServer.Listen(100);
            this.TcpServer.BeginAccept(AsyncAction, null);
        }

        private void AsyncAction(IAsyncResult result)
        {
            try
            {
                Socket AcceptSocket = this.TcpServer.EndAccept(result); //<- can throw a error
                SSPClient client = GetNewClient();
                client.Handle = AcceptSocket;
                client.Server = this;
                client.Connection = new Network.Connection(client);
                client.Connection.ClientId = randomDecimal.NextDecimal();

                lock (Clients)
                {
                    while (Clients.ContainsKey(client.Connection.ClientId))
                        client.Connection.ClientId = randomDecimal.NextDecimal();
                    Clients.Add(client.Connection.ClientId, client);
                }
            }
            catch { }
            this.TcpServer.BeginAccept(AsyncAction, null);
        }

        public void Dispose()
        {

        }
    }
}
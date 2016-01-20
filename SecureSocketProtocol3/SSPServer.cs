using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Processors;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace SecureSocketProtocol3
{
    public abstract class SSPServer : IDisposable
    {
        /// <summary> Get a new initialized client that can be used for the server </summary>
        public abstract SSPClient GetNewClient();

        internal object AuthLock = new object();
        internal Socket TcpServer { get; private set; }
        internal Socket TcpServer6 { get; private set; }
        public ServerProperties serverProperties { get; private set; }
        internal SortedList<decimal, SSPClient> Clients { get; private set; }
        internal RandomDecimal randomDecimal { get; private set; }

        private ClientAcceptProcessor ClientAcceptProcessor4; //IPv4
        private ClientAcceptProcessor ClientAcceptProcessor6; //IPv6

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
            this.randomDecimal = new RandomDecimal(DateTime.Now.Millisecond);

            SysLogger.Log("Starting server", SysLogType.Debug);

            this.ClientAcceptProcessor4 = new ClientAcceptProcessor();
            this.ClientAcceptProcessor6 = new ClientAcceptProcessor();



            //start the server for IPv4
            this.TcpServer = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.TcpServer.Bind(new IPEndPoint(IPAddress.Parse(serverProperties.ListenIp), serverProperties.ListenPort));
            this.TcpServer.Listen(100);
            this.TcpServer.BeginAccept(AcceptClientCallback, null);

            if (serverProperties.UseIPv4AndIPv6)
            {
                //start the server for IPv6
                this.TcpServer6 = new Socket(AddressFamily.InterNetworkV6, SocketType.Stream, ProtocolType.Tcp);
                this.TcpServer6.Bind(new IPEndPoint(IPAddress.Parse(serverProperties.ListenIp6), serverProperties.ListenPort));
                this.TcpServer6.Listen(100);
                this.TcpServer6.BeginAccept(AcceptClient6Callback, null);
            }

            SysLogger.Log("Started server", SysLogType.Debug);
        }

        private void AcceptClientCallback(IAsyncResult result)
        {
            ClientAcceptProcessor4.ProcessClient(this, TcpServer, result);

            try
            {
                this.TcpServer.BeginAccept(AcceptClientCallback, null);
            }
            catch { }
        }

        private void AcceptClient6Callback(IAsyncResult result)
        {
            ClientAcceptProcessor6.ProcessClient(this, TcpServer6, result);

            try
            {
                this.TcpServer6.BeginAccept(AcceptClient6Callback, null);
            }
            catch { }
        }

        public SSPClient[] GetClients()
        {
            lock (Clients)
            {
                SSPClient[] clients = new SSPClient[Clients.Count];
                Clients.Values.CopyTo(clients, 0);
                return clients;
            }
        }

        internal void RemoveClient(SSPClient client)
        {
            if (client != null)
            {
                lock (Clients)
                {
                    if (Clients.ContainsKey(client.ClientId))
                    {
                        Clients.Remove(client.ClientId);
                    }
                }
            }
        }

        public void Dispose()
        {
            TcpServer.Close();

            if (TcpServer6 != null)
                TcpServer.Close();

            lock (Clients)
            {
                foreach (SSPClient client in new List<SSPClient>(Clients.Values))
                {
                    client.Disconnect();
                }
            }
        }
    }
}
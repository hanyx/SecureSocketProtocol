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
    The MIT License (MIT)

    Copyright (c) 2016 AnguisCaptor

    Permission is hereby granted, free of charge, to any person obtaining a copy
    of this software and associated documentation files (the "Software"), to deal
    in the Software without restriction, including without limitation the rights
    to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
    copies of the Software, and to permit persons to whom the Software is
    furnished to do so, subject to the following conditions:

    The above copyright notice and this permission notice shall be included in all
    copies or substantial portions of the Software.

    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
    OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
    SOFTWARE.
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

        private ClientAcceptProcessor ClientAcceptProcessor4; //IPv4
        private ClientAcceptProcessor ClientAcceptProcessor6; //IPv6

        internal ClientPrecomputes PreComputes { get; private set; }

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

            SysLogger.Log("Starting server", SysLogType.Debug);

            this.ClientAcceptProcessor4 = new ClientAcceptProcessor();
            this.ClientAcceptProcessor6 = new ClientAcceptProcessor();

            this.PreComputes = new ClientPrecomputes();

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
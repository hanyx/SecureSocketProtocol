using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class SSPClient : IClient
    {
        public string RemoteIp { get; internal set; }
        public decimal ClientId { get { return Connection.ClientId; } }
        internal ClientProperties Properties { get; private set; }
        internal Socket Handle { get; set; }
        public Connection connection;

        public SSPClient()
        {

        }

        /// <summary>
        /// Create a connection
        /// </summary>
        /// <param name="Properties">The Properties</param>
        public SSPClient(ClientProperties Properties)
            : this()
        {
            this.Properties = Properties;
            Connect(ConnectionState.Open);
        }

        internal void Connect(ConnectionState State)
        {
            IPAddress[] resolved = Dns.GetHostAddresses(Properties.HostIp);
            string DnsIp = "";

            for (int i = 0; i < resolved.Length; i++)
            {
                if (resolved[i].AddressFamily == AddressFamily.InterNetwork)
                {
                    DnsIp = resolved[i].ToString();
                    break;
                }
            }

            if (DnsIp == "")
            {
                throw new Exception("Unable to resolve \"" + Properties.HostIp + "\" by using DNS");
            }

            do
            {
                this.Handle = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                IAsyncResult result = this.Handle.BeginConnect(new IPEndPoint(resolved[0], Properties.Port), (IAsyncResult ar) =>
                {
                    try
                    {
                        this.Handle.EndConnect(ar);
                    }
                    catch { /* Will throw a error if connection couldn't be made */ }
                }, null);

                Stopwatch sw = Stopwatch.StartNew();
                if (Properties.ConnectingTimeout > 0)
                    result.AsyncWaitHandle.WaitOne(Properties.ConnectingTimeout);
                else
                    result.AsyncWaitHandle.WaitOne();
                sw.Stop();
                Properties.ConnectingTimeout -= (int)sw.ElapsedMilliseconds;

                if (!this.Handle.Connected)
                    this.Handle.Close();

            } while (Properties.ConnectingTimeout > 0 && !this.Handle.Connected);

            if (!Handle.Connected)
                throw new Exception("Unable to establish a connection with " + Properties.HostIp + ":" + Properties.Port);

            connection = new Connection(this);
        }

        public override void onClientConnect()
        {

        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }

        public override void onException(Exception ex, ErrorType errorType)
        {

        }

        public override void Disconnect()
        {

        }
    }
}
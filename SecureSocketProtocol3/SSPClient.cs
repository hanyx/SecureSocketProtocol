using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Network.Messages.TCP;
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
        public bool Connected { get { return Connection.Connected; } }

        internal ClientProperties Properties { get; private set; }
        internal Socket Handle { get; set; }
        public Connection connection { get; private set; }
        internal SSPServer Server;
        internal ClientMaze clientHS { get; private set; }

        private object Locky = new object();

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

            if (String.IsNullOrEmpty(Properties.Username))
                throw new ArgumentException("Username");
            if (String.IsNullOrEmpty(Properties.Password))
                throw new ArgumentException("Password");
            if (Properties.PublicKeyFile == null)
                throw new ArgumentException("PublicKeyFile");
            if (Properties.PublicKeyFile.Length < 128)
                throw new ArgumentException("PublicKeyFile must be >=128 in length");
            if (Properties.PrivateKeyFiles == null)
                throw new ArgumentException("PrivateKeyFiles");
            if (Properties.PrivateKeyFiles.Length == 0)
                throw new ArgumentException("There must be atleast 1 private key file");

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

            int ConTimeout = Properties.ConnectionTimeout;
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
                if (ConTimeout > 0)
                {
                    result.AsyncWaitHandle.WaitOne(ConTimeout);
                }
                else
                {
                    result.AsyncWaitHandle.WaitOne();
                }

                sw.Stop();
                ConTimeout -= (int)sw.ElapsedMilliseconds;

                if (!this.Handle.Connected)
                    this.Handle.Close();

            } while (ConTimeout > 0 && !this.Handle.Connected);

            if (!Handle.Connected)
                throw new Exception("Unable to establish a connection with " + Properties.HostIp + ":" + Properties.Port);

            connection = new Connection(this);

            //let's begin the handshake
            this.clientHS = new ClientMaze();
            byte[] byteCode = clientHS.GetByteCode();
            connection.SendMessage(new MsgHandshake(byteCode), new SystemHeader());
        }

        protected override void onClientConnect()
        {

        }

        protected override void onDisconnect(DisconnectReason Reason)
        {

        }

        protected override void onException(Exception ex, ErrorType errorType)
        {

        }

        protected override void Disconnect()
        {

        }

        public void CreateConnection()
        {
            lock (Locky)
            {
                connection.SendMessage(new MsgCreateConnection(), new SystemHeader());


            }
        }
    }
}
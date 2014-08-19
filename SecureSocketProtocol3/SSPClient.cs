using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class SSPClient
    {
        public abstract void onBeforeConnect();
        public abstract void onConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onException(Exception ex, ErrorType errorType);

        public Connection Connection { get; internal set; }
        public string RemoteIp { get; internal set; }
        public decimal ClientId { get { return Connection.ClientId; } }
        public bool Connected { get { return Connection.Connected; } }

        internal ClientProperties Properties { get; private set; }
        internal Socket Handle { get; set; }
        internal SSPServer Server;
        internal Mazing clientHS { get; private set; }
        internal ServerMaze serverHS { get; private set; }

        private object Locky = new object();
        internal bool IsServerSided { get { return Server != null; } }

        public SSPClient()
        {
            serverHS = new ServerMaze();
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

            Connection = new Connection(this);
            Connection.StartReceiver();

            //let's begin the handshake
            User user = new User(Properties.Username, Properties.Password, new List<Stream>(Properties.PrivateKeyFiles), Properties.PublicKeyFile);
            user.GenKey(SessionSide.Client);

            this.clientHS = user.MazeHandshake;
            byte[] encryptedPublicKey = clientHS.GetEncryptedPublicKey();


            byte[] byteCode = clientHS.GetByteCode();
            Connection.SendMessage(new MsgHandshake(byteCode), new SystemHeader());

            //send our encrypted public key
            Connection.SendMessage(new MsgHandshake(encryptedPublicKey), new SystemHeader());

            //and now just wait for the handshake to finish...
            MazeErrorCode errorCode = Connection.HandshakeSync.Wait<MazeErrorCode>(MazeErrorCode.Error, 30000);

            if (errorCode != MazeErrorCode.Finished)
            {
                throw new Exception("Username or Password is incorrect.");
            }

            bool initOk = Connection.InitSync.Wait<bool>(false, 30000);
            if (!initOk)
            {
                throw new Exception("A server time-out occured");
            }
            onBeforeConnect();
            onConnect();
        }

        public void Disconnect()
        {

        }

        public void RegisterOperationalSocket(OperationalSocket opSocket)
        {
            lock (Connection.RegisteredOperationalSockets)
            {
                if (Connection.RegisteredOperationalSockets.ContainsKey(opSocket.GetIdentifier()))
                    throw new Exception("This operational socket is already registered, conflict?");
                Connection.RegisteredOperationalSockets.Add(opSocket.GetIdentifier(), opSocket.GetType());
            }
        }

        internal bool RegisteredOperationalSocket(OperationalSocket opSocket)
        {
            lock (Connection.RegisteredOperationalSockets)
            {
                return Connection.RegisteredOperationalSockets.ContainsKey(opSocket.GetIdentifier());
            }
        }
    }
}
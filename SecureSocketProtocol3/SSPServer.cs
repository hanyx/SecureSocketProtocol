using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Processors;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class SSPServer : IDisposable
    {
        /// <summary> Get a new initialized client that can be used for the server </summary>
        public abstract SSPClient GetNewClient();

        public abstract User.UserDbInfo onFindUser(string EncryptedPublicKeyHash);

        internal object AuthLock = new object();
        internal Socket TcpServer { get; private set; }
        internal Socket TcpServer6 { get; private set; }
        public ServerProperties serverProperties { get; private set; }
        internal SortedList<decimal, SSPClient> Clients { get; private set; }
        internal RandomDecimal randomDecimal { get; private set; }

        private ClientAcceptProcessor ClientAcceptProcessor4;
        private ClientAcceptProcessor ClientAcceptProcessor6;

        private object FindKeyLock = new object();

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

        internal bool serverHS_onFindKeyInDatabase(string EncryptedHash, ref byte[] Key, ref byte[] Salt, ref byte[] PublicKey, ref string Username)
        {
            lock (FindKeyLock)
            {
                try
                {
                    User.UserDbInfo user = onFindUser(EncryptedHash);

                    if (user == null)
                        return false;

                    Key = user.Key.getBytes();
                    Salt = user.PrivateSalt.getBytes();
                    PublicKey = user.PublicKey;
                    Username = user.UsernameStr;
                    return true;
                }
                catch (Exception ex)
                {
                    SysLogger.Log(ex.Message, SysLogType.Error, ex); 
                    return false;
                }
            }
        }

        /// <summary>
        /// Create a new instance of User
        /// </summary>
        /// <param name="Username">The Username for the user</param>
        /// <param name="Password">The Password for the user</param>
        /// <param name="PrivateKeys">The Private Key(s) that are being used to Encrypt the Session</param>
        /// <param name="PublicKey">The Public Key to indentify the user</param>
        public User RegisterUser(string Username, string Password, List<Stream> PrivateKeys, Stream PublicKey)
        {
            User user = new User(Username, Password, PrivateKeys, PublicKey);
            user.GenKey(SessionSide.Server, serverProperties.Handshake_Maze_Size, serverProperties.Handshake_MazeCount, serverProperties.Handshake_StepSize);
            return user;
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
                lock(Clients)
                {
                    if (Clients.ContainsKey(client.ClientId))
                        Clients.Remove(client.ClientId);
                }
            }
        }

        public void Dispose()
        {
            TcpServer.Close();

            if(TcpServer6 != null)
                TcpServer.Close();

            lock (Clients)
            {
                foreach(SSPClient client in Clients.Values)
                {
                    client.Disconnect();
                }
            }
        }
    }
}
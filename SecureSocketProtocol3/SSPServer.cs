using SecureSocketProtocol3.Network;
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
        public ServerProperties serverProperties { get; private set; }
        internal SortedList<decimal, SSPClient> Clients { get; private set; }
        internal RandomDecimal randomDecimal { get; private set; }

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
            this.TcpServer = new Socket(AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
            this.TcpServer.Bind(new IPEndPoint(IPAddress.Parse(serverProperties.ListenIp), serverProperties.ListenPort));
            this.TcpServer.Listen(100);
            this.TcpServer.BeginAccept(AsyncAction, null);
            SysLogger.Log("Started server", SysLogType.Debug);
        }

        private void AsyncAction(IAsyncResult result)
        {
            try
            {
                Socket AcceptSocket = this.TcpServer.EndAccept(result); //<- can throw a error
                SSPClient client = GetNewClient();
                client.Handle = AcceptSocket;
                client.RemoteIp = AcceptSocket.RemoteEndPoint.ToString().Split(':')[0];
                client.Server = this;
                client.Connection = new Network.Connection(client);
                client.Connection.ClientId = randomDecimal.NextDecimal();
                client.serverHS.onFindKeyInDatabase += serverHS_onFindKeyInDatabase;
                client.Certificate = serverProperties.ServerCertificate;

                SysLogger.Log("Accepted peer " + client.RemoteIp, SysLogType.Debug);

                lock (Clients)
                {
                    while (Clients.ContainsKey(client.Connection.ClientId))
                        client.Connection.ClientId = randomDecimal.NextDecimal();
                    Clients.Add(client.Connection.ClientId, client);
                }
                client.Connection.StartReceiver();
            }
            catch(Exception ex)
            {
                SysLogger.Log(ex.Message, SysLogType.Error);
            }
            this.TcpServer.BeginAccept(AsyncAction, null);
        }

        private bool serverHS_onFindKeyInDatabase(string EncryptedHash, ref byte[] Key, ref byte[] Salt, ref byte[] PublicKey, ref string Username)
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
                    SysLogger.Log(ex.Message, SysLogType.Error); 
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
            user.GenKey(SessionSide.Server);
            return user;
        }

        public void Dispose()
        {

        }
    }
}
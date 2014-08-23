using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Misc;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network
{
    /// <summary>
    /// A Operational Socket is a virtual Socket
    /// All the functionality should be written in here
    /// </summary>
    public abstract class OperationalSocket
    {
        public abstract void onReceiveData(byte[] Data, Header header);
        public abstract void onReceiveMessage(IMessage Message, Header header);

        public abstract void onBeforeConnect();
        public abstract void onConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onException(Exception ex, ErrorType errorType);

        public SSPClient Client { get; private set; }
        internal TaskQueue<PayloadInfo> PacketQueue;
        internal int ConnectionId { get; set; }
        internal MessageHandler messageHandler;
        public HeaderList Headers { get; private set; }

        /// <summary>
        /// The name of the Operation Socket, must be unique
        /// </summary>
        public abstract string Name { get; }

        /// <summary>
        /// The version of the Operational Socket
        /// </summary>
        public abstract Version Version { get; }

        public bool isConnected { get; internal set; }

        /// <summary>
        /// Create a new Operational Socket to create a new Virtual Socket
        /// </summary>
        /// <param name="Client">The Client to use</param>
        public OperationalSocket(SSPClient Client)
        {
            this.Client = Client;
            this.PacketQueue = new TaskQueue<PayloadInfo>(onPacketQueue, 50); //Payload x 10 = Memory in use
            this.messageHandler = new MessageHandler(Client.Connection.messageHandler.Seed);
            this.Headers = new HeaderList(Client.Connection);
        }

        /// <summary>
        /// Send data to the other side
        /// </summary>
        /// <param name="Data">The data to send</param>
        /// <param name="Offset">The index of where the data starts</param>
        /// <param name="Length">The length to send</param>
        /// <param name="Header">The header that is being used for this packet</param>
        protected void SendData(byte[] Data, int Offset, int Length, Header Header)
        {
            if (Offset > 0)
            {
                byte[] temp = new byte[Length];
                Array.Copy(Data, Offset, temp, 0, temp.Length);
                Client.Connection.SendMessage(new MsgConnectionData(this, temp, Header), new ConnectionHeader(this.ConnectionId));
            }
            else
            {
                Client.Connection.SendMessage(new MsgConnectionData(this, Data, Header), new ConnectionHeader(this.ConnectionId));
            }
        }

        /// <summary>
        /// Send a message to the other side
        /// </summary>
        /// <param name="Message">The message to send</param>
        /// <param name="Header">The header that is being used for this packet</param>
        protected void SendData(IMessage Message, Header Header)
        {

        }

        private void onPacketQueue(PayloadInfo inf)
        {

        }

        /// <summary>
        /// Establish the virtual connection
        /// </summary>
        public void Connect()
        {
            if (isConnected)
                throw new Exception("Already connected");
            if (!Client.RegisteredOperationalSocket(this))
                throw new Exception("Register the Operational Socket first");

            onBeforeConnect();

            int RequestId = 0;
            SyncObject syncObj = Client.Connection.RegisterRequest(ref RequestId);

            Client.Connection.SendMessage(new MsgCreateConnection(GetIdentifier()), new RequestHeader(RequestId, false));

            MsgCreateConnectionResponse response = syncObj.Wait<MsgCreateConnectionResponse>(null, 100000);
            if (response == null)
                throw new Exception("A server time-out occured");

            if (!response.Success)
                throw new Exception("No success in creating the Operational Socket, too many connections or server-sided error ?");

            if (Client.Connection.OperationalSockets.ContainsKey(response.ConnectionId))
                throw new Exception("Connection Id Conflict detected, An attacker ?");

            Client.Connection.OperationalSockets.Add(response.ConnectionId, this);
            this.ConnectionId = response.ConnectionId;
            this.isConnected = true;
            onConnect();
        }

        /// <summary>
        /// Disconnect the virtual connection
        /// </summary>
        public void Disconnect()
        {

        }

        internal ulong GetIdentifier()
        {
            CRC32 hasher = new CRC32();
            uint name = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Name)), 0);
            uint version = BitConverter.ToUInt32(hasher.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Version.ToString())), 0);
            return name * version;
        }
    }
}
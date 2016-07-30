using SecureSocketProtocol3.Hashers;
using SecureSocketProtocol3.Misc;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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

namespace SecureSocketProtocol3.Network
{
    /// <summary>
    /// A Operational Socket is a virtual Socket
    /// All the functionality should be written in here
    /// </summary>
    public abstract class OperationalSocket : IDisposable
    {
        public abstract void onReceiveMessage(IMessage Message, Header header);

        public abstract void onBeforeConnect();
        public abstract void onConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onException(Exception ex, ErrorType errorType);

        public SSPClient Client { get; private set; }
        internal ushort ConnectionId { get; set; }
        public MessageHandler MessageHandler { get; private set; }
        public HeaderList Headers { get; private set; }
        internal TaskQueue<SystemPacket> PacketQueue { get; private set; }

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
        /// Create a new Operational Socket
        /// </summary>
        /// <param name="Client">The Client to use</param>
        public OperationalSocket(SSPClient Client)
        {
            this.Client = Client;
            this.MessageHandler = new MessageHandler(Client.Connection.messageHandler.Seed, Client.Connection);
            this.Headers = new HeaderList(Client.Connection);
            this.PacketQueue = new TaskQueue<SystemPacket>(PacketQueue_Process, Client.Connection);
        }

        /// <summary>
        /// Send a message to the other side
        /// </summary>
        /// <param name="Message">The message to send</param>
        /// <param name="Header">The header that is being used for this message</param>
        protected int SendMessage(IMessage Message, Header Header)
        {
            if (isConnected && Client.Connection != null)
            {
                return Client.Connection.SendMessage(Message, new ConnectionHeader(Header, this, 0), this);
            }
            return -1;
        }

        internal int InternalSendMessage(IMessage Message, Header Header)
        {
            if (isConnected && Client.Connection != null)
            {
                return Client.Connection.SendMessage(Message, Header);
            }
            return -1;
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
            Client.onOperationalSocket_BeforeConnect(this);

            int RequestId = 0;
            SyncObject syncObj = Client.Connection.RegisterRequest(ref RequestId);

            Client.Connection.SendMessage(new MsgCreateConnection(GetIdentifier()), new RequestHeader(RequestId, false));

            MsgCreateConnectionResponse response = syncObj.Wait<MsgCreateConnectionResponse>(null, 100000);
            if (response == null)
                throw new Exception("A time-out occured");

            if (!response.Success)
                throw new Exception("No success in creating the Operational Socket, too many connections or server-sided error ?");

            lock (Client.Connection.OperationalSockets)
            {
                if (Client.Connection.OperationalSockets.ContainsKey(response.ConnectionId))
                    throw new Exception("Connection Id Conflict detected");

                Client.Connection.OperationalSockets.Add(response.ConnectionId, this);
            }

            this.ConnectionId = response.ConnectionId;
            this.isConnected = true;
            onConnect();
            Client.onOperationalSocket_Connected(this);
        }

        /// <summary>
        /// Disconnect the virtual connection
        /// </summary>
        public void Disconnect()
        {
            if (!isConnected)
                return;

            int RequestId = 0;
            SyncObject syncObj = Client.Connection.RegisterRequest(ref RequestId);

            Client.Connection.SendMessage(new MsgOpDisconnect(this.ConnectionId), new RequestHeader(RequestId, false));

            MsgOpDisconnectResponse response = syncObj.Wait<MsgOpDisconnectResponse>(null, 5000);
            if (response == null)
            {
                throw new Exception("A time-out occured");
            }

            isConnected = false;

            lock (Client.Connection.OperationalSockets)
            {
                if (Client.Connection.OperationalSockets.ContainsKey(ConnectionId))
                {
                    Client.Connection.OperationalSockets.Remove(ConnectionId);
                }
            }

            try
            {
                onDisconnect(DisconnectReason.UserDisconnection);
                Client.onOperationalSocket_Disconnected(this, DisconnectReason.UserDisconnection);
            }
            catch(Exception ex)
            {
                SysLogger.Log(ex.Message, SysLogType.Error, ex);
            }
        }

        internal ulong GetIdentifier()
        {
            CRC32 crc = new CRC32();
            byte[] name = crc.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Name));
            byte[] version = crc.ComputeHash(ASCIIEncoding.ASCII.GetBytes(Version.ToString()));

            byte[] temp = new byte[8];
            Array.Copy(name, 0, temp, 0, 4);
            Array.Copy(version, 0, temp, 4, 4);

            return BitConverter.ToUInt64(temp, 0);
        }

        private void PacketQueue_Process(SystemPacket Packet)
        {
            ConnectionHeader ConHeader = Packet.Header as ConnectionHeader;
            Header header = ConHeader.DeserializeHeader(this);
            if (header == null)
            {
                return;
            }

            onReceiveMessage(Packet.Message, header);
        }

        public void Dispose()
        {
            Disconnect();
        }
    }
}
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
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

namespace SecureSocketProtocol3.Security.Handshakes
{
    public abstract class Handshake
    {
        public SSPClient Client { get; private set; }

        public abstract void onStartHandshake();
        public abstract void onReceiveMessage(IMessage Message);
        public abstract void onFinish();

        public bool IsFinished { get; private set; }

        /// <summary>
        /// Enable Layer Protection
        /// </summary>
        public bool EnableLayer { get; private set; }

        internal SyncObject HandshakeSync { get; set; }

        public Handshake(SSPClient Client)
        {
            this.Client = Client;
            this.HandshakeSync = new SyncObject(Client);
            this.HandshakeSync.Value = false;
        }

        /// <summary>
        /// Send a Handshake message
        /// </summary>
        /// <param name="Message">The message to send</param>
        protected void SendMessage(IMessage Message)
        {
            lock (Client)
            {
                Client.Connection.SendMessage(Message, new SystemHeader());
            }
        }

        /// <summary>
        /// Send a Handshake Message with Header
        /// </summary>
        /// <param name="Message">The message to send</param>
        /// <param name="Header">The Header to send with the message</param>
        protected void SendMessage(IMessage Message, Header Header)
        {
            lock (Client)
            {
                Client.Connection.SendMessage(Message, Header);
            }
        }

        /// <summary>
        /// Let the server/client know we finished the handshake
        /// </summary>
        public void Finish()
        {
            InternalFinish(true);
        }

        internal void InternalFinish(bool SendFinish)
        {
            lock (Client)
            {
                if (!IsFinished)
                {
                    IsFinished = true;

                    if (SendFinish)
                    {
                        Client.Connection.SendMessage(new MsgHandshakeFinish(), new SystemHeader());
                    }

                    HandshakeSync.Value = true;
                    HandshakeSync.Pulse();

                    if (Client.handshakeSystem.CompletedAllHandshakes)
                    {
                        try
                        {
                            if (Client.IsServerSided)
                            {
                                Client.onConnect();
                            }
                        }
                        catch (Exception ex)
                        {
                            SysLogger.Log(ex.Message, SysLogType.Error, ex);
                        }
                    }
                }
            }
        }
    }
}
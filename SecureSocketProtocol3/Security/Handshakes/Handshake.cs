using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
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
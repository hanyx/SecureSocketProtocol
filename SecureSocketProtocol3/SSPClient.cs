using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Network.Messages;
using SecureSocketProtocol3.Network.Messages.TCP;
using SecureSocketProtocol3.Security.Configurations;
using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Security.Layers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Net;
using System.Net.Sockets;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

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
    public abstract class SSPClient : IDisposable
    {
        public abstract void onBeforeConnect();
        public abstract void onConnect();
        public abstract void onDisconnect(DisconnectReason Reason);
        public abstract void onException(Exception ex, ErrorType errorType);
        public abstract void onApplyLayers(LayerSystem layerSystem);
        public abstract void onApplyHandshakes(HandshakeSystem handshakeSystem);

        public abstract void onOperationalSocket_BeforeConnect(OperationalSocket OPSocket);
        public abstract void onOperationalSocket_Connected(OperationalSocket OPSocket);
        public abstract void onOperationalSocket_Disconnected(OperationalSocket OPSocket, DisconnectReason Reason);

        public abstract IDataIntegrityLayer DataIntegrityLayer { get; }

        public Connection Connection { get; internal set; }
        public string RemoteIp { get; internal set; }

        internal RandomDecimal randomDecimal { get; private set; }

        public decimal ClientId
        {
            get;
            internal set;
        }

        public bool Connected
        {
            get
            {
                if (Connection == null)
                    return false;
                return Connection.Connected;
            }
        }

        public ClientProperties Properties { get; private set; }
        internal Socket Handle { get; set; }
        internal SSPServer Server;

        private object Locky = new object();
        internal bool IsServerSided { get { return Server != null; } }

        private Stopwatch _connectionTime;

        /// <summary>
        /// Get the time how long a client is connected for
        /// </summary>
        public TimeSpan ConnectionTime { get { return _connectionTime.Elapsed; } }

        /// <summary>
        /// The name of the logged in person
        /// </summary>
        public string Username { get; set; }

        public TimingConfig TimingConfiguration { get; private set; }

        private System.Timers.Timer KeepAliveTimer;
        private SecureRandom KeepAliveRandom = new SecureRandom();

        public bool IsDisposed { get; private set; }
        internal LayerSystem layerSystem { get; private set; }
        internal HandshakeSystem handshakeSystem { get; private set; }

        private ClientPrecomputes _preComputes;
        internal ClientPrecomputes PreComputes
        {
            get
            {
                if (IsServerSided)
                    return Server.PreComputes;
                return _preComputes;
            }
            private set
            {
                _preComputes = value;
            }
        }

        public MessageHandler MessageHandler
        {
            get
            {
                if (Connection != null)
                    return Connection.messageHandler;
                return null;
            }
        }

        public SSPClient()
        {
            _connectionTime = Stopwatch.StartNew();
            this.TimingConfiguration = new TimingConfig();
            this.layerSystem = new LayerSystem(this);
            this.handshakeSystem = new HandshakeSystem();
            this.randomDecimal = new RandomDecimal();
            this.PreComputes = new ClientPrecomputes();
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
            bool IsIPv6 = false;

            for (int i = 0; i < resolved.Length; i++)
            {
                if (resolved[i].AddressFamily == AddressFamily.InterNetwork ||
                    resolved[i].AddressFamily == AddressFamily.InterNetworkV6)
                {
                    IsIPv6 = resolved[i].AddressFamily == AddressFamily.InterNetworkV6;
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
                this.Handle = new Socket(IsIPv6 ? AddressFamily.InterNetworkV6 : AddressFamily.InterNetwork, SocketType.Stream, ProtocolType.Tcp);
                IAsyncResult result = this.Handle.BeginConnect(new IPEndPoint(resolved[0], Properties.Port), (IAsyncResult ar) =>
                {
                    try
                    {
                        this.Handle.EndConnect(ar);
                    }
                    catch (Exception ex)
                    {
                        /* Will throw a error if connection couldn't be made */
                        SysLogger.Log(ex.Message, SysLogType.Error, ex);
                    }
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
                {
                    this.Handle.Close();

                    //A Firewall blocked the connection ?
                    if (ConTimeout > 0 && sw.ElapsedMilliseconds <= 10)
                    {
                        Thread.Sleep(1000);
                        ConTimeout -= 1000;
                    }
                }

            } while (ConTimeout > 0 && !this.Handle.Connected);

            if (!Handle.Connected)
                throw new Exception("Unable to establish a connection with " + Properties.HostIp + ":" + Properties.Port);

            PreComputes.SetPreNetworkKey(this);
            PreComputes.ComputeNetworkKey(this);

            Connection = new Connection(this);

            onApplyLayers(layerSystem);
            onApplyHandshakes(handshakeSystem);

            Connection.StartReceiver();

            onBeforeConnect();

            StartKeepAliveTimer();

            while (!handshakeSystem.CompletedAllHandshakes)
            {
                Handshake curHandshake = handshakeSystem.GetCurrentHandshake();

                if (curHandshake != null)
                {
                    curHandshake.CallStartHandshake();

                    curHandshake.FinishedInitialization = true;

                    if (!curHandshake.HandshakeSync.Wait<bool>(false, 30000))
                    {
                        //handshake failed or took too long
                        Disconnect();
                        throw new Exception("Handshake \"" + curHandshake.GetType().Name + "\" failed");
                    }
                }
            }

            onConnect();
        }

        internal void StartKeepAliveTimer()
        {
            if (this.KeepAliveTimer != null)
                this.KeepAliveTimer.Stop();

            this.KeepAliveTimer = new System.Timers.Timer();
            this.KeepAliveTimer.Interval = 5000;
            this.KeepAliveTimer.Elapsed += KeepAliveTimer_Elapsed;
            this.KeepAliveTimer.Enabled = true;
        }

        void KeepAliveTimer_Elapsed(object sender, System.Timers.ElapsedEventArgs e)
        {
            try
            {
                if (!Connected)
                {
                    return;
                }

                if (Connection.LastPacketSendElapsed.TotalSeconds > 5)
                {
                    //Make the Keep-Alive go a bit random to confuse time attacks with real traffic
                    this.KeepAliveTimer.Interval = KeepAliveRandom.Next(2000, 8000);
                    Connection.SendMessage(new MsgKeepAlive(), new SystemHeader());
                }

                if (Connection.LastPacketReceivedElapsed.TotalSeconds >= 30)
                {
                    //hardware disconnection
                    Disconnect();
                }

                if (IsServerSided && !handshakeSystem.CompletedAllHandshakes)
                {
                    Handshake curHandshake = handshakeSystem.GetCurrentHandshake();
                    if (curHandshake.TimeTaken != null && curHandshake.TimeTaken.Elapsed.TotalSeconds > 30)
                    {
                        Disconnect();
                    }
                }

            }
            catch (Exception ex)
            {
                SysLogger.Log(ex.Message, SysLogType.Error, ex);
            }
        }

        public void Disconnect()
        {
            Dispose();
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

        public long GetNextRandomLong()
        {
            decimal number = GetNextRandomDecimal();
            number %= long.MaxValue;
            return (int)number;
        }

        public int GetNextRandomInteger()
        {
            decimal number = GetNextRandomDecimal();
            number %= int.MaxValue;
            return (int)number;
        }

        public decimal GetNextRandomDecimal()
        {
            lock (Connection.NextRandomIdLock)
            {
                return randomDecimal.NextDecimal();
            }
        }

        public void Dispose()
        {
            try
            {
                Handle.Shutdown(SocketShutdown.Both);
                Handle.Close();
            }
            catch (Exception ex)
            {
                SysLogger.Log(ex.Message, SysLogType.Error, ex);
            }

            if (IsServerSided)
            {
                Server.RemoveClient(this);
            }

            this.Connection = null;
            this.Properties = null;
            this.Handle = null;
            this.Server = null;

            if (this.KeepAliveTimer != null)
                this.KeepAliveTimer.Enabled = false;

            this.IsDisposed = true;

            try
            {
                onDisconnect(DisconnectReason.UserDisconnection);
            }
            catch (Exception ex)
            {
                SysLogger.Log(ex.Message, SysLogType.Error, ex);
            }
        }
    }
}
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
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
        private FastRandom KeepAliveRandom = new FastRandom();

        public bool IsDisposed { get; private set; }
        internal LayerSystem layerSystem { get; private set; }
        internal HandshakeSystem handshakeSystem { get; private set; }

        public SSPClient()
        {
            _connectionTime = Stopwatch.StartNew();
            this.TimingConfiguration = new TimingConfig();
            this.layerSystem = new LayerSystem();
            this.handshakeSystem = new HandshakeSystem();
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
                    this.Handle.Close();

            } while (ConTimeout > 0 && !this.Handle.Connected);

            if (!Handle.Connected)
                throw new Exception("Unable to establish a connection with " + Properties.HostIp + ":" + Properties.Port);

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
                    curHandshake.onStartHandshake();
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
            if (!Connected)
                return;

            try
            {
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

        /// <summary>
        /// This will request a random id from the server to use, a better way of getting a random number
        /// </summary>
        /// <returns>A random decimal number</returns>
        public long GetNextRandomLong()
        {
            decimal number = GetNextRandomDecimal();
            number %= long.MaxValue;
            return (int)number;
        }

        /// <summary>
        /// This will request a random id from the server to use, a better way of getting a random number
        /// </summary>
        /// <returns>A random decimal number</returns>
        public int GetNextRandomInteger()
        {
            decimal number = GetNextRandomDecimal();
            number %= int.MaxValue;
            return (int)number;
        }

        /// <summary>
        /// This will request a random id from the server to use, a better way of getting a random number
        /// </summary>
        /// <returns>A random decimal number</returns>
        public decimal GetNextRandomDecimal()
        {
            lock (Connection.NextRandomIdLock)
            {
                if (IsServerSided)
                {
                    return Server.randomDecimal.NextDecimal();
                }

                int ReqId = 0;
                SyncObject SyncNextRandomId = Connection.RegisterRequest(ref ReqId);

                Connection.SendMessage(new MsgGetNextId(), new RequestHeader(ReqId, false));

                decimal? response = SyncNextRandomId.Wait<decimal?>(null, 30000);

                if (!response.HasValue)
                    throw new Exception("A time out occured");

                return response.Value;
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
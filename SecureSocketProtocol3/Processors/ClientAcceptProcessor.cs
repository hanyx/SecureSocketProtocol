using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Security.Handshakes;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
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

namespace SecureSocketProtocol3.Processors
{
    internal class ClientAcceptProcessor
    {
        public ClientAcceptProcessor()
        {

        }

        public SSPClient ProcessClient(SSPServer Server, Socket TcpServer, IAsyncResult result)
        {
            try
            {
                Socket AcceptSocket = TcpServer.EndAccept(result); //<- can throw a error
                SSPClient client = Server.GetNewClient();
                client.Handle = AcceptSocket;

                if (AcceptSocket.AddressFamily == AddressFamily.InterNetworkV6)
                    client.RemoteIp = ((IPEndPoint)AcceptSocket.RemoteEndPoint).Address.ToString();
                else
                    client.RemoteIp = AcceptSocket.RemoteEndPoint.ToString().Split(':')[0];

                client.Server = Server;
                client.Connection = new Network.Connection(client);
                client.ClientId = Server.randomDecimal.NextDecimal();

                SysLogger.Log("Accepted peer " + client.RemoteIp, SysLogType.Debug);

                lock (Server.Clients)
                {
                    while (Server.Clients.ContainsKey(client.ClientId))
                        client.ClientId = Server.randomDecimal.NextDecimal();
                    Server.Clients.Add(client.ClientId, client);
                }

                client.onApplyLayers(client.layerSystem);
                client.onApplyHandshakes(client.handshakeSystem);

                try
                {
                    client.onBeforeConnect();
                }
                catch (Exception ex)
                {
                    SysLogger.Log(ex.Message, SysLogType.Error, ex);
                    client.onException(ex, ErrorType.UserLand);
                }

                Handshake CurHandshake = client.handshakeSystem.GetCurrentHandshake();

                if (CurHandshake != null)
                {
                    try
                    {
                        CurHandshake.onStartHandshake();
                    }
                    catch (Exception ex)
                    {
                        SysLogger.Log(ex.Message, SysLogType.Error, ex);
                        client.Disconnect();
                        return null;
                    }
                }

                client.StartKeepAliveTimer();

                client.Connection.StartReceiver();
                return client;
            }
            catch (Exception ex)
            {
                SysLogger.Log(ex.Message, SysLogType.Error, ex);
                return null;
            }
        }
    }
}
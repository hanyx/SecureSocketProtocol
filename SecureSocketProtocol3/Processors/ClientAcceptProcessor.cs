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

                Server.PreComputes.SetPreNetworkKey(client);
                Server.PreComputes.ComputeNetworkKey(client);

                client.Connection = new Network.Connection(client);
                client.ClientId = client.randomDecimal.NextDecimal();

                SysLogger.Log("Accepted peer " + client.RemoteIp, SysLogType.Debug);

                lock (Server.Clients)
                {
                    while (Server.Clients.ContainsKey(client.ClientId))
                        client.ClientId = client.randomDecimal.NextDecimal();
                    Server.Clients.Add(client.ClientId, client);
                }

                client.onApplyLayers(client.layerSystem);
                client.onApplyHandshakes(client.handshakeSystem);
                client.handshakeSystem.RegisterMessages(client.MessageHandler);

                try
                {
                    client.onBeforeConnect();
                }
                catch (Exception ex)
                {
                    SysLogger.Log(ex.Message, SysLogType.Error, ex);
                    client.onException(ex, ErrorType.UserLand);
                }

                client.StartKeepAliveTimer();
                client.Connection.StartReceiver();


                //there are no handshakes
                if (client.handshakeSystem.CompletedAllHandshakes)
                {
                    client.Connection.CreateNewThread(new System.Threading.ThreadStart(() =>
                    {
                        try
                        {
                            client.onConnect();
                        }
                        catch (Exception exx)
                        {
                            SysLogger.Log(exx.Message, SysLogType.Error, exx);
                        }
                    })).Start();
                }

                if (!client.handshakeSystem.CompletedAllHandshakes)
                {
                    Handshake curHandshake = client.handshakeSystem.GetCurrentHandshake();
                    curHandshake.CallStartHandshake();
                    curHandshake.FinishedInitialization = true;
                }

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
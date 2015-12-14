using SecureSocketProtocol3.Network.MazingHandshake;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Net;
using System.Net.Sockets;
using System.Text;

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

                client.serverHS = new ServerMaze(Server.serverProperties.Handshake_Maze_Size, Server.serverProperties.Handshake_MazeCount, Server.serverProperties.Handshake_StepSize);
                client.serverHS.onFindKeyInDatabase += Server.serverHS_onFindKeyInDatabase;

                SysLogger.Log("Accepted peer " + client.RemoteIp, SysLogType.Debug);

                lock (Server.Clients)
                {
                    while (Server.Clients.ContainsKey(client.ClientId))
                        client.ClientId = Server.randomDecimal.NextDecimal();
                    Server.Clients.Add(client.ClientId, client);
                }

                client.onApplyLayers(client.layerSystem);
                client.StartKeepAliveTimer();

                try
                {
                    client.onBeforeConnect();
                }
                catch (Exception ex)
                {
                    SysLogger.Log(ex.Message, SysLogType.Error, ex);
                    client.onException(ex, ErrorType.UserLand);
                }

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
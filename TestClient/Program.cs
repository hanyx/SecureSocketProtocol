using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.IO;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.Encryptions;
using System.Threading;
using SecureSocketProtocol3.Utils;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.MazingHandshake;
using TestClient.Sockets;
using SecureSocketProtocol3.Security.Layers;
using SecureSocketProtocol3.Security.DataIntegrity;
using ExtraLayers.LZMA;
using ExtraLayers.LZ4;
using SecureSocketProtocol3.Security.Handshakes;

namespace TestClient
{
    class Program
    {
        static List<ClientStatus> ConnectionCount = new List<ClientStatus>();

        static void Main(string[] args)
        {
            //SysLogger.onSysLog += SysLogger_onSysLog;
            Console.Title = "SSP Client";

            for (int i = 0; i < 50; i++)
            {
                ClientStatus status = new ClientStatus(i);
                ConnectionCount.Add(status);
                new Thread(new ParameterizedThreadStart(ClientThread)).Start(status);
            }

            /*while (true)
            {
                Console.Clear();
                foreach(ClientStatus status in ConnectionCount)
                {
                    Console.WriteLine(String.Format("[{0}][{1}] Connection Count: {2}, Status: {3}", status.Id, status.TimeToConnect.Elapsed, status.ConnectionCount, status.Status));
                }

                Thread.Sleep(250);
            }*/

            Process.GetCurrentProcess().WaitForExit();
        }

        static void SysLogger_onSysLog(string Message, SysLogType Type)
        {
            Console.WriteLine("[SysLogger][" + Type + "] " + Message);
        }

        static void ClientThread(object o)
        {
            ClientStatus status = (ClientStatus)o;
            
            //while (true)
            {
                status.Status = "Connecting...";
                status.TimeToConnect.Reset();
                status.TimeToConnect.Start();

                Client client = new Client();

                status.TimeToConnect.Stop();

                status.ConnectionCount++;
                status.Status = "Connected";
            }
        }

        class ClientStatus
        {
            public int Id { get; private set; }
            public string Status { get; set; }
            public int ConnectionCount { get; set; }
            public Stopwatch TimeToConnect { get; set; }

            public ClientStatus(int Id)
            {
                this.Id = Id;
                this.TimeToConnect = new Stopwatch();
            }
        }
    }
}
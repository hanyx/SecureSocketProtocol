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

            for (int i = 0; i < 1; i++)
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
            ClientProps props = new ClientProps();

            while (true)
            {
                status.Status = "Connecting...";
                status.TimeToConnect.Reset();
                status.TimeToConnect.Start();

                using (Client client = new Client(props))
                {
                    /**/byte[] test = new byte[65535];
                    using (TestSocket sock = new TestSocket(client))
                    {
                        sock.Connect();
                        for (int i = 0; i < 999999999; i++)
                        {
                            sock.Send_Protobuf_Message(test);
                        }
                    }

                    status.TimeToConnect.Stop();

                    status.ConnectionCount++;
                    status.Status = "Connected";
                    //Thread.Sleep(5000);
                }
            }
            Console.WriteLine("Thread closed");
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
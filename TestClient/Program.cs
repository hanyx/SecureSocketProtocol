using SecureSocketProtocol3;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Text;
using System.IO;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Encryptions;
using System.Threading;
using SecureSocketProtocol3.Utils;

namespace TestClient
{
    class Program
    {
        static void Main(string[] args)
        {
            Client client = new Client();
            Random random = new Random();


            byte[] temp = new byte[6000];
            
            Stopwatch sw = Stopwatch.StartNew();
            Stopwatch RuntimeSW = Stopwatch.StartNew();

            int count = 0;
            while (true)
            {
                temp = new byte[random.Next(60000)];
                client.connection.Send(temp, 0, temp.Length);
                //Console.WriteLine(count++);

                if (sw.ElapsedMilliseconds >= 1000)
                {
                    Console.Title = "Runtime: " + RuntimeSW.Elapsed;
                    sw = Stopwatch.StartNew();
                }
            }
            Process.GetCurrentProcess().WaitForExit();
        }
    }

    public class Client : SSPClient
    {
        public Client()
            : base(new ClientProperties("127.0.0.1", 444))
        {

        }

        public override void onClientConnect()
        {

        }

        public override void onDisconnect(DisconnectReason Reason)
        {

        }
    }
}
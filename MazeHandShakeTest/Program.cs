using SecureSocketProtocol3.Encryptions;
using SecureSocketProtocol3.Network.MazingHandshake;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace MazeHandShakeTest
{
    class Program
    {
        static void Main(string[] args)
        {
            byte[] CryptCode = new byte[0];
            byte[] DecryptCode = new byte[0];
            WopEx.GenerateCryptoCode(67234823, 100, ref CryptCode, ref DecryptCode);


            ClientMaze client = new ClientMaze();
            ServerMaze server = new ServerMaze();

            //1. Send server the bytecode
            byte[] byteCode = client.GetByteCode();
            Console.WriteLine("[Client] Sending ByteCode to server");


            //2. Server receives the ByteCode
            if (server.onReceiveData(byteCode))
            {
                Console.WriteLine("[Server] ByteCode is correct, continue on with handshake");
            }
            else
            {
                Console.WriteLine("[Server] ByteCode is not correct, disconnecting...");
            }

            List<byte[]> PrivateKeys = new List<byte[]>();
            foreach (string file in Directory.GetFiles(@"F:\", "*.dll"))
            {
                PrivateKeys.Add(File.ReadAllBytes(file));
            }

            client.SetLoginData("UserTest", "UserPasS", PrivateKeys, null);
            client.GetMazeKey();

            Process.GetCurrentProcess().WaitForExit();
        }
    }
}
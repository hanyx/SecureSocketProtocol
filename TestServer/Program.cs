using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;

namespace TestServer
{
    class Program
    {
        public static SortedList<string, User.UserDbInfo> Users;

        static void Main(string[] args)
        {
            Console.Title = "SSP Server";
            Users = new SortedList<string, User.UserDbInfo>();



            Server server = new Server();

            Process.GetCurrentProcess().WaitForExit();
        }
    }
}

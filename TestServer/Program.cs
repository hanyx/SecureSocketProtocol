using SecureSocketProtocol3;
using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Threading;

namespace TestServer
{
    class Program
    {
        public static SortedList<string, User.UserDbInfo> Users;

        static void Main(string[] args)
        {
            //SysLogger.onSysLog += SysLogger_onSysLog;
            Console.Title = "SSP Server";
            Users = new SortedList<string, User.UserDbInfo>();

            Server server = new Server();

            while(true)
            {
                Console.Title = "SSP Server - Connected Clients: " + server.GetClients().Length;
                Thread.Sleep(250);
            }

            Process.GetCurrentProcess().WaitForExit();
        }

        private static void SysLogger_onSysLog(string Message, SysLogType Type, Exception ex)
        {
            Console.ForegroundColor = ConsoleColor.Cyan;
            Console.WriteLine("[SysLogger][" + Type + "] " + Message);
            Console.ForegroundColor = ConsoleColor.Gray;
        }
    }
}

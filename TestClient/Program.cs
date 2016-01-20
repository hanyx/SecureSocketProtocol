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
        static void Main(string[] args)
        {
            //SysLogger.onSysLog += SysLogger_onSysLog;
            Console.Title = "SSP Client";
            Client client = new Client();

            Process.GetCurrentProcess().WaitForExit();
        }

        static void SysLogger_onSysLog(string Message, SysLogType Type)
        {
            Console.WriteLine("[SysLogger][" + Type + "] " + Message);
        }
    }
}
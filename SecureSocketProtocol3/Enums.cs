using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3
{
    //action with more arguments
    public delegate void Action<in T1, in T2>(T1 arg1, T2 arg2);
    public delegate void Action<in T1, in T2, in T3>(T1 arg1, T2 arg2, T3 arg3);
    public delegate void Action<in T1, in T2, in T3, in T4>(T1 arg1, T2 arg2, T3 arg3, T4 arg4);
    public delegate void Action<in T1, in T2, in T3, in T4, in T5>(T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5);
    public delegate void Action<in T1, in T2, in T3, in T4, in T5, in T6>(T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6);
    public delegate void Action<in T1, in T2, in T3, in T4, in T5, in T6, in T7>(T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7);
    public delegate void Action<in T1, in T2, in T3, in T4, in T5, in T6, in T7, in T8>(T1 arg1, T2 arg2, T3 arg3, T4 arg4, T5 arg5, T6 arg6, T7 arg7, T8 arg8);
    public delegate T Callback<T>(T arg1);

    public delegate SSPClient[] GetClientsDelegate();
    internal delegate bool AuthenticationDelegate(SSPClient client, string Username, string Password);
    public delegate void ReceiveDataCallback(byte[] Payload, Header header);

    public enum DisconnectReason
    {
        UnexpectedlyDisconnected = 0,
        DeepPacketInspectionDisconnection = 1,
        DataModificationDetected = 2,
        UserDisconnection = 3,
        StrangeBehaviorDetected = 4,
        CertificatePastValidTime = 5,
        TimeOut = 6,
        HandShakeFailed = 7,
        HardwareDisconnection = 8,
        ServerShuttingDown = 9,
    }

    public enum ConnectionState
    {
        Open,
        Closed,
        Reconnecting,
    }

    public enum ReceiveType
    {
        Header,
        Payload
    }

    public enum ErrorType
    {
        /// <summary> When this occurs it's a error from the user and not from SSP </summary>
        UserLand,
        /// <summary> This is a SSP error which should get fixed </summary>
        Core
    }

    public enum ChecksumHash
    {
        None = 0,
        CRC32 = 1,
        MD5 = 2,
        SHA512 = 4,
        SHA1 = 8
    }

    public enum SessionSide
    {
        Server,
        Client
    }

    internal enum PayloadType
    {
        Data = 1,
        Message = 2,
    }
}

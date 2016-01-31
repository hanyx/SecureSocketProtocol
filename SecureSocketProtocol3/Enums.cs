using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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

    public delegate void SysLogDeletegate(string Message, SysLogType Type, Exception ex);

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

    public enum WopEncMode
    {
        /// <summary>
        /// The order for encrypting/decrypting does not matter and it will decrease the security of the Initial Vector Key (Highly Decreases security)
        /// </summary>
        Simple = 0,
        /// <summary>
        /// Shuffle the algorithm after calling the Encrypt method
        /// This is a quick way of making the next data "Unique"
        /// </summary>
        ShuffleInstructions = 1,
        /// <summary>
        /// Generate a new unique algorithm to use after the Encrypt method has been called
        /// This will make the data completely unique but thus will take longer to encrypt a lot of data
        /// </summary>
        GenerateNewAlgorithm = 2
    }

    public enum SysLogType
    {
        None = 0,
        Debug = 1,
        Network = 2,
        HandShake = 3,
        PacketAnalyzes = 4,
        Error = 5,
        Everything = 6,
    }

    public enum EncAlgorithm
    {
        /// <summary>
        /// Hardware Accelerated AES by using the AesCryptoServiceProvider (performance only gained if CPU supports it)
        /// </summary>
        HwAES = 1,
        /// <summary>
        /// WopEx is a custom made encryption algorithm designed to be secure
        /// </summary>
        WopEx = 2
    }

    public enum CompressionAlgorithm
    {
        /// <summary>
        /// Use no compression algorithm
        /// </summary>
        None = 0,
        QuickLZ = 1,
        Gzip = 2
    }

    public enum TimingVar
    {
        /// <summary>
        /// The time will use a fixed amount of time
        /// </summary>
        Fixed,
        Variable
    }

    public enum LayerType
    {
        Encryption,
        Compression
    }
}

﻿using SecureSocketProtocol2.Network;
using SecureSocketProtocol2.Network.Messages;
using System;
using System.Collections.Generic;
using System.Runtime.InteropServices;
using System.Text;

namespace SecureSocketProtocol2
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
    
    public delegate void PluginHeaderCallback(ref byte[] Header);
    public delegate void RequestCallback(object state);
    public delegate bool ReceiveCallback(IMessage message);
    public delegate SyncObject ReceiveDeletegate(ReceiveCallback message);
    public delegate SSPClient[] GetClientsDelegate();

    public enum SocksVersion
    {
        Socks5
    }

    public enum PacketOption
    {
        Compression = 1,
        Cache = 2,
        Plugin = 4,
    }

    public enum Protocol
    {
        TCP = 1,
        UDP = 2
    }

    public enum Instruction
    {
        /// <summary>
        /// Copy from the Cache to array  
        /// MEMCPY(1) + SIZE(4) + CacheOffset(4)
        /// </summary>
        MEMCPY,
        /// <summary>
        /// Jump to the end of the data (1)
        /// </summary>
        EJUMP,
        /// <summary>
        /// Copy all data after this instruction to cache
        /// </summary>
        MEMCPYEX,
        /// <summary>
        /// Copy new data(3)  
        /// NEWDATA(1) + SIZE(2)
        /// </summary>
        NEWDATA
    }

    public enum CacheMode
    {
        /// <summary>
        /// This mode will check if your input data and cache at every byte to see at which static position is different
        /// </summary>
        SimpleByteScan,
        /// <summary>
        /// This mode will go through your input data quick and hash the ChunkSize you gave, this could be fast but less accurate this will look for any position in the cache
        /// </summary>
        RandomPosition,
        /// <summary>
        /// This mode will rapidly go through your input data
        /// </summary>
        QuickByteScan,
    }

    public enum PacketId
    {
        Unknown = 0,
        Payload = 1,
        PacketQueue = 2,
        KeepAlive = 3,
        ChannelPayload = 4,
        OpenChannel = 5,
        OpenChannelResponse = 6,
        CloseChannel = 7,
        Disconnected = 8,
        PluginPacket = 9,
        Reconnection = 10,
    }

    public enum UdpPAcketId
    {
        Unknown = 0,
        Payload = 1,
        Handshake = 2,
    }

    public enum ReceiveType
    {
        Header,
        Payload
    }

    public enum ConnectionState
    {
        Open,
        Closed,
        Reconnecting,
    }

    public enum ChannelError
    {
        Success,
        Timeout,
        InitializeError,
        ChannelClosed,
        Unsuccessful,
    }

    public enum SSPError
    {
        ErrorSuccess,
        ClientDisconnected,
    }

    public enum ReceivePerformance
    {
        Safe, Unsafe
    }

    public enum MessageCacheType
    {
        Byte = 0,
        Integer = 1,
        UInteger = 2,
        Short = 3,
        UShort = 4,
        ULong = 5,
        Bool = 6,
        Double = 7,
        Long = 8,
        Float = 9,
        Decimal = 10,
        String = 11,
        NULL = 12,
        NotUpdated = 13,
        OtherObject = 14,
        ByteArray = 15,
    }

    public enum ProtectionType
    {
        Cache,
        Compression,
        Encryption,
        Masker,
    }

    public enum ChecksumHash
    {
        None, CRC32, MurMur, MD5
    }
}
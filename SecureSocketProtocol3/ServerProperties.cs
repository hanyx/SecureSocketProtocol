using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class ServerProperties
    {
        /// <summary> The port to listen at </summary>
        public abstract ushort ListenPort { get; }

        /// <summary> The local ip used to listen at, default: 0.0.0.0 </summary>
        public abstract string ListenIp { get; }

        /// <summary> If keyfiles are being used it will make it harder to decrypt the traffic </summary>
        public abstract Stream[] KeyFiles { get; }

        /// <summary>  </summary>
        public abstract uint Cipher_Rounds { get; }

        public abstract EncAlgorithm EncryptionAlgorithm { get; }
        public abstract CompressionAlgorithm CompressionAlgorithm { get; }

        /// <summary> The maximum amount of time a client can be connected for, if the time ran out the client will get kicked </summary>
        public abstract TimeSpan ClientTimeConnected { get; }

        public abstract Size Handshake_Maze_Size { get; }
        public abstract ushort Handshake_StepSize { get; }
        public abstract ushort Handshake_MazeCount { get; }

        public abstract byte[] NetworkKey { get; }
    }
}
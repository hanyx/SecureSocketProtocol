using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;

namespace SecureSocketProtocol3
{
    public abstract class ClientProperties
    {
        public abstract string HostIp { get; }
        public abstract ushort Port { get;  }
        public abstract int ConnectionTimeout { get; }

        public abstract string Username { get; }
        public abstract string Password { get; }

        public abstract Stream[] PrivateKeyFiles { get; }
        public abstract Stream PublicKeyFile { get; }

        public abstract byte[] NetworkKey { get; }

        public abstract uint Cipher_Rounds { get; }

        public abstract EncAlgorithm EncryptionAlgorithm { get; }
        public abstract CompressionAlgorithm CompressionAlgorithm { get; }

        public abstract Size Handshake_Maze_Size { get; }
        public abstract ushort Handshake_StepSize { get; }
        public abstract ushort Handshake_MazeCount { get; }

        public ClientProperties()
        {

        }


    }
}
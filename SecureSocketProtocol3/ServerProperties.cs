using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
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

        /// <summary> This certificate will help the users know they're connected over a secure connection and not being attacked by man-in-the-middle </summary>
        public abstract CertificateInfo ServerCertificate { get; }

        /// <summary> When enabled the user needs to authenicate itself with a username and password </summary>
        public abstract bool UserPassAuthenication { get; }

        /// <summary> If keyfiles are being used it will make it harder to decrypt the traffic </summary>
        public abstract Stream[] KeyFiles { get; }

        /// <summary>  </summary>
        public abstract uint Cipher_Rounds { get; }

        public abstract EncAlgorithm EncryptionAlgorithm { get; }
        public abstract CompressionAlgorithm CompressionAlgorithm { get; }
    }
}
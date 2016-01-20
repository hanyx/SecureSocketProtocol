using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Security.DataIntegrity;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
using System.Text;

/*
    Secure Socket Protocol
    Copyright (C) 2016 AnguisCaptor

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

namespace SecureSocketProtocol3
{
    public abstract class ServerProperties
    {
        /// <summary> The port to listen at </summary>
        public abstract ushort ListenPort { get; }

        /// <summary> The local ip used to listen at, default: 0.0.0.0 </summary>
        public abstract string ListenIp { get; }

        /// <summary> The local ip used to listen at for IPv6, default: ::1 </summary>
        public abstract string ListenIp6 { get; }

        /// <summary> Use IPv4 + IPv6 at the same time, if 'False' only IPV4 will be ran </summary>
        public abstract bool UseIPv4AndIPv6 { get; }

        /// <summary> If keyfiles are being used it will make it harder to decrypt the traffic </summary>
        public abstract Stream[] KeyFiles { get; }

        /// <summary> The maximum amount of time a client can be connected for, if the time ran out the client will get kicked </summary>
        public abstract TimeSpan ClientTimeConnected { get; }

        public abstract byte[] NetworkKey { get; }
    }
}
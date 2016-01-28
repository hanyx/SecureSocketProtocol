using ProtoBuf;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Security.Serialization;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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

namespace SecureSocketProtocol3.Network.Messages
{
    [SerializableAttribute]
    public abstract class IMessage
    {
        /// <summary> This is the message in raw size we received </summary>
        public int RawSize { get; set; }

        /// <summary> This is the message in raw size after decompression </summary>
        public int DecompressedRawSize { get; set; }

        public Header Header { get; internal set; }

        public IMessage()
        {

        }

        public abstract void ProcessPayload(SSPClient client, OperationalSocket OpSocket);

        public virtual ISerialization onGetSerializer()
        {
            return null;
        }
    }
}

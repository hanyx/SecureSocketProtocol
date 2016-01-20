using SecureSocketProtocol3.Network;
using SecureSocketProtocol3.Network.Headers;
using SecureSocketProtocol3.Network.Messages;
using System;
using System.Collections.Generic;
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

namespace SecureSocketProtocol3.Misc
{
    internal class SystemPacket
    {
        public Header Header { get; private set; }
        public IMessage Message { get; private set; }
        public ushort ConnectionId { get; private set; }
        public OperationalSocket OpSocket { get; private set; }

        public SystemPacket(Header header, IMessage message, ushort ConnectionId, OperationalSocket OpSocket)
        {
            this.Header = header;
            this.Message = message;
            this.ConnectionId = ConnectionId;
            this.OpSocket = OpSocket;
        }
    }
}
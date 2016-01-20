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

namespace SecureSocketProtocol3.Network.Headers
{
    public class HeaderList
    {
        private SortedList<ushort, Type> Headers;
        private Connection connection;

        public HeaderList(Connection connection)
        {
            this.Headers = new SortedList<ushort, Type>();
            this.connection = connection;
        }

        public void RegisterHeader(Type HeaderType)
        {
            Header header = (Header)Activator.CreateInstance(HeaderType);
            ushort headerId = (ushort)(connection.PrivateSeed + header.GetHeaderId());

            if (Headers.ContainsKey(headerId))
                throw new Exception("Header already exists, Header Conflict!");

            Headers.Add(headerId, HeaderType);
        }

        public Type GetHeaderType(ushort HeaderId)
        {
            Type type = null;
            Headers.TryGetValue(HeaderId, out type);
            return type;
        }

        public ushort GetHeaderId(Header header)
        {
            return (ushort)(connection.PrivateSeed + header.GetHeaderId());
        }
    }
}

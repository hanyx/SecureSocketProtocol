using System;
using System.Collections.Generic;
using System.Text;

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

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

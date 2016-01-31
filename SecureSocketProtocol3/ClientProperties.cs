using SecureSocketProtocol3.Security.DataIntegrity;
using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.IO;
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

namespace SecureSocketProtocol3
{
    public abstract class ClientProperties
    {
        public abstract string HostIp { get; }
        public abstract ushort Port { get; }
        public abstract int ConnectionTimeout { get; }

        public abstract byte[] NetworkKey { get; }

        /// <summary>
        /// The Default Serializer will only be used if a Message you're going to send did not specified the serializer
        /// </summary>
        public abstract ISerialization DefaultSerializer { get; }

        public ClientProperties()
        {

        }
    }
}
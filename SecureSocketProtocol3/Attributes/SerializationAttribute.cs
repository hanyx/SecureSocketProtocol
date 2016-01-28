using SecureSocketProtocol3.Security.Serialization;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
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

namespace SecureSocketProtocol3.Attributes
{
    public class SerializationAttribute : Attribute
    {
        public delegate void Invoky();
        public ISerialization Serializer { get; private set; }
        public SerializationAttribute(Type SerializationType)
        {
            this.Serializer = Activator.CreateInstance(SerializationType) as ISerialization;

            if (Serializer == null)
            {
                throw new Exception("Type must be inherited by ISerialization");
            }
        }

        public SerializationAttribute(ISerialization Serializer)
        {
            if (Serializer == null)
                throw new ArgumentNullException("Serializer");

            this.Serializer = Serializer;
        }
    }
}
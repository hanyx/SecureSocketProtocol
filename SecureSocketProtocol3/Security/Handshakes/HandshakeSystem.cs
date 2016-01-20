using System;
using System.Collections.Generic;
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

namespace SecureSocketProtocol3.Security.Handshakes
{
    public class HandshakeSystem
    {
        private List<Handshake> _handshakes;

        public Handshake[] Handshakes
        {
            get { return _handshakes.ToArray(); }
        }

        public HandshakeSystem()
        {
            this._handshakes = new List<Handshake>();
        }

        public void AddLayer(Handshake Handshake)
        {
            lock (_handshakes)
            {
                this._handshakes.Add(Handshake);
            }
        }

        public bool CompletedAllHandshakes
        {
            get
            {
                if (_handshakes.Where(o => !o.IsFinished).Count() > 0)
                    return false;
                return true;
            }
        }

        /// <summary>
        /// Grab the top unfinished Handshake
        /// </summary>
        /// <returns></returns>
        public Handshake GetCurrentHandshake()
        {
            return _handshakes.FirstOrDefault(o => !o.IsFinished);
        }
    }
}
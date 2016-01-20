using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

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

namespace SecureSocketProtocol3.Utils
{
    public sealed class SyncObject
    {
        public bool IsPulsed { get; internal set; }
        private Object LockedObject = new Object();

        /// <summary> The main object </summary>
        public Object Value = null;
        public bool TimedOut = false;
        private Connection connection;

        public SyncObject(Connection connection)
        {
            if (connection == null)
                throw new ArgumentNullException("connection");
            this.connection = connection;
        }
        public SyncObject(SSPClient connection)
        {
            if (connection == null)
                throw new ArgumentNullException("connection");
            if (connection.Connection == null)
                throw new ArgumentException("connection.Connection is null");
            this.connection = connection.Connection;
        }
        public SyncObject(OperationalSocket OpSocket)
        {
            if (OpSocket == null)
                throw new ArgumentNullException("OpSocket");
            if (OpSocket.Client == null)
                throw new ArgumentNullException("OpSocket.Client");
            this.connection = OpSocket.Client.Connection;
        }

        /// <param name="TimeOut">The time to wait for the object being pulsed</param>
        public T Wait<T>(T TimeOutValue, uint TimeOut = 0)
        {
            if (IsPulsed)
                return (T)Value;

            int waitTime = 0;

            lock (LockedObject)
            {
                while (!IsPulsed && connection.Connected)
                {
                    if (TimeOut == 0)
                    {
                        Monitor.Wait(LockedObject, 250);
                    }
                    else
                    {
                        //Monitor.Wait(LockedObject, (int)TimeOut);
                        Monitor.Wait(LockedObject, 250);
                        waitTime += 250;
                        this.TimedOut = waitTime > TimeOut;

                        if (this.TimedOut)
                            return (T)TimeOutValue;
                    }
                }

                if (!IsPulsed)
                    return TimeOutValue;
            }
            return (T)Value;
        }

        public void Pulse()
        {
            lock (LockedObject)
            {
                Monitor.Pulse(LockedObject);
            }
            IsPulsed = true;
        }
    }
}
using SecureSocketProtocol3.Network;
using System;
using System.Collections.Generic;
using System.Text;
using System.Threading;

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

namespace SecureSocketProtocol3.Utils
{
    public sealed class SyncObject
    {
        public bool IsPulsed { get; internal set; }
        private Object LockedObject = new Object();
        private Object ValueLock = new Object();

        private Object _value = null; 

        /// <summary> The main object </summary>
        public Object Value
        {
            get
            {
                lock (ValueLock)
                {
                    return _value;
                }
            }
            set
            {
                lock (ValueLock)
                {
                    _value = value;
                }
            }
        }

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

        public void Reset()
        {
            IsPulsed = false;
            Value = null;
            TimedOut = false;
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
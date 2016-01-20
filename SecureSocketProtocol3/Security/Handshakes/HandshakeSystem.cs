using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

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
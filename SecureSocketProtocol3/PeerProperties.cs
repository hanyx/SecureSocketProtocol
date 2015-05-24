using SecureSocketProtocol3.Security.Configurations;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3
{
    public class PeerProperties
    {
        public TimingConfig Timing { get; private set; }

        public PeerProperties()
        {
            this.Timing = new TimingConfig();
        }
    }
}
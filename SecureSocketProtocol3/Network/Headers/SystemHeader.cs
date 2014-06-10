using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Network.Headers
{
    public class SystemHeader : Header
    {
        public override Version Version
        {
            get { return new Version(1, 0, 0, 0); }
        }

        public override string HeaderName
        {
            get { return "Secure Socket Protocol Header"; }
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Security.Configurations
{
    /// <summary>
    /// dasdas
    /// </summary>
    public class TimingConfig
    {
        /// <summary>
        /// Enabling the timing configuration might slow down the traffic but it worth it trying to avoid timing attacks
        /// </summary>
        public bool Enable_Timing { get; set; }

        /// <summary>
        /// Set the time to wait to send a response to the client to tell the password is wrong, Longer = Less Bruteforce attacks
        /// </summary>
        public TimeSpan Authentication_WrongPassword { get; set; }

        internal TimingConfig()
        {
            this.Enable_Timing = true;
            this.Authentication_WrongPassword = new TimeSpan(0, 0, 5);
        }
    }
}
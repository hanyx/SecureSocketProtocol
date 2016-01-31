using System;
using System.Collections.Generic;
using System.Linq;
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
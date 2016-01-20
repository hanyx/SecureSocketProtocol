using System;
using System.Collections.Generic;
using System.Diagnostics;
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

namespace SecureSocketProtocol3.Utils
{
    public delegate void BenchCallback();
    public class Benchmark
    {
        public ulong SpeedPerSec { get; private set; }
        private Stopwatch SW;
        private ulong speed = 0;
        public bool PastASecond { get; private set; }

        public Benchmark()
        {

        }

        public void Bench(BenchCallback callback)
        {
            PastASecond = false;
            if (SW == null)
                SW = Stopwatch.StartNew();

            callback();
            speed++;

            if (SW.ElapsedMilliseconds >= 1000)
            {
                SpeedPerSec = speed;
                speed = 0;
                SW = Stopwatch.StartNew();
                PastASecond = true;
            }
        }
    }
}
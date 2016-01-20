using System;
using System.Collections.Generic;
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
    public class RandomDecimal
    {
        private FastRandom random;

        public RandomDecimal(int Seed)
        {
            random = new FastRandom(Seed);
        }

        private int NextInt32()
        {
            unchecked
            {
                int firstBits = this.random.Next(0, 1 << 4) << 28;
                int lastBits = this.random.Next(0, 1 << 28);
                return firstBits | lastBits;
            }
        }

        public decimal NextDecimal()
        {
            lock (random)
            {
                byte scale = (byte)this.random.Next(29);
                bool sign = this.random.Next(2) == 1;
                return new decimal(NextInt32(), NextInt32(), NextInt32(), sign, scale);
            }
        }
    }
}

using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    /// <summary>
    /// The Mazing Handshake is a custom handshake to replace RSA & Diffie-Hellman
    /// </summary>
    public abstract class Mazing
    {
        public ulong[,] Maze { get; private set; }

        /// <summary>
        /// Initialize the mazing handshake
        /// </summary>
        /// <param name="Seed">The seed to use for the Handshake</param>
        /// <param name="size">The size of the actual maze</param>
        public Mazing(double Seed, Size size)
        {
            this.Maze = new ulong[size.Width, size.Height];


        }


    }
}
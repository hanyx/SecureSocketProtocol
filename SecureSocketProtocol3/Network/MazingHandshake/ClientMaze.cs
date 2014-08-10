using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.Drawing;
using System.Security.Cryptography;
using System.Text;

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    public class ClientMaze : Mazing
    {
        public ClientMaze()
            : base(new Size(512, 512), 10, 30)
        {

        }

        public override bool onReceiveData(byte[] Data)
        {
            switch (base.Step)
            {
                case 1:
                    {

                        break;
                    }
            }

            return true;
        }

        public byte[] GetByteCode()
        {
            return Mazing.ByteCode;
        }

    }
}
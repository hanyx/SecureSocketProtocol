using System;
using System.Collections.Generic;
using System.Drawing;
using System.Text;

namespace SecureSocketProtocol3.Network.MazingHandshake
{
    public class ServerMaze : Mazing
    {

        public ServerMaze()
            : base(new Size(512, 512), 10, 30)
        {

        }

        public override bool onReceiveData(byte[] Data)
        {
            switch (base.Step)
            {
                case 1:
                {
                    if (Data.Length != Mazing.ByteCode.Length)
                        return false;

                    for (int i = 0; i < Mazing.ByteCode.Length; i++)
                    {
                        if (Mazing.ByteCode[i] != Data[i])
                            return false;
                    }
                    Step++;
                    break;
                }
                case 2:
                {

                    break;
                }
            }

            return true;
        }
    }
}
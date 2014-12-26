using System;
using System.Collections.Generic;
using System.Text;

namespace SecureSocketProtocol3.Encryptions.Compiler
{
    public interface IAlgorithm
    {
        ulong CalculateULong(ulong Value);
        //byte CalculateByte(byte Value);
    }
}

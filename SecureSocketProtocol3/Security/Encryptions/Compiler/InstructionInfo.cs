using ProtoBuf;
using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
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

namespace SecureSocketProtocol3.Security.Encryptions.Compiler
{
    [ProtoContract]
    public class InstructionInfo
    {
        private bool _isValue1Set;
        private bool _isValue2Set;
        private bool _isValue3Set;

        private BigInteger _value1;
        private BigInteger _value2;
        private BigInteger _value3;

        private byte _value_byte;
        private byte _value2_byte;
        private byte _value3_byte;

        private ulong _value_long;
        private ulong _value2_long;
        private ulong _value3_long;

        [ProtoMember(1)]
        public WopEx.Instruction Inst;

        [ProtoMember(2)]
        public byte[] ValueData;

        [ProtoMember(3)]
        public byte[] ValueData2;

        [ProtoMember(4)]
        public byte[] ValueData3;

        public BigInteger Value
        {
            get
            {
                if (!_isValue1Set)
                {
                    _value1 = new BigInteger(ValueData);
                    _isValue1Set = true;
                }
                return _value1;
            }
            private set
            {
                _value1 = value;
                ValueData = value.getBytes();
            }
        }
        public BigInteger Value2
        {
            get
            {
                if (!_isValue2Set)
                {
                    _value2 = new BigInteger(ValueData2);
                    _isValue2Set = true;
                }
                return _value2;
            }
            private set
            {
                _value2 = value;
                ValueData2 = value.getBytes();
            }
        }
        public BigInteger Value3
        {
            get
            {
                if (!_isValue3Set)
                {
                    _value3 = new BigInteger(ValueData3);
                    _isValue3Set = true;
                }
                return _value3;
            }
            private set
            {
                _value3 = value;
                ValueData3 = value.getBytes();
            }
        }


        public byte Value_Byte
        {
            get
            {
                if (_value_byte == 0)
                    _value_byte = (byte)(Value.IntValue() & 0xFF);
                return _value_byte;
            }
        }

        public byte Value2_Byte
        {
            get
            {
                if (_value2_byte == 0)
                    _value2_byte = (byte)(Value2.IntValue() & 0xFF);
                return _value2_byte;
            }
        }

        public byte Value3_Byte
        {
            get
            {
                if (_value3_byte == 0)
                    _value3_byte = (byte)(Value3.IntValue() & 0xFF);
                return _value3_byte;
            }
        }


        public ulong Value_Long
        {
            get
            {
                if (_value_long == 0)
                    _value_long = (ulong)Value.LongValue();
                return _value_long;
            }
        }

        public ulong Value2_Long
        {
            get
            {
                if (_value2_long == 0)
                    _value2_long = (byte)Value2.LongValue();
                return _value2_long;
            }
        }

        public ulong Value3_Long
        {
            get
            {
                if (_value3_long == 0)
                    _value3_long = (byte)Value3.LongValue();
                return _value3_long;
            }
        }


        public InstructionInfo()
        {

        }

        public InstructionInfo(WopEx.Instruction Inst, BigInteger Value)
        {
            this.Inst = Inst;
            this.Value = Value;
        }
        public InstructionInfo(WopEx.Instruction Inst, BigInteger Value, BigInteger Value2)
        {
            this.Inst = Inst;
            this.Value = Value;
            this.Value2 = Value2;
        }
        public InstructionInfo(WopEx.Instruction Inst, BigInteger Value, BigInteger Value2, BigInteger Value3)
        {
            this.Inst = Inst;
            this.Value = Value;
            this.Value2 = Value2;
            this.Value3 = Value3;
        }

        public override string ToString()
        {
            return "Instruction:" + Inst + ", Value:" + Value;
        }
    }
}

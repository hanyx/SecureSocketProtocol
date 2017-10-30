using SecureSocketProtocol3.Utils;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;

namespace SecureSocketProtocol3.Network
{
    //all the pre-computations should be put in here to lower the cpu-usage down and such
    internal class ClientPrecomputes
    {
        private object ComputeLocker = new object();

        private byte[] _preNetworkKey;
        private byte[] _networkKey;
        private byte[] _networkSalt;
        private byte[] _saltKey;

        internal byte[] PreNetworkKey
        {
            get
            {
                if(_preNetworkKey != null)
                    return _preNetworkKey.ToArray();
                return null;
            }
            private set
            {
                _preNetworkKey = value;
            }
        }

        /// <summary>
        /// Network key with the KeyFiles applied
        /// </summary>
        internal byte[] NetworkKey
        {
            get
            {
                if (_networkKey != null)
                    return _networkKey.ToArray();
                return null;
            }
            private set
            {
                _networkKey = value;
            }
        }

        public byte[] NetworkKeySalt
        {
            get
            {
                if (_networkSalt != null)
                    return _networkSalt.ToArray();
                return null;
            }
            private set
            {
                _networkSalt = value;
            }
        }

        public int PrivateSeed
        {
            get;
            private set;
        }

        public byte[] SaltKey
        {
            get
            {
                if (_preNetworkKey != null)
                    return _saltKey.ToArray();
                return null;
            }
            private set
            {
                _saltKey = value;
            }
        }

        public ClientPrecomputes()
        {

        }

        public void ComputeNetworkKey(SSPClient Client)
        {
            lock (ComputeLocker)
            {
                if (this.NetworkKey != null)
                    return;

                byte[] FinalKey = _preNetworkKey;
                FastRandom rand = new FastRandom(PrivateSeed);
                Stream[] keyFiles = null;

                if (FinalKey.Length < 1024)
                {
                    Array.Resize(ref FinalKey, 1024);
                }

                if (Client.Server != null && Client.Server.serverProperties.KeyFiles != null)
                    keyFiles = Client.Server.serverProperties.KeyFiles;
                else if (Client.ConnectedProperty.KeyFiles != null)
                    keyFiles = Client.ConnectedProperty.KeyFiles;

                if (keyFiles != null)
                {
                    foreach (Stream stream in keyFiles)
                    {
                        if (stream.CanSeek)
                            stream.Position = 0;

                        byte[] TempData = new byte[stream.Length];
                        int ReadOffset = 0;

                        if (TempData.Length < 8192)
                            TempData = new byte[8192];

                        while (ReadOffset != TempData.Length && stream.Length != ReadOffset)
                        {
                            int read = stream.Read(TempData, ReadOffset, TempData.Length - ReadOffset);
                            ReadOffset += read;
                        }

                        if (ReadOffset != TempData.Length)
                        {
                            //fillup the empty space with random data
                            byte[] TempRandom = new byte[TempData.Length - ReadOffset];
                            rand.NextBytes(TempRandom);
                            Array.Copy(TempRandom, 0, TempData, ReadOffset, TempRandom.Length);
                        }


                        rand = new FastRandom(PrivateSeed);
                        for (int i = 0; i < FinalKey.Length; i++)
                        {
                            for (int j = 0; j < TempData.Length; j++)
                            {
                                FinalKey[i] += (byte)((TempData[j] + rand.Next(0, 255)) % 0xFF);
                            }
                        }
                    }
                }

                this.NetworkKey = FinalKey;

                //compute the Network Salt
                _networkSalt = new byte[FinalKey.Length];
                Array.Copy(FinalKey, _networkSalt, _networkSalt.Length);
                rand = new FastRandom(PrivateSeed);

                for (int i = 0; i < _networkSalt.Length; i++)
                    _networkSalt[i] += (byte)(_preNetworkKey[i % _preNetworkKey.Length] + rand.Next(0, 255) % 0xFF);

                this._saltKey = new byte[NetworkKey.Length];
                Array.Copy(NetworkKey, _saltKey, _saltKey.Length);

                for (int i = 0; i < _saltKey.Length; i++)
                    _saltKey[i] += (byte)PrivateSeed;
            }
        }

        public void SetPreNetworkKey(SSPClient Client)
        {
            lock (ComputeLocker)
            {
                if (this._preNetworkKey != null)
                    return;

                _preNetworkKey = Client.Server != null ? Client.Server.serverProperties.NetworkKey : Client.ConnectedProperty.NetworkKey;
                PrivateSeed = _preNetworkKey.Length >= 4 ? BitConverter.ToInt32(_preNetworkKey, 0) : 0xBEEF;

                for (int i = 0; i < _preNetworkKey.Length; i++)
                    PrivateSeed += _preNetworkKey[i];
            }
        }
    }
}
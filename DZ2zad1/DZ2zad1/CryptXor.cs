using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DZ2zad1
{
    class CryptXor: ICrypt
    {

        public byte[] Encrypt(byte[] src, byte[] key)
        {
            var res = new byte[src.Length];

            for (var i = 0; i < res.Length; i++)
                res[i] = (byte)(src[i] ^ key[i % key.Length]);

            return res;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DZ2zad1
{
    public interface ICrypt
    {
        byte[] Encrypt(byte[] src, byte[] key);
    }
}

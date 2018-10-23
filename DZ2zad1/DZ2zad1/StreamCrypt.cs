using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace DZ2zad1
{
    class StreamCrypt 
    {
        private ICrypt crypter;

        public StreamCrypt(ICrypt crypter)
        {
            this.crypter = crypter;
        }

        public int Crypt(Stream stream, long offset, byte[] buff, byte[] key)
        {
            stream.Seek(offset, SeekOrigin.Begin);
            var readBytes = stream.Read(buff, 0, buff.Length);

            // шифровать
            var encrypted = crypter.Encrypt(buff, key);

            stream.Seek(offset, SeekOrigin.Begin);
            stream.Write(encrypted, 0, readBytes);

            return readBytes;
        }
        
    }
}

using System.Diagnostics;
using System.Text;

namespace CryptSindresorhusConf
{
    class Program
    {
        public static void Main()
        {
            string filename = "data.txt";
            byte[] key = Encoding.Default.GetBytes("key");
            string data = "hello there";

            // Encrypt File
            Conf.EncryptFile(key, filename, data);

            // Decrypt File
            string decrypted = Conf.DecryptFile(key, filename);
            Debug.Assert(decrypted == data);

            Conf conf = new(key);

            // Encrypt
            byte[] encrypted = conf.Encrypt(data);

            // Decrypt
            string plaintext = conf.Decrypt(
                new ArraySegment<byte>(encrypted, 17, encrypted.Length - 17).ToArray()
            );
            Debug.Assert(plaintext == data);
        }
    }
}

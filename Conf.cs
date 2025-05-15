using System.Text;
using System.Security.Cryptography;
using System.Diagnostics;

namespace CryptSindresorhusConf;

public class Conf
{
    readonly Aes aes;

    public Conf(byte[] key, byte[]? iv = null)
    {
        aes = Aes.Create();

        Debug.Print("Key:      {0}", BitConverter.ToString(key));

        if (iv is not null)
            aes.IV = iv;

        Debug.Print("IV:       {0}", BitConverter.ToString(aes.IV));

        // Wow!
        byte[] salt = Encoding.Default.GetBytes(Encoding.UTF8.GetString(aes.IV));
        Debug.Print("Salt:     {0}", BitConverter.ToString(salt));

        byte[] password = Rfc2898DeriveBytes.Pbkdf2(key, salt, 10_000, HashAlgorithmName.SHA512, 32);
        aes.Key = password;
        Debug.Print("Password: {0}", BitConverter.ToString(password));
    }

    public byte[] Encrypt(string plaintext)
    {
        byte[] colon = [0x3A]; // ":"
        byte[] encrypted = aes.EncryptCbc(Encoding.UTF8.GetBytes(plaintext), aes.IV);
        byte[] rv = new byte[aes.IV.Length + colon.Length + encrypted.Length];
        Buffer.BlockCopy(aes.IV, 0, rv, 0, aes.IV.Length);
        Buffer.BlockCopy(colon, 0, rv, aes.IV.Length, colon.Length);
        Buffer.BlockCopy(encrypted, 0, rv, aes.IV.Length + colon.Length, encrypted.Length);

        return rv;
    }

    public string Decrypt(byte[] ciphertext)
    {
        byte[] decrypted = aes.DecryptCbc(ciphertext, aes.IV);
        return Encoding.UTF8.GetString(decrypted);
    }

    public static void EncryptFile(byte[] key, string filename, string plaintext)
    {
        using FileStream fileStream = new(filename, FileMode.OpenOrCreate);
        fileStream.Write(new Conf(key, Aes.Create().IV).Encrypt(plaintext));
    }

    public static string DecryptFile(byte[] key, string filename)
    {
        using FileStream fileStream = new(filename, FileMode.Open);

        byte[] iv = new byte[16];
        fileStream.ReadExactly(iv, 0, 16);

        fileStream.Seek(17, 0); // Skip the colon

        byte[] ciphertext = new byte[fileStream.Length - 17];
        fileStream.Read(ciphertext);

        return new Conf(key, iv).Decrypt(ciphertext);
    }
}

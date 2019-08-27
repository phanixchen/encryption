using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using SCBULSeeSecure;

namespace TestConsoleApplication1
{
    class Program
    {
        static void Main(string[] args)
        {
            string plain = "this is a book";
            Console.WriteLine(plain);
            //string cipher = UlseeEncryption.OpenSSLEncryptDynamic(plain);
            string cipher = UlseeEncryption.EncryptDES(plain, "20171114");
            Console.WriteLine(cipher);
            Console.WriteLine(UlseeEncryption.DecryptDES(cipher, "20171114"));
            //Console.Write(DateTime.Now.ToString("yyyyMMdd"));
            Console.ReadLine();
        }
    }
}

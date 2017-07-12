using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;
using System.Globalization;
using System.IO;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace PHPDecryptor
{
    public partial class WebForm : System.Web.UI.Page
    {

        const String key = "03e22ab6765bef74497601a6d94d5bd7b9fd8e345e578fdfad673f5b0ad291ca";

        /// <summary>
        /// Decodes a Base64 encoded String back to ASCII
        /// </summary>
        /// <param name="codedString">Base64 encoded string</param>
        /// <returns>Plaintext representation</returns>
        private static String base64_decode(String codedString)
        {
            // From: https://stackoverflow.com/a/7134853
            byte[] data = Convert.FromBase64String(codedString);
            return Encoding.ASCII.GetString(data);
        }

        /// <summary>
        /// Calculates a HMAC-SHA256 for the given Key and Message
        /// </summary>
        /// <param name="key">The key</param>
        /// <param name="message">The message</param>
        /// <returns>The HMAC</returns>
        private static byte[] HashHMAC(byte[] key, byte[] message)
        {
            // From: https://stackoverflow.com/a/12253723
            var hash = new HMACSHA256(key);
            return hash.ComputeHash(message);
        }

        private static String HashEncode(byte[] hash)
        {
            // From: https://stackoverflow.com/a/12253723
            return BitConverter.ToString(hash).Replace("-", "").ToLower();
        }

        private static byte[] StringToByteArray(string text)
        {
            // From: https://stackoverflow.com/a/12253723
            var encoding = new ASCIIEncoding();
            return encoding.GetBytes(text);
        }

        private static byte[] HexDecode(string hex)
        {
            // From: https://stackoverflow.com/a/12253723
            var bytes = new byte[hex.Length / 2];
            for (int i = 0; i < bytes.Length; i++)
            {
                bytes[i] = byte.Parse(hex.Substring(i * 2, 2), NumberStyles.HexNumber);
            }
            return bytes;
        }

        private static string HashHMACHex(string keyHex, string message)
        {
            byte[] hash = HashHMAC(HexDecode(keyHex), StringToByteArray(message));
            return HashEncode(hash);
        }

        // Decrypt a string into a string using a key and an IV
        private static string Decrypt(byte[] cipherData, byte[] key, byte[] iv)
        {
            // Based on: https://stackoverflow.com/a/20298260
            // There should be an Exception Handling

            // To get AES256 you need to explicitly set KeySize AND BlockSize
            // PHP's mcrypt is using Zero-Bytes for Padding. The default Padding for C# is PKCS7 (which you either have to implement in PHP or use PHP's Zero-Padding)
            using (var rijndaelManaged = new RijndaelManaged { KeySize = 256, BlockSize = 256, Key = key, IV = iv, Mode = CipherMode.CBC, Padding = PaddingMode.Zeros })
            using (var memoryStream = new MemoryStream(cipherData))
            using (var cryptoStream = new CryptoStream(memoryStream, rijndaelManaged.CreateDecryptor(key, iv), CryptoStreamMode.Read))
            {
                return new StreamReader(cryptoStream).ReadToEnd();
            }
        }


        /// <summary>
        /// Size of the used Initialisation Vector
        /// </summary>
        const int IVSize = 32;

        /// <summary>
        /// Decrypt a String with concatednated IV
        /// </summary>
        /// <param name="cipherText">IV || cipherText</param>
        /// <param name="key">Decryption Key</param>
        /// <returns>Plaintext</returns>
        private static String DecryptWithIV(byte[] cipherText, byte[] key)
        {
            /*
            // Extract the IV
            String IVString = cipherText.Substring(0, IVSize);
            String cipherData = cipherText.Substring(IVSize);
            byte[] iv = StringToByteArray(IVString);
            */

            byte[] iv = new byte[IVSize];
            Array.Copy(cipherText, iv, IVSize);

            byte[] cipherData = new byte[cipherText.Length - IVSize];
            Array.Copy(cipherText, IVSize, cipherData, 0, cipherData.Length);

            return Decrypt(cipherData, key, iv);
        }

        protected void Page_Load(object sender, EventArgs e)
        {
            // Fetch the data from the GET-Parameters
            String data = Request.QueryString["data"];
            String signature = Request.QueryString["signature"];

            if ((data == null) || (signature == null))
            {
                // If one of the parameters is missing: either display the message or throw an Exception
                dataPanel.Text = "Data or Signature are missing";
                // throw new Exception("Data or Signature are missing");
                return;
            }

            // Data is filled with text, so replace " " (Space) with "+" (plus sign) to undo URL Decoding
            data = data.Replace(' ', '+');

            // Check the HMAC
            String hmac = HashHMACHex(key, data);
            if (hmac != signature)
            {
                // Signature does not match -> Error or Exception
                dataPanel.Text = "Signature is wrong";
                return;
            }

            // Now move on to decrypt the data
            // Don't convert from Base64 -> String -> byte[]
            // Do it in one step: Base64 -> byte[]
            String DecryptedData = DecryptWithIV(Convert.FromBase64String(data), HexDecode(key));

            // Now that the data is decrypted, convert it back to an object
            dynamic receivedData = JsonConvert.DeserializeObject(DecryptedData);

            StringBuilder sb = new StringBuilder();
            sb.Append("<pre>");

            // Inspect the contents
            foreach( JProperty property in receivedData)
            {
                sb.Append(property.Name);
                sb.Append(" -&gt; ");
                sb.Append(property.Value);
                sb.Append("\n");
            }

            sb.Append("</pre>");

            dataPanel.Text = sb.ToString();

        }
    }
}
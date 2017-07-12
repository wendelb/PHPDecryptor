using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Web;
using System.Web.UI;
using System.Web.UI.WebControls;
using System.Security.Cryptography;
using System.Globalization;

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


        }
    }
}
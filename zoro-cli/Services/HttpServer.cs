using Newtonsoft.Json;
using System;
using System.IO;
using System.Net;
using System.Text;
using Zoro.Wallets;
using Zoro.Wallets.NEP6;

namespace Zoro.Services
{
    public class HttpServer
    {
        private static HttpListener Listener = new HttpListener();

        public static void HttpServerStart(string address)
        {            
            Listener.Prefixes.Add(address);

            while (true)
            {
                Listener.Start();
                HttpListenerContext requestContext = Listener.GetContext();
                byte[] buffer = new byte[] { };

                try
                {
                    StreamReader sr = new StreamReader(requestContext.Request.InputStream);
                    string reqMethod = requestContext.Request.RawUrl.Replace("/", "");
                    string data = sr.ReadToEnd();

                    string result = GetResponse(reqMethod, data);
                                        
                    buffer = Encoding.UTF8.GetBytes(JsonConvert.SerializeObject(result));
                }

                catch (Exception e)
                {
                    var rsp = JsonConvert.SerializeObject(e.Message);
                    buffer = Encoding.UTF8.GetBytes(rsp);
                }
                finally
                {
                    requestContext.Response.StatusCode = 200;
                    requestContext.Response.Headers.Add("Access-Control-Allow-Origin", "*");
                    requestContext.Response.ContentType = "application/json";
                    requestContext.Response.ContentEncoding = Encoding.UTF8;
                    requestContext.Response.ContentLength64 = buffer.Length;
                    var output = requestContext.Response.OutputStream;
                    output.Write(buffer, 0, buffer.Length);
                    output.Close();
                }
            }
        }

        private static string GetResponse(string reqMethod, string data)
        {
            if (reqMethod == "openwallet")
            {
                Program.Wallet = OpenWalletByData(data, Settings.Default.UnlockWallet.Password);
                Console.WriteLine("Open wallet successfully");
                return "Open wallet successfully";
            }
            else if (reqMethod == "closewallet")
            {
                Program.Wallet = null;
                Console.WriteLine("Clear wallet successfully");
                return "Clear wallet successfully";
            }
            else
                return "Params error";
        }

        private static Wallet OpenWalletByData(string data, string password)
        {
            Wallet wallet = null;

            NEP6Wallet nep6wallet = new NEP6Wallet(data);
            nep6wallet.Unlock(password);
            wallet = nep6wallet;

            ZoroChainSystem.Singleton.SetWallet(wallet);


            return wallet;
        }
    }
}

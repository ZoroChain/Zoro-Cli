using Akka.Actor;
using Zoro.IO;
using Zoro.Ledger;
using Zoro.Network.P2P;
using Zoro.Network.P2P.Payloads;
using Zoro.Persistence;
using Zoro.Persistence.LevelDB;
using Zoro.Services;
using Zoro.SmartContract;
using Zoro.Wallets;
using Zoro.Wallets.NEP6;
using Zoro.Plugins;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using ECCurve = Zoro.Cryptography.ECC.ECCurve;
using ECPoint = Zoro.Cryptography.ECC.ECPoint;

namespace Zoro.Shell
{
    internal class MainService : ConsoleServiceBase
    {
        private const string PeerStatePath = "peers.dat";

        private LevelDBStore store;
        private ZoroChainSystem system;
        private AppChainService appchainService;

        protected override string Prompt => "zoro";
        public override string ServiceName => "Zoro-CLI";

        public MainService()
        {
            appchainService = new AppChainService();
        }

        private static bool NoWallet()
        {
            if (Program.Wallet != null) return false;
            Console.WriteLine("You have to open the wallet first.");
            return true;
        }

        protected override bool OnCommand(string[] args)
        {
            if (PluginManager.Singleton.SendMessage(args)) return true;
            switch (args[0].ToLower())
            {
                case "broadcast":
                    return OnBroadcastCommand(args);
                case "relay":
                    return OnRelayCommand(args);
                case "sign":
                    return OnSignCommand(args);
                case "create":
                    return OnCreateCommand(args);
                case "export":
                    return OnExportCommand(args);
                case "help":
                    return OnHelpCommand(args);
                case "import":
                    return OnImportCommand(args);
                case "list":
                    return OnListCommand(args);
                case "open":
                    return OnOpenCommand(args);
                case "show":
                    return OnShowCommand(args);
                case "start":
                    return OnStartCommand(args);
                case "appchain":
                    return OnAppChainCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnBroadcastCommand(string[] args)
        {
            string command = args[1].ToLower();
            string hashString = args[2];
            ZoroSystem zoroSystem = system.GetZoroSystem(hashString);
            Blockchain blockchain = system.GetBlockchain(hashString);
            if (zoroSystem == null || blockchain == null)
            {
                Console.WriteLine($"Unknown blockchain hash {hashString}.");
                return true;
            }
            ISerializable payload = null;
            switch (command)
            {
                case "addr":
                    payload = AddrPayload.Create(NetworkAddressWithTime.Create(new IPEndPoint(IPAddress.Parse(args[3]), ushort.Parse(args[4])), NetworkAddressWithTime.NODE_NETWORK, DateTime.UtcNow.ToTimestamp()));
                    break;
                case "block":
                    if (args[3].Length == 64 || args[3].Length == 66)
                        payload = blockchain.GetBlock(UInt256.Parse(args[3]));
                    else
                        payload = blockchain.Store.GetBlock(uint.Parse(args[3]));
                    break;
                case "getblocks":
                case "getheaders":
                    payload = GetBlocksPayload.Create(UInt256.Parse(args[3]));
                    break;
                case "getdata":
                    payload = InvPayload.Create(Enum.Parse<InventoryType>(args[3], true), UInt256.Parse(args[4]));
                    break;
                case "inv":
                case "getdatagroup":
                    payload = InvPayload.Create(Enum.Parse<InventoryType>(args[3], true), args.Skip(4).Select(UInt256.Parse).ToArray());
                    break;
                case "tx":
                    payload = blockchain.GetTransaction(UInt256.Parse(args[3]));
                    break;
                case "alert":
                case "consensus":
                case "filteradd":
                case "filterload":
                case "headers":
                case "merkleblock":
                case "ping":
                case "pong":
                case "reject":
                case "verack":
                case "version":
                    Console.WriteLine($"Command \"{command}\" is not supported.");
                    return true;
            }
            zoroSystem.LocalNode.Tell(Message.Create(command, payload));
            return true;
        }

        private bool OnRelayCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("You must input JSON object to relay.");
                return true;
            }
            string hashString = args[1];
            ZoroSystem zoroSystem = system.GetZoroSystem(hashString);
            if (zoroSystem == null)
            {
                Console.WriteLine($"Unknown blockchain hash {hashString}.");
                return true;
            }

            var jsonObjectToRelay = string.Join(string.Empty, args.Skip(2));
            if (string.IsNullOrWhiteSpace(jsonObjectToRelay))
            {
                Console.WriteLine("You must input JSON object to relay.");
                return true;
            }
            try
            {
                ContractParametersContext context = ContractParametersContext.Parse(jsonObjectToRelay);
                if (!context.Completed)
                {
                    Console.WriteLine("The signature is incomplete.");
                    return true;
                }
                context.Verifiable.Witnesses = context.GetWitnesses();
                IInventory inventory = (IInventory)context.Verifiable;
                zoroSystem.LocalNode.Tell(new LocalNode.Relay { Inventory = inventory });
                Console.WriteLine($"Data relay success, the hash is shown as follows:\r\n{inventory.Hash}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"One or more errors occurred:\r\n{e.Message}");
            }
            return true;
        }

        private bool OnSignCommand(string[] args)
        {
            if (NoWallet()) return true;

            if (args.Length < 2)
            {
                Console.WriteLine("You must input JSON object pending signature data.");
                return true;
            }
            var jsonObjectToSign = string.Join(string.Empty, args.Skip(1));
            if (string.IsNullOrWhiteSpace(jsonObjectToSign))
            {
                Console.WriteLine("You must input JSON object pending signature data.");
                return true;
            }
            try
            {
                ContractParametersContext context = ContractParametersContext.Parse(jsonObjectToSign);
                if (!Program.Wallet.Sign(context))
                {
                    Console.WriteLine("The private key that can sign the data is not found.");
                    return true;
                }
                Console.WriteLine($"Signed Output:\r\n{context}");
            }
            catch (Exception e)
            {
                Console.WriteLine($"One or more errors occurred:\r\n{e.Message}");
            }
            return true;
        }

        private bool OnCreateCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "address":
                    return OnCreateAddressCommand(args);
                case "wallet":
                    return OnCreateWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnCreateAddressCommand(string[] args)
        {
            if (NoWallet()) return true;
            if (args.Length > 3)
            {
                Console.WriteLine("error");
                return true;
            }

            ushort count;
            if (args.Length >= 3)
                count = ushort.Parse(args[2]);
            else
                count = 1;

            int x = 0;
            List<string> addresses = new List<string>();

            Parallel.For(0, count, (i) =>
            {
                WalletAccount account = Program.Wallet.CreateAccount();

                lock (addresses)
                {
                    x++;
                    addresses.Add(account.Address);
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"[{x}/{count}]");
                }
            });

            if (Program.Wallet is NEP6Wallet wallet)
                wallet.Save();
            Console.WriteLine();
            string path = "address.txt";
            Console.WriteLine($"export addresses to {path}");
            File.WriteAllLines(path, addresses);
            return true;
        }

        private bool OnCreateWalletCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("error");
                return true;
            }
            string path = args[2];
            string password = ReadPassword("password");
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            string password2 = ReadPassword("password");
            if (password != password2)
            {
                Console.WriteLine("error");
                return true;
            }
            switch (Path.GetExtension(path))
            {
                case ".json":
                    {
                        NEP6Wallet wallet = new NEP6Wallet(path);
                        wallet.Unlock(password);
                        WalletAccount account = wallet.CreateAccount();
                        wallet.Save();
                        Program.Wallet = wallet;
                        Console.WriteLine($"address: {account.Address}");
                        Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
                        ZoroChainSystem.Singleton.SetWallet(Program.Wallet);
                    }
                    break;
                default:
                    Console.WriteLine("Wallet files in that format are not supported, please use a .json or .db3 file extension.");
                    break;
            }
            return true;
        }

        private bool OnExportCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "key":
                    return OnExportKeyCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnExportKeyCommand(string[] args)
        {
            if (NoWallet()) return true;
            if (args.Length < 2 || args.Length > 4)
            {
                Console.WriteLine("error");
                return true;
            }
            UInt160 scriptHash = null;
            string path = null;
            if (args.Length == 3)
            {
                try
                {
                    scriptHash = args[2].ToScriptHash();
                }
                catch (FormatException)
                {
                    path = args[2];
                }
            }
            else if (args.Length == 4)
            {
                scriptHash = args[2].ToScriptHash();
                path = args[3];
            }
            string password = ReadPassword("password");
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            if (!Program.Wallet.VerifyPassword(password))
            {
                Console.WriteLine("Incorrect password");
                return true;
            }
            IEnumerable<KeyPair> keys;
            if (scriptHash == null)
                keys = Program.Wallet.GetAccounts().Where(p => p.HasKey).Select(p => p.GetKey());
            else
                keys = new[] { Program.Wallet.GetAccount(scriptHash).GetKey() };
            if (path == null)
                foreach (KeyPair key in keys)
                    Console.WriteLine(key.Export());
            else
                File.WriteAllLines(path, keys.Select(p => p.Export()));
            return true;
        }

        private bool OnHelpCommand(string[] args)
        {
            Console.Write(
                "Normal Commands:\n" +
                "\tversion\n" +
                "\thelp\n" +
                "\tclear\n" +
                "\texit\n" +
                "Wallet Commands:\n" +
                "\tcreate wallet <path>\n" +
                "\topen wallet <path>\n" +
                "\tupgrade wallet <path>\n" +
                "\trebuild index\n" +
                "\tlist address\n" +
                "\tlist asset\n" +
                "\tlist key\n" +
                "\tshow utxo [id|alias]\n" +
                "\tshow gas\n" +
                "\tclaim gas [all]\n" +
                "\tcreate address [n=1]\n" +
                "\timport key <wif|path>\n" +
                "\texport key [address] [path]\n" +
                "\timport multisigaddress m pubkeys...\n" +
                "\tsend <id|alias> <address> <value>|all [fee=0]\n" +
                "\tsign <jsonObjectToSign>\n" +
                "Node Commands:\n" +
                "\tshow state\n" +
                "\tshow pool [verbose]\n" +
                "\trelay <jsonObjectToSign>\n" +
                "Advanced Commands:\n" +
                "\tstart consensus\n");
            return true;
        }

        private bool OnImportCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "key":
                    return OnImportKeyCommand(args);
                case "multisigaddress":
                    return OnImportMultisigAddress(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnImportMultisigAddress(string[] args)
        {
            if (NoWallet()) return true;

            if (args.Length < 5)
            {
                Console.WriteLine("Error. Use at least 2 public keys to create a multisig address.");
                return true;
            }

            int m = int.Parse(args[2]);
            int n = args.Length - 3;

            if (m < 1 || m > n || n > 1024)
            {
                Console.WriteLine("Error. Invalid parameters.");
                return true;
            }

            ECPoint[] publicKeys = args.Skip(3).Select(p => ECPoint.Parse(p, ECCurve.Secp256r1)).ToArray();

            Contract multiSignContract = Contract.CreateMultiSigContract(m, publicKeys);
            KeyPair keyPair = Program.Wallet.GetAccounts().FirstOrDefault(p => p.HasKey && publicKeys.Contains(p.GetKey().PublicKey))?.GetKey();

            WalletAccount account = Program.Wallet.CreateAccount(multiSignContract, keyPair);
            if (Program.Wallet is NEP6Wallet wallet)
                wallet.Save();

            Console.WriteLine("Multisig. Addr.: " + multiSignContract.Address);

            return true;
        }

        private bool OnImportKeyCommand(string[] args)
        {
            if (args.Length > 3)
            {
                Console.WriteLine("error");
                return true;
            }
            byte[] prikey = null;
            try
            {
                prikey = Wallet.GetPrivateKeyFromWIF(args[2]);
            }
            catch (FormatException) { }
            if (prikey == null)
            {
                string[] lines = File.ReadAllLines(args[2]);
                for (int i = 0; i < lines.Length; i++)
                {
                    if (lines[i].Length == 64)
                        prikey = lines[i].HexToBytes();
                    else
                        prikey = Wallet.GetPrivateKeyFromWIF(lines[i]);
                    Program.Wallet.CreateAccount(prikey);
                    Array.Clear(prikey, 0, prikey.Length);
                    Console.SetCursorPosition(0, Console.CursorTop);
                    Console.Write($"[{i + 1}/{lines.Length}]");
                }
                Console.WriteLine();
            }
            else
            {
                WalletAccount account = Program.Wallet.CreateAccount(prikey);
                Array.Clear(prikey, 0, prikey.Length);
                Console.WriteLine($"address: {account.Address}");
                Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
            }
            if (Program.Wallet is NEP6Wallet wallet)
                wallet.Save();
            return true;
        }

        private bool OnListCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "address":
                    return OnListAddressCommand(args);
                case "asset":
                    return OnListAssetCommand(args);
                case "key":
                    return OnListKeyCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnListKeyCommand(string[] args)
        {
            if (NoWallet()) return true;
            foreach (KeyPair key in Program.Wallet.GetAccounts().Where(p => p.HasKey).Select(p => p.GetKey()))
            {
                Console.WriteLine(key.PublicKey);
            }
            return true;
        }

        private bool OnListAddressCommand(string[] args)
        {
            if (NoWallet()) return true;
            foreach (Contract contract in Program.Wallet.GetAccounts().Where(p => !p.WatchOnly).Select(p => p.Contract))
            {
                Console.WriteLine($"{contract.Address}\t{(contract.Script.IsStandardContract() ? "Standard" : "Nonstandard")}");
            }
            return true;
        }

        private bool OnListAssetCommand(string[] args)
        {
            if (NoWallet()) return true;
            try
            {
                UInt160 chainHash = args.Length == 3 ? UInt160.Parse(args[2]) : UInt160.Zero;

                foreach (var item in Program.Wallet.GetCoins(chainHash).GroupBy(p => p.AssetId, (k, g) => new
                {
                    Asset = Blockchain.Root.Store.GetAssets().TryGet(k),
                    Balance = g.Sum(p => p.Balance)
                }))
                {
                    Console.WriteLine($"       id:{item.Asset.AssetId}");
                    Console.WriteLine($"     name:{item.Asset.GetName()}");
                    Console.WriteLine($"  balance:{item.Balance}");
                    Console.WriteLine();
                }
            }
            catch (Exception)
            {
                return true;
            }

            return true;
        }

        private bool OnOpenCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "wallet":
                    return OnOpenWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        //TODO: 目前没有想到其它安全的方法来保存密码
        //所以只能暂时手动输入，但如此一来就不能以服务的方式启动了
        //未来再想想其它办法，比如采用智能卡之类的
        private bool OnOpenWalletCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("error");
                return true;
            }
            string path = args[2];
            if (!File.Exists(path))
            {
                Console.WriteLine($"File does not exist");
                return true;
            }
            string password = ReadPassword("password");
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            try
            {
                Program.Wallet = OpenWallet(path, password);
            }
            catch (CryptographicException)
            {
                Console.WriteLine($"failed to open file \"{path}\"");
            }
            return true;
        }

        private bool OnShowCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "pool":
                    return OnShowPoolCommand(args);
                case "state":
                    return OnShowStateCommand(args);
                case "statistic":
                    return OnShowStatisticCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnShowPoolCommand(string[] args)
        {
            bool verbose = args.Length >= 3 && args[2] == "verbose";
            Transaction[] transactions = Blockchain.Root.GetMemoryPool().ToArray();
            if (verbose)
                foreach (Transaction tx in transactions)
                    Console.WriteLine($"{tx.Hash} {tx.GetType().Name}");
            Console.WriteLine($"total: {transactions.Length}");
            return true;
        }

        private bool OnShowStateCommand(string[] args)
        {
            bool stop = false;
            bool detail = (args.Length >= 3 && int.Parse(args[2]) == 1);
            if (detail)
                PluginManager.EnableLog(false);

            Task.Run(() =>
            {
                while (!stop)
                {
                    Console.Clear();
                    ShowState(Blockchain.Root, LocalNode.Root, detail);
                    LocalNode[] appchainNodes = ZoroChainSystem.Singleton.GetAppChainLocalNodes();
                    foreach (var node in appchainNodes)
                    {
                        if (node != null && node.Blockchain != null)
                        {
                            Console.WriteLine("====================================================================");
                            ShowState(node.Blockchain, node, detail);
                        }
                    }
                    Thread.Sleep(1000);
                }
            });
            Console.ReadLine();
            stop = true;
            if (detail)
                PluginManager.EnableLog(true);
            return true;
        }

        private void ShowState(Blockchain blockchain, LocalNode localNode, bool printRemoteNode)
        {
            Console.WriteLine($"block:{blockchain.Name} {blockchain.ChainHash.ToString()} {blockchain.Height}/{blockchain.HeaderHeight}  connected: {localNode.ConnectedCount}  unconnected: {localNode.UnconnectedCount}  mempool:{blockchain.GetMemoryPoolCount()}");
            if (printRemoteNode)
            {
                foreach (RemoteNode node in localNode.GetRemoteNodes().Take(Console.WindowHeight - 2))
                {
                    Console.WriteLine($"  ip: {node.Remote.Address}\tport: {node.Remote.Port}\tlisten: {node.ListenerPort}\theight: {node.Version?.StartHeight}");
                }
            }
        }

        private bool OnShowStatisticCommand(string[] args)
        {
            bool stop = false;
            int detail = args.Length >= 3 ? int.Parse(args[2]) : 0;
            if (detail > 0)
                PluginManager.EnableLog(false);

            Task.Run(() =>
            {
                while (!stop)
                {
                    Console.Clear();
                    ShowStatistic(Blockchain.Root, LocalNode.Root, detail > 0, detail - 1);
                    LocalNode[] appchainNodes = ZoroChainSystem.Singleton.GetAppChainLocalNodes();
                    foreach (var node in appchainNodes)
                    {
                        if (node != null && node.Blockchain != null)
                        {
                            Console.WriteLine("====================================================================");
                            ShowStatistic(node.Blockchain, node, detail > 0, detail - 1);
                        }
                    }
                    Thread.Sleep(1000);
                }
            });
            Console.ReadLine();
            stop = true;
            if (detail > 0)
                PluginManager.EnableLog(true);
            return true;
        }

        private void ShowStatistic(Blockchain blockchain, LocalNode localNode, bool printRemoteNode, int index)
        {
            Console.WriteLine($"block:{blockchain.Name} {blockchain.ChainHash.ToString()} {blockchain.Height}/{blockchain.HeaderHeight}  connected: {localNode.ConnectedCount}  unconnected: {localNode.UnconnectedCount}  mempool:{blockchain.GetMemoryPoolCount()}");
            if (printRemoteNode)
            {
                index = Math.Clamp(index, 0, 2);

                foreach (RemoteNode node in localNode.GetRemoteNodes().Take(Console.WindowHeight - 2))
                {
                    Console.WriteLine($"  ip: {node.Remote.Address}\ttimeout: {node.TaskTimeoutStat(index)}\tsend: {node.DataSendedStat(index)}\trequest: {node.DataRequestStat(index)}\trecv: {node.TaskCompletedStat(index)}");
                }
            }
        }

        protected internal override void OnStart(string[] args)
        {
            bool useRPC = false;
            bool disableLog = false;
            for (int i = 0; i < args.Length; i++)
                switch (args[i])
                {
                    case "/rpc":
                    case "--rpc":
                    case "-r":
                        useRPC = true;
                        break;
                    case "/disableLog":
                    case "--disableLog":
                    case "-logoff":
                        disableLog = true;
                        break;
                }

            if (disableLog)
            {
                PluginManager.EnableLog(false);
            }

            store = new LevelDBStore(Path.GetFullPath(Settings.Default.Paths.Chain));
            system = new ZoroChainSystem(store);

            if (Settings.Default.UnlockWallet.IsActive)
            {
                try
                {
                    Program.Wallet = OpenWallet(Settings.Default.UnlockWallet.Path, Settings.Default.UnlockWallet.Password);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine($"failed to open file \"{Settings.Default.UnlockWallet.Path}\"");
                }
            }
            system.StartNode(UInt160.Zero, Settings.Default.P2P.Port, Settings.Default.P2P.WsPort);
            if (Settings.Default.UnlockWallet.StartConsensus && Program.Wallet != null)
            {
                OnStartConsensusCommand(null);
            }
            if (useRPC)
            {
                system.StartRpc(IPAddress.Any,
                    Settings.Default.RPC.Port,
                    wallet: Program.Wallet,
                    sslCert: Settings.Default.RPC.SslCert,
                    password: Settings.Default.RPC.SslCertPassword);
            }
        }

        private bool OnStartCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "consensus":
                    return OnStartConsensusCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnStartConsensusCommand(string[] args)
        {
            if (NoWallet()) return true;
            ShowPrompt = false;
            system.StartConsensus(UInt160.Zero, Program.Wallet);
            return true;
        }

        protected internal override void OnStop()
        {
            system.Dispose();
            Console.WriteLine("Press enter key to quit.");
            Console.ReadLine();
        }

        private Wallet OpenWallet(string path, string password)
        {
            Wallet wallet = null;
            if (Path.GetExtension(path) == ".json")
            {
                NEP6Wallet nep6wallet = new NEP6Wallet(path);
                nep6wallet.Unlock(password);
                wallet = nep6wallet;

                ZoroChainSystem.Singleton.SetWallet(wallet);
            }

            return wallet;
        }

        private bool OnAppChainCommand(string[] args)
        {
            return appchainService.OnAppChainCommand(args);
        }
    }
}
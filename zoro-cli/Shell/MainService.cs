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
using Zoro.Wallets.SQLite;
using Zoro.Plugins;
using Neo.VM;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Threading;
using System.Threading.Tasks;
using System.Text;
using ECCurve = Zoro.Cryptography.ECC.ECCurve;
using ECPoint = Zoro.Cryptography.ECC.ECPoint;

namespace Zoro.Shell
{
    internal class MainService : ConsoleServiceBase
    {
        private const string PeerStatePath = "peers.dat";

        private LevelDBStore store;
        private ZoroSystem system;
        private WalletIndexer indexer;

        protected override string Prompt => "zoro";
        public override string ServiceName => "Zoro-CLI";

        private WalletIndexer GetIndexer()
        {
            if (indexer is null)
                indexer = new WalletIndexer(Settings.Default.Paths.Index);
            return indexer;
        }

        private static bool NoWallet()
        {
            if (Program.Wallet != null) return false;
            Console.WriteLine("You have to open the wallet first.");
            return true;
        }

        protected override bool OnCommand(string[] args)
        {
            if (system.PluginMgr.SendMessage(args)) return true;
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
                case "claim":
                    return OnClaimCommand(args);
                case "open":
                    return OnOpenCommand(args);
                case "rebuild":
                    return OnRebuildCommand(args);
                case "send":
                    return OnSendCommand(args);
                case "show":
                    return OnShowCommand(args);
                case "start":
                    return OnStartCommand(args);
                case "upgrade":
                    return OnUpgradeCommand(args);
                case "appchain":
                    return OnAppChainCommand(args);
                case "log":
                    return OnLogCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnBroadcastCommand(string[] args)
        {
            string command = args[1].ToLower();
            ISerializable payload = null;
            switch (command)
            {
                case "addr":
                    payload = AddrPayload.Create(NetworkAddressWithTime.Create(new IPEndPoint(IPAddress.Parse(args[2]), ushort.Parse(args[3])), NetworkAddressWithTime.NODE_NETWORK, DateTime.UtcNow.ToTimestamp()));
                    break;
                case "block":
                    if (args[2].Length == 64 || args[2].Length == 66)
                        payload = Blockchain.Root.GetBlock(UInt256.Parse(args[2]));
                    else
                        payload = Blockchain.Root.Store.GetBlock(uint.Parse(args[2]));
                    break;
                case "getblocks":
                case "getheaders":
                    payload = GetBlocksPayload.Create(UInt256.Parse(args[2]));
                    break;
                case "getdata":
                case "inv":
                    payload = InvPayload.Create(Enum.Parse<InventoryType>(args[2], true), UInt256.Parse(args[3]));
                    break;
                case "getdatagroup":
                case "invgroup":
                    payload = InvGroupPayload.Create(Enum.Parse<InventoryType>(args[2], true), args.Skip(3).Select(UInt256.Parse).ToArray());
                    break;
                case "tx":
                    payload = Blockchain.Root.GetTransaction(UInt256.Parse(args[2]));
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
            system.LocalNode.Tell(Message.Create(command, payload));
            return true;
        }

        private bool OnRelayCommand(string[] args)
        {
            if (args.Length < 2)
            {
                Console.WriteLine("You must input JSON object to relay.");
                return true;
            }
            var jsonObjectToRelay = string.Join(string.Empty, args.Skip(1));
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
                system.LocalNode.Tell(new LocalNode.Relay { Inventory = inventory });
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
                case "appchain":
                    return OnCreateAppChainCommand(args);
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
                case ".db3":
                    {
                        Program.Wallet = UserWallet.Create(GetIndexer(), path, password);
                        WalletAccount account = Program.Wallet.CreateAccount();
                        Console.WriteLine($"address: {account.Address}");
                        Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
                    }
                    break;
                case ".json":
                    {
                        NEP6Wallet wallet = new NEP6Wallet(GetIndexer(), path);
                        wallet.Unlock(password);
                        WalletAccount account = wallet.CreateAccount();
                        wallet.Save();
                        Program.Wallet = wallet;
                        Console.WriteLine($"address: {account.Address}");
                        Console.WriteLine($" pubkey: {account.GetKey().PublicKey.EncodePoint(true).ToHexString()}");
                    }
                    break;
                default:
                    Console.WriteLine("Wallet files in that format are not supported, please use a .json or .db3 file extension.");
                    break;
            }
            return true;
        }

        private bool OnCreateAppChainCommand(string[] args)
        {
            if (NoWallet()) return true;

            KeyPair keyPair = Program.Wallet.GetAccounts().FirstOrDefault(p => p.HasKey)?.GetKey();
            if (keyPair == null)
            {
                Console.WriteLine("error, can't get pubkey");
                return true;
            }

            string name = ReadString("name");
            if (name.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }

            int numSeeds = ReadInt("seed count");
            if (numSeeds <= 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }

            string[] seedList = new string[numSeeds];
            for (int i = 0; i < numSeeds; i++)
            {
                seedList[i] = ReadString("seed node address " + (i + 1).ToString());
            }

            int numValidators = ReadInt("validator count");
            if (numValidators < 4)
            {
                Console.WriteLine("cancelled, the input nmber is less then minimum validator count:4.");
                return true;
            }

            string[] validators = new string[numValidators];
            for (int i = 0; i < numValidators; i++)
            {
                validators[i] = ReadString("validator pubkey " + (i + 1).ToString());
            }

            ScriptBuilder sb = new ScriptBuilder();
            for (int i = 0; i < numValidators; i++)
            {
                sb.EmitPush(validators[i]);
            }
            sb.EmitPush(numValidators);
            for (int i = 0; i < numSeeds; i++)
            {
                sb.EmitPush(seedList[i]);
            }
            sb.EmitPush(numSeeds);
            sb.EmitPush(DateTime.UtcNow.ToTimestamp());
            sb.EmitPush(keyPair.PublicKey.EncodePoint(true));
            sb.EmitPush(name);

            UInt160 chainHash = sb.ToArray().ToScriptHash();
            sb.EmitPush(chainHash);
            sb.EmitSysCall("Zoro.AppChain.Create");

            RelayResultReason reason = SubmitInvocationTransaction(keyPair, sb.ToArray());

            if (reason == RelayResultReason.Succeed)
            {
                Console.WriteLine($"Appchain hash: {chainHash.ToArray().Reverse().ToHexString()}");
            }

            return true;
        }

        private static string GetRelayResult(RelayResultReason reason)
        {
            switch (reason)
            {
                case RelayResultReason.AlreadyExists:
                    return "Block or transaction already exists and cannot be sent repeatedly.";
                case RelayResultReason.OutOfMemory:
                    return "The memory pool is full and no more transactions can be sent.";
                case RelayResultReason.UnableToVerify:
                    return "The block cannot be validated.";
                case RelayResultReason.Invalid:
                    return "Block or transaction validation failed.";
                default:
                    return "Unkown error.";
            }
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

        private bool OnClaimCommand(string[] args)
        {
            if (NoWallet()) return true;

            Coins coins = new Coins(Program.Wallet, system);

            switch (args[1].ToLower())
            {
                case "gas":
                    if (args.Length > 2)
                    {
                        switch (args[2].ToLower())
                        {
                            case "all":
                                ClaimTransaction[] txs = coins.ClaimAll();
                                if (txs.Length > 0)
                                {
                                    foreach (ClaimTransaction tx in txs)
                                    {
                                        Console.WriteLine($"Tranaction Suceeded: {tx.Hash}");
                                    }
                                }
                                return true;
                            default:
                                return base.OnCommand(args);
                        }
                    }
                    else
                    {
                        ClaimTransaction tx = coins.Claim();
                        if (tx != null)
                        {
                            Console.WriteLine($"Tranaction Suceeded: {tx.Hash}");
                        }
                        return true;
                    }
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnShowGasCommand(string[] args)
        {
            if (NoWallet()) return true;

            Coins coins = new Coins(Program.Wallet, system);
            Console.WriteLine($"unavailable: {coins.UnavailableBonus().ToString()}");
            Console.WriteLine($"  available: {coins.AvailableBonus().ToString()}");
            return true;
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
            foreach (var item in Program.Wallet.GetCoins().Where(p => !p.State.HasFlag(CoinState.Spent)).GroupBy(p => p.Output.AssetId, (k, g) => new
            {
                Asset = Blockchain.Root.Store.GetAssets().TryGet(k),
                Balance = g.Sum(p => p.Output.Value),
                Confirmed = g.Where(p => p.State.HasFlag(CoinState.Confirmed)).Sum(p => p.Output.Value)
            }))
            {
                Console.WriteLine($"       id:{item.Asset.AssetId}");
                Console.WriteLine($"     name:{item.Asset.GetName()}");
                Console.WriteLine($"  balance:{item.Balance}");
                Console.WriteLine($"confirmed:{item.Confirmed}");
                Console.WriteLine();
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
                Program.Wallet = OpenWallet(GetIndexer(), path, password);
            }
            catch (CryptographicException)
            {
                Console.WriteLine($"failed to open file \"{path}\"");
            }
            return true;
        }

        private bool OnRebuildCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "index":
                    return OnRebuildIndexCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnRebuildIndexCommand(string[] args)
        {
            GetIndexer().RebuildIndex();
            return true;
        }

        private bool OnSendCommand(string[] args)
        {
            if (args.Length < 4 || args.Length > 5)
            {
                Console.WriteLine("error");
                return true;
            }
            if (NoWallet()) return true;
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
            UIntBase assetId;
            switch (args[1].ToLower())
            {
                case "neo":
                case "ans":
                    assetId = Blockchain.GoverningToken.Hash;
                    break;
                case "gas":
                case "anc":
                    assetId = Blockchain.UtilityToken.Hash;
                    break;
                default:
                    assetId = UIntBase.Parse(args[1]);
                    break;
            }
            UInt160 scriptHash = args[2].ToScriptHash();
            bool isSendAll = string.Equals(args[3], "all", StringComparison.OrdinalIgnoreCase);
            Transaction tx;
            if (isSendAll)
            {
                Coin[] coins = Program.Wallet.FindUnspentCoins().Where(p => p.Output.AssetId.Equals(assetId)).ToArray();
                tx = new ContractTransaction
                {
                    Attributes = new TransactionAttribute[0],
                    Inputs = coins.Select(p => p.Reference).ToArray(),
                    Outputs = new[]
                    {
                        new TransactionOutput
                        {
                            AssetId = (UInt256)assetId,
                            Value = coins.Sum(p => p.Output.Value),
                            ScriptHash = scriptHash
                        }
                    }
                };
            }
            else
            {
                AssetDescriptor descriptor = new AssetDescriptor(assetId);
                if (!BigDecimal.TryParse(args[3], descriptor.Decimals, out BigDecimal amount))
                {
                    Console.WriteLine("Incorrect Amount Format");
                    return true;
                }
                Fixed8 fee = args.Length >= 5 ? Fixed8.Parse(args[4]) : Fixed8.Zero;
                tx = Program.Wallet.MakeTransaction(null, new[]
                {
                    new TransferOutput
                    {
                        AssetId = assetId,
                        Value = amount,
                        ScriptHash = scriptHash
                    }
                }, fee: fee);
                if (tx == null)
                {
                    Console.WriteLine("Insufficient funds");
                    return true;
                }
            }
            ContractParametersContext context = new ContractParametersContext(tx, Blockchain.Root);
            Program.Wallet.Sign(context);
            if (context.Completed)
            {
                tx.Witnesses = context.GetWitnesses();
                Program.Wallet.ApplyTransaction(tx);
                system.LocalNode.Tell(new LocalNode.Relay { Inventory = tx });
                Console.WriteLine($"TXID: {tx.Hash}");
            }
            else
            {
                Console.WriteLine("SignatureContext:");
                Console.WriteLine(context.ToString());
            }
            return true;
        }

        private bool OnShowCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "gas":
                    return OnShowGasCommand(args);
                case "pool":
                    return OnShowPoolCommand(args);
                case "state":
                    return OnShowStateCommand(args);
                case "utxo":
                    return OnShowUtxoCommand(args);
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
            Task.Run(() =>
            {
                while (!stop)
                {
                    uint wh = 0;
                    if (Program.Wallet != null)
                        wh = (Program.Wallet.WalletHeight > 0) ? Program.Wallet.WalletHeight - 1 : 0;
                    Console.Clear();
                    ShowState(wh, Blockchain.Root, LocalNode.Root);
                    LocalNode[] appchainNodes = LocalNode.AppChainNodes();
                    foreach (var node in appchainNodes)
                    {
                        if (node != null)
                        {
                            Console.WriteLine("====================================================================");
                            ShowState(0, node.Blockchain, node);
                        }
                    }
                    Thread.Sleep(500);
                }
            });
            Console.ReadLine();
            stop = true;
            return true;
        }

        private void ShowState(uint wh, Blockchain blockchain, LocalNode localNode)
        {
            Console.WriteLine($"block:{blockchain.ChainHash.ToString()} {wh}/{blockchain.Height}/{blockchain.HeaderHeight}  connected: {localNode.ConnectedCount}  unconnected: {localNode.UnconnectedCount}");
            foreach (RemoteNode node in localNode.GetRemoteNodes().Take(Console.WindowHeight - 2))
                Console.WriteLine($"  ip: {node.Remote.Address}\tport: {node.Remote.Port}\tlisten: {node.ListenerPort}\theight: {node.Version?.StartHeight}");
        }

        private bool OnShowUtxoCommand(string[] args)
        {
            if (NoWallet()) return true;
            IEnumerable<Coin> coins = Program.Wallet.FindUnspentCoins();
            if (args.Length >= 3)
            {
                UInt256 assetId;
                switch (args[2].ToLower())
                {
                    case "neo":
                    case "ans":
                        assetId = Blockchain.GoverningToken.Hash;
                        break;
                    case "gas":
                    case "anc":
                        assetId = Blockchain.UtilityToken.Hash;
                        break;
                    default:
                        assetId = UInt256.Parse(args[2]);
                        break;
                }
                coins = coins.Where(p => p.Output.AssetId.Equals(assetId));
            }
            Coin[] coins_array = coins.ToArray();
            const int MAX_SHOW = 100;
            for (int i = 0; i < coins_array.Length && i < MAX_SHOW; i++)
                Console.WriteLine($"{coins_array[i].Reference.PrevHash}:{coins_array[i].Reference.PrevIndex}");
            if (coins_array.Length > MAX_SHOW)
                Console.WriteLine($"({coins_array.Length - MAX_SHOW} more)");
            Console.WriteLine($"total: {coins_array.Length} UTXOs");
            return true;
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
                PluginManager.DisableLog();
            }

            store = new LevelDBStore(Path.GetFullPath(Settings.Default.Paths.Chain));
            system = new ZoroSystem(UInt160.Zero, store, null);
            system.StartNode(Settings.Default.P2P.Port, Settings.Default.P2P.WsPort);
            system.StartAppChains();
            if (Settings.Default.UnlockWallet.IsActive)
            {
                try
                {
                    Program.Wallet = OpenWallet(GetIndexer(), Settings.Default.UnlockWallet.Path, Settings.Default.UnlockWallet.Password);
                }
                catch (CryptographicException)
                {
                    Console.WriteLine($"failed to open file \"{Settings.Default.UnlockWallet.Path}\"");
                }
                if (Settings.Default.UnlockWallet.StartConsensus && Program.Wallet != null)
                {
                    OnStartConsensusCommand(null);
                }
                system.StartAppChainsConsensus(Program.Wallet);
            }
            if (useRPC)
            {
                system.StartRpc(Settings.Default.RPC.BindAddress,
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
        }

        private bool OnUpgradeCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "wallet":
                    return OnUpgradeWalletCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnUpgradeWalletCommand(string[] args)
        {
            if (args.Length < 3)
            {
                Console.WriteLine("error");
                return true;
            }
            string path = args[2];
            if (Path.GetExtension(path) != ".db3")
            {
                Console.WriteLine("Can't upgrade the wallet file.");
                return true;
            }
            if (!File.Exists(path))
            {
                Console.WriteLine("File does not exist.");
                return true;
            }
            string password = ReadPassword("password");
            if (password.Length == 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }
            string path_new = Path.ChangeExtension(path, ".json");
            NEP6Wallet.Migrate(GetIndexer(), path_new, path, password).Save();
            Console.WriteLine($"Wallet file upgrade complete. New wallet file has been auto-saved at: {path_new}");
            return true;
        }

        private Wallet OpenWallet(WalletIndexer indexer, string path, string password)
        {
            Wallet wallet;
            if (Path.GetExtension(path) == ".db3")
            {
                wallet = UserWallet.Open(indexer, path, password);
            }
            else
            {
                NEP6Wallet nep6wallet = new NEP6Wallet(indexer, path);
                nep6wallet.Unlock(password);
                wallet = nep6wallet;
            }

            system.PluginMgr.SetWallet(wallet);
            return wallet;
        }

        private bool OnAppChainCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "seedlist":
                    return OnChangeAppChainSeedListCommand(args);
                case "validators":
                    return OnChangeAppChainValidatorsCommand(args);
                case "follow":
                    return OnFollowAppChainCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnChangeAppChainSeedListCommand(string[] args)
        {
            if (NoWallet()) return true;

            KeyPair keyPair = Program.Wallet.GetAccounts().FirstOrDefault(p => p.HasKey)?.GetKey();
            if (keyPair == null)
            {
                Console.WriteLine("error, can't get pubkey");
                return true;
            }

            string hashString = ReadString("appchain hash");
            if (hashString.Length != 40)
            {
                Console.WriteLine("cancelled");
                return true;
            }

            int numSeeds = ReadInt("seed count");
            if (numSeeds <= 0)
            {
                Console.WriteLine("cancelled");
                return true;
            }

            string[] seedList = new string[numSeeds];
            for (int i = 0; i < numSeeds; i++)
            {
                seedList[i] = ReadString("seed node address " + (i + 1).ToString());
            }

            ScriptBuilder sb = new ScriptBuilder();

            for (int i = 0; i < numSeeds; i++)
            {
                sb.EmitPush(seedList[i]);
            }
            sb.EmitPush(numSeeds);

            UInt160 chainHash = UInt160.Parse(hashString);
            sb.EmitPush(chainHash);
            sb.EmitSysCall("Zoro.AppChain.ChangeSeedList");

            SubmitInvocationTransaction(keyPair, sb.ToArray());
            return true;
        }

        private bool OnChangeAppChainValidatorsCommand(string[] args)
        {
            if (NoWallet()) return true;

            KeyPair keyPair = Program.Wallet.GetAccounts().FirstOrDefault(p => p.HasKey)?.GetKey();
            if (keyPair == null)
            {
                Console.WriteLine("error, can't get pubkey");
                return true;
            }

            string hashString = ReadString("appchain hash");
            if (hashString.Length != 40)
            {
                Console.WriteLine("cancelled");
                return true;
            }

            int numValidators = ReadInt("validator count");
            if (numValidators < 4)
            {
                Console.WriteLine("cancelled, the input nmber is less then minimum validator count:4.");
                return true;
            }

            string[] validators = new string[numValidators];
            for (int i = 0; i < numValidators; i++)
            {
                validators[i] = ReadString("validator pubkey " + (i + 1).ToString());
            }

            ScriptBuilder sb = new ScriptBuilder();
            for (int i = 0; i < numValidators; i++)
            {
                sb.EmitPush(validators[i]);
            }
            sb.EmitPush(numValidators);

            UInt160 chainHash = UInt160.Parse(hashString);
            sb.EmitPush(chainHash);
            sb.EmitSysCall("Zoro.AppChain.ChangeValidators");

            SubmitInvocationTransaction(keyPair, sb.ToArray());
            return true;
        }

        private RelayResultReason SubmitInvocationTransaction(KeyPair keyPair, byte[] script)
        {
            InvocationTransaction tx = new InvocationTransaction
            {
                ChainHash = UInt160.Zero,
                Version = 1,
                Script = script,
                Gas = Fixed8.Zero,
            };
            tx.Gas -= Fixed8.FromDecimal(10);
            if (tx.Gas < Fixed8.Zero) tx.Gas = Fixed8.Zero;
            tx.Gas = tx.Gas.Ceiling();

            tx.Inputs = new CoinReference[0];
            tx.Outputs = new TransactionOutput[0];

            tx.Attributes = new TransactionAttribute[1];
            tx.Attributes[0] = new TransactionAttribute();
            tx.Attributes[0].Usage = TransactionAttributeUsage.Script;
            tx.Attributes[0].Data = Contract.CreateSignatureRedeemScript(keyPair.PublicKey).ToScriptHash().ToArray();

            ContractParametersContext context = new ContractParametersContext(tx, Blockchain.Root);
            Program.Wallet.Sign(context);
            if (context.Completed)
            {
                tx.Witnesses = context.GetWitnesses();

                RelayResultReason reason = system.Blockchain.Ask<RelayResultReason>(tx).Result;

                if (reason != RelayResultReason.Succeed)
                {
                    Console.WriteLine($"Local Node could not relay transaction: {GetRelayResult(reason)}");
                }
                else
                {
                    Console.WriteLine($"Transaction has been accepted.");
                }
                return reason;
            }

            return RelayResultReason.UnableToVerify;
        }

        private bool OnFollowAppChainCommand(string[] args)
        {
            string hashString = ReadString("appchain hash");
            ushort port = (ushort)ReadInt("port");
            ushort wsport = (ushort)ReadInt("websocket port");
            int startConsensus = ReadInt("start consensus");

            bool exists = system.FollowAppChain(hashString, port, wsport);

            if (startConsensus == 1 && Program.Wallet != null)
            {
                system.StartAppChainConsensus(hashString, Program.Wallet);
            }

            if (exists)
            {
                AppChainSettings settings = new AppChainSettings(hashString, port, wsport, startConsensus == 1);

                AppChainsSettings.Default.Chains.Add(hashString, settings);

                SaveAppChainJson();
            }

            return true;
        }

        private void SaveAppChainJson()
        {
            using (FileStream fs = new FileStream("appchain.json", FileMode.Create, FileAccess.Write, FileShare.None))
            {
                using (StreamWriter writer = new StreamWriter(fs, Encoding.UTF8))
                {
                    writer.Write(AppChainsSettings.Default.ToJson().ToString());
                }
            }
        }

        private bool OnLogCommand(string[] args)
        {
            switch (args[1].ToLower())
            {
                case "enable":
                    return OnEnableLogCommand(args);
                case "disable":
                    return OnDisableLogCommand(args);
                default:
                    return base.OnCommand(args);
            }
        }

        private bool OnEnableLogCommand(string[] args)
        {
            string source = args[2];
            if (source == "all")
            {
                PluginManager.EnableLogAll();
            }
            else
            {
                PluginManager.EnableLogSource(source);
            }

            return true;
        }

        private bool OnDisableLogCommand(string[] args)
        {
            string source = args[2];
            if (source == "all")
            {
                PluginManager.DisableLog();
            }
            else
            {
                PluginManager.DisableLogSource(source);
            }

            return true;
        }
    }
}
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;

using SKGL;

namespace OfflineKeyValidationCSharp
{
    public class Program
    {
        static void Main(string[] args)
        {
            OfflineKeyValidationNew();
            OfflineKeyValidationWithPeriodicTimeCheck();
            OfflineKeyValidationOld();
        }


        public static void OfflineKeyValidationNew()
        {
            var RSAPublicKey = "<RSAKeyValue><Modulus>sGbvxwdlDbqFXOMlVUnAF5ew0t0WpPW7rFpI5jHQOFkht/326dvh7t74RYeMpjy357NljouhpTLA3a6idnn4j6c3jmPWBkjZndGsPL4Bqm+fwE48nKpGPjkj4q/yzT4tHXBTyvaBjA8bVoCTnu+LiC4XEaLZRThGzIn5KQXKCigg6tQRy0GXE13XYFVz/x1mjFbT9/7dS8p85n8BuwlY5JvuBIQkKhuCNFfrUxBWyu87CFnXWjIupCD2VO/GbxaCvzrRjLZjAngLCMtZbYBALksqGPgTUN7ZM24XbPWyLtKPaXF2i4XRR9u6eTj5BfnLbKAU5PIVfjIS+vNYYogteQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            var keyInfo = new KeyInformation().LoadFromFile("license.txt");

            if(keyInfo.HasValidSignature(RSAPublicKey)
                      .IsOnRightMachine()
                      .IsValid())
            {
                // the signature is correct so
                // the program can now launch
            }
            else
            {
                var machineCode = SKGL.SKM.getMachineCode(SKGL.SKM.getSHA1);
                keyInfo = SKGL.SKM.KeyActivation("3", "2", "751963", "MJAWL-ITPVZ-LKGAN-DLJDN", machineCode, secure: true, signMid: true, signDate: true);

                if(keyInfo.HasValidSignature(RSAPublicKey)
                          .IsOnRightMachine()
                          .IsValid())
                {
                    // the signature is correct and the key is valid.
                    // save to file.
                    keyInfo.SaveToFile("license.txt");

                    // the program can now launch
                }
                else
                {
                    // failure. close the program.
                }
            }

        }

        /// <summary>
        /// The only difference between this method and OfflineKeyValidationNew is that
        /// we make the activation files expire after a certain amount of days,
        /// which will force the user to connect to the Internet again. In this case,
        /// they can use the software offline for 30 days. 
        /// </summary>
        public static void OfflineKeyValidationWithPeriodicTimeCheck()
        {
            var RSAPublicKey = "<RSAKeyValue><Modulus>sGbvxwdlDbqFXOMlVUnAF5ew0t0WpPW7rFpI5jHQOFkht/326dvh7t74RYeMpjy357NljouhpTLA3a6idnn4j6c3jmPWBkjZndGsPL4Bqm+fwE48nKpGPjkj4q/yzT4tHXBTyvaBjA8bVoCTnu+LiC4XEaLZRThGzIn5KQXKCigg6tQRy0GXE13XYFVz/x1mjFbT9/7dS8p85n8BuwlY5JvuBIQkKhuCNFfrUxBWyu87CFnXWjIupCD2VO/GbxaCvzrRjLZjAngLCMtZbYBALksqGPgTUN7ZM24XbPWyLtKPaXF2i4XRR9u6eTj5BfnLbKAU5PIVfjIS+vNYYogteQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

            var keyInfo = new KeyInformation().LoadFromFile("license2.txt");

            if (keyInfo.HasValidSignature(RSAPublicKey, 30)
                       .IsOnRightMachine()
                       .IsValid())
            {
                // the signature is correct so
                // the program can now launch
            }
            else
            {
                var machineCode = SKGL.SKM.getMachineCode(SKGL.SKM.getSHA1);
                keyInfo = SKGL.SKM.KeyActivation("3", "2", "751963", "MJAWL-ITPVZ-LKGAN-DLJDN", machineCode, secure: true, signMid: true, signDate: true);

                if (keyInfo.HasValidSignature(RSAPublicKey)
                           .IsOnRightMachine()
                           .IsValid())
                {
                    // the signature is correct and the key is valid.
                    // save to file.
                    keyInfo.SaveToFile("license2.txt");

                    // the program can now launch
                }
                else
                {
                    // failure. close the program.
                }
            }

        }




        public static void OfflineKeyValidationOld()
        {
            // this key is found on https://serialkeymanager.com/User/Security
            var RSAPublicKey = "<RSAKeyValue><Modulus>js3sJGrsVz9FpmJfFDwNQvM418ntvcM6UyHIbQCblqZycJ8hyGOxbMG7NMToPPAEel/f1JIDfZfAFbXi4jaLOuyP4KmnKwlLnz9pHjauK4aoN/TUCR1bpxLaxkROzasJodMAqG9Jdty+Or/459BAdlx62RcxqjNxiBqwGaY6OsTfE0046BavS/Pgcv8fRzagi6VCprzn/QSezrn4COOyLPijwA3kPyZ1XOkjO1cT4SxFQOlzD1V2gtiLMPvMPXUH83YkpVgtb08bbzroyVUNC5GwLck8bPhL6kyJ/vxJPI7j71XrvGaPmDv2BJ3s0sI6x2Ny/dgtwt3GiEZk87YoIw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";


            var KeyInfo = SKGL.SKM.LoadKeyInformationFromFile("licenseinfo.txt");

            // if fileLoaded is true, there is already an "activation file", 
            // so no need to check with the server.

            if (KeyInfo != null)
            {
                if (CheckLocalFile(KeyInfo, RSAPublicKey))
                {
                    // everything is fine!
                }
                else
                {
                    KeyActivation();
                    // now, we should repeat the procedure, i.e. try to run keyactivation again.
                }

            }
            else
            {
                // we are here, we couldn't find a local activation file,
                // so we need to perform an activation/validation

                KeyActivation();

                // now, we should repeat the procedure, i.e. try to run offlinekeyvalidation again.
            }

        }


        public static SKGL.KeyInformation KeyActivation()
        {
            var machineCode = SKGL.SKM.getMachineCode(SKGL.SKM.getSHA1);
            var KeyInfo = SKGL.SKM.KeyActivation("3", "2", "751963", "MJAWL-ITPVZ-LKGAN-DLJDN", machineCode, secure: true, signMid: true, signDate: true);

            // saving key info into a file.
            // a good idea to have try catch here.
            if (KeyInfo != null)
            {
                SKGL.SKM.SaveKeyInformationToFile(KeyInfo, "licenseinfo.txt");
            }

            return KeyInfo;

        }

        public static bool CheckLocalFile(SKGL.KeyInformation KeyInfo, string RSAPublicKey)
        {
            bool result = false;

            // below, we want to make sure that the user has not
            // changed the key information file that is stored locally.
            if (SKGL.SKM.IsKeyInformationGenuine(KeyInfo, RSAPublicKey))
            {
                // if we've come so far, we know that
                // * the key has been checked against the database once
                // * the file with the key infromation has not been modified.

                // this is the validation
                if (KeyInfo != null)
                {
                    Console.WriteLine(KeyInfo.CreationDate);
                    //

                    // here, you can check if the activation file corresponds to the current machine code.

                    var machineCode = SKGL.SKM.getMachineCode(SKGL.SKM.getSHA1);


                    if (KeyInfo.Mid.Equals(machineCode))
                    {
                        // valid and on right computer!!!
                        result = true;
                    }

                }
                else
                {
                    // something is wrong. try activation again.

                }

            }
            else
            {
                // if we are here, the user has modified the activation file
                // you can either close the application
                // or attempt to activate the key again.
            }

            return result;
        }


    }

  
}

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
            OfflineKeyValidation();
        }

        public static void OfflineKeyValidation()
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

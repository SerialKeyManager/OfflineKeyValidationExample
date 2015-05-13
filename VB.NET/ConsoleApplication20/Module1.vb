Module Module1

    Sub Main()
        OfflineKeyValidation()
    End Sub

    Public Function OfflineKeyValidation()

        ' this key is found on https://serialkeymanager.com/User/Security
        Dim RSAPublicKey = "<RSAKeyValue><Modulus>js3sJGrsVz9FpmJfFDwNQvM418ntvcM6UyHIbQCblqZycJ8hyGOxbMG7NMToPPAEel/f1JIDfZfAFbXi4jaLOuyP4KmnKwlLnz9pHjauK4aoN/TUCR1bpxLaxkROzasJodMAqG9Jdty+Or/459BAdlx62RcxqjNxiBqwGaY6OsTfE0046BavS/Pgcv8fRzagi6VCprzn/QSezrn4COOyLPijwA3kPyZ1XOkjO1cT4SxFQOlzD1V2gtiLMPvMPXUH83YkpVgtb08bbzroyVUNC5GwLck8bPhL6kyJ/vxJPI7j71XrvGaPmDv2BJ3s0sI6x2Ny/dgtwt3GiEZk87YoIw==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>"



        Dim KeyInfo = SKGL.SKM.LoadKeyInformationFromFile("licenseinfo.txt")


        ' if fileLoaded is true, there is already an "activation file", 
        ' so no need to check with the server.

        If KeyInfo IsNot Nothing Then
            If CheckLocalFile(KeyInfo, RSAPublicKey) Then
                ' everything is fine!
            Else
                KeyActivation()
                ' now, we should repeat the procedure, i.e. try to run keyactivation again.
            End If

        Else
            ' we are here, we couldn't find a local activation file,
            ' so we need to perform an activation/validation

            KeyActivation()

            ' now, we should repeat the procedure, i.e. try to run offlinekeyvalidation again.
        End If

    End Function

    Public Function KeyActivation()
        Dim machineCode = SKGL.SKM.getMachineCode(AddressOf SKGL.SKM.getSHA1)
        Dim KeyInfo = SKGL.SKM.KeyActivation("3", "2", "751963", "MJAWL-ITPVZ-LKGAN-DLJDN", machineCode, secure:=True, signMid:=True, signDate:=True)

        ' saving key info into a file.
        ' a good idea to have try catch here.
        If KeyInfo IsNot Nothing Then
            SKGL.SKM.SaveKeyInformationToFile(KeyInfo, "licenseinfo.txt")
        End If

        Return KeyInfo

    End Function

    Public Function CheckLocalFile(ByVal KeyInfo As SKGL.KeyInformation, ByVal RSAPublicKey As String) As Boolean
        Dim result As Boolean = False

        ' below, we want to make sure that the user has not
        ' changed the key information file that is stored locally.
        If SKGL.SKM.IsKeyInformationGenuine(KeyInfo, RSAPublicKey) Then
            ' if we've come so far, we know that
            ' * the key has been checked against the database once
            ' * the file with the key infromation has not been modified.

            If KeyInfo IsNot Nothing Then ' this is the validation
                Console.WriteLine(KeyInfo.CreationDate) '

                ' here, you can check if the activation file corresponds to the current machine code.

                Dim machineCode = SKGL.SKM.getMachineCode(AddressOf SKGL.SKM.getSHA1)

                If KeyInfo.Mid.Equals(machineCode) Then

                    ' valid and on right computer!!!
                    result = True
                End If

            Else
                ' something is wrong. try activation again.

            End If

        Else
            ' if we are here, the user has modified the activation file
            ' you can either close the application
            ' or attempt to activate the key again.
        End If

        Return result
    End Function

End Module

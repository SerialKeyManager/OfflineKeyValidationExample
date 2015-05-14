# Offline Key Validation Example

This is an example demonstrating Offline Key Validation using Serial Key Manager Platform (serialkeymanager.com). Please read more here: http://support.serialkeymanager.com/kb/passive-key-validation/

### Why?
Offline key validation allows you to perform key validation periodically or only once. A key activation file will be signed by the server and validated each time you start your application using your public key that you can find here(https://serialkeymanager.com/User/Security)

### Structure
This repository contains examples in both VB.NET and C#.

### Remarks
Solutions can be made even safer by checking the activation date. It will be signed if you set signDate to true during activation and later check the time difference. If you would have any questions, pleas feel free to ask them here (http://support.serialkeymanager.com/forums/)

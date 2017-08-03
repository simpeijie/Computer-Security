# Secure File Store

An efficient and secure file store on a malicious storage server.

## Implementation

This project utilizes the crypto.py API provided for security-critical operations. Features of the file store system include:
1. Uploading/Downloading -- store files of different users and the users can store files of the same name - content of each file will not be overwritten. When an adversary modifies a valid user's file, an `IntegrityError` will be raised.
2. Sharing/Revoking -- files can be shared between users and access to a file can be revoked at any time. Sharing is also transitive in which any user with access to file can share it with other users. Any update performed on a file is immediately visible to all users.
3. Efficient Updates -- a small update to a file does not require reuploading of the entire file, rather only modification to parts of the file content is necessary. Such efficiency is made possible through the implementation of a Merkel tree.

For the full documentation of the code provided, please see the online
documentation at
https://www.icir.org/vern/cs161-sp17/projects/encrypted-file-store/docs/


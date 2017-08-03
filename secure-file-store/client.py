"""Secure client implementation

This is a skeleton file for you to build your secure file store client.

Fill in the methods for the class Client per the project specification.

You may add additional functions and classes as desired, as long as your
Client class conforms to the specification. Be sure to test against the
included functionality tests.
"""

import util
from base_client import BaseClient, IntegrityError
from crypto import CryptoError

def path_join(*strings):
    """Joins a list of strings putting a "/" between each.

    :param strings: a list of strings to join
    :returns: a string
    """
    return '/'.join(strings)

class Client(BaseClient):
    def __init__(self, storage_server, public_key_server, crypto_object,
                 username):
        super().__init__(storage_server, public_key_server, crypto_object,
                         username)
        keys = self.storage_server.get(path_join(self.username, "dir_keys"))
        # Client hasn't been initialized 
        if not keys:
            k_e, k_a = self.crypto.get_random_bytes(16), self.crypto.get_random_bytes(16)
            symm_keys = self.crypto.asymmetric_encrypt(message=util.to_json_string((k_e, k_a)), public_key=self.private_key.publickey())
            signature = self.crypto.asymmetric_sign(message=symm_keys, private_key=self.private_key)
            self.storage_server.put(path_join(self.username, "dir_keys"), util.to_json_string((symm_keys, signature)))

            dir_lst = util.to_json_string(dict())
            self.update_dir_lst(dir_lst, k_e, k_a)

            shared_dir_lst = util.to_json_string(dict())
            self.update_shared_dir(shared_dir_lst, k_e, k_a)

        # Else, verify the integrity of the keys
        else:
            try:
                symm_keys, signature = util.from_json_string(keys)
            except ValueError:
                raise IntegrityError()
            if not self.crypto.asymmetric_verify(message=symm_keys, signature=signature, public_key=self.private_key.publickey()):
                raise IntegrityError()
            # Can safely decrypt after checking the encrypted keys against the signature
            try:
                k_e, k_a = util.from_json_string(self.crypto.asymmetric_decrypt(symm_keys, self.private_key))
            except ValueError:
                raise IntegrityError()

        self.k_e, self.k_a = k_e, k_a

    # Takes DIR_LST as a string and put it in the storage server
    def update_dir_lst(self, dir_lst, k_e, k_a):
        IV = self.crypto.get_random_bytes(16)
        encrypted_dir_lst = IV + self.crypto.symmetric_encrypt(message=dir_lst, key=k_e, cipher_name='AES', mode_name='CBC', IV=IV)
        tag = self.crypto.message_authentication_code(message=encrypted_dir_lst, key=k_a, hash_name='SHA256')
        self.storage_server.put(path_join(self.username, "directory"), util.to_json_string((encrypted_dir_lst, tag)))

    # Takes SHARED_DIR as a string and put it in the storage server
    def update_shared_dir(self, shared_dir, k_e, k_a):
        IV = self.crypto.get_random_bytes(16)
        encrypted_shared_dir = IV + self.crypto.symmetric_encrypt(message=shared_dir, key=k_e, cipher_name='AES', mode_name='CBC', IV=IV)
        tag = self.crypto.message_authentication_code(message=encrypted_shared_dir, key=k_a, hash_name='SHA256')
        self.storage_server.put(path_join(self.username, "shared"), util.to_json_string((encrypted_shared_dir, tag)))

    # Checks the directory listing/file content to make sure it hasn't been tampered with
    def verify_server_data(self, ID, k_1, k_2):
        data = self.storage_server.get(ID)
        try:
            data, cur_tag = util.from_json_string(data)
        except ValueError:
            raise IntegrityError()
        tag = self.crypto.message_authentication_code(message=data, key=k_2, hash_name='SHA256')
        if tag != cur_tag:
            raise IntegrityError()

        decrypted_data = self.crypto.symmetric_decrypt(ciphertext=data[32:], key=k_1, cipher_name='AES', mode_name='CBC', IV=data[:32])
        try:
            data = util.from_json_string(decrypted_data)
        except ValueError:
            raise IntegrityError()

        return data

    def upload(self, name, value):
        # Replace with your implementation
        dir_lst = self.verify_server_data(path_join(self.username, "directory"), self.k_e, self.k_a)
        # Updating the data of file
        try:
            r, k_1, k_2, is_owner = dir_lst[name]
            if not is_owner:
                data = self.verify_server_data(r, k_1, k_2)
                r, k_1, k_2, io = data
            self.upload_helper(r, k_1, k_2, name, value, False)

        # Uploading file with NAME for the first time
        except KeyError:
            r = self.crypto.get_random_bytes(16)
            k_1 = self.crypto.get_random_bytes(16)
            k_2 = self.crypto.get_random_bytes(16)
            is_owner = True	

            dir_lst[name] = (r, k_1, k_2, is_owner)
            self.upload_helper(r, k_1, k_2, name, value, True)
            self.update_dir_lst(util.to_json_string(dir_lst), self.k_e, self.k_a)
        
        return True

    def upload_helper(self, r, k_1, k_2, name, value, is_first):
        message_blocks = [value[i:i+16000] for i in range(0, len(value), 16000)]
        new_length = len(message_blocks)
        new_leave_hashes = [self.crypto.cryptographic_hash(block, 'SHA256') for block in message_blocks]

        if is_first:
            # store length so that we can reconstruct the message during download
            # and leave hashes on server to build the necessary merkle tree
            metadata = util.to_json_string((new_length, new_leave_hashes))
            IV = self.crypto.get_random_bytes(16)
            encrypted_meta = IV + self.crypto.symmetric_encrypt(message=metadata, key=k_1, \
                                                                    cipher_name='AES', mode_name='CBC', IV=IV)
            tag = self.crypto.message_authentication_code(message=encrypted_meta, key=k_2, hash_name='SHA256')
            self.storage_server.put(r, util.to_json_string((encrypted_meta, tag)))
            self.store_message_on_server(message_blocks=message_blocks, r=r, k_1=k_1, k_2=k_2)
        else:
            data = self.storage_server.get(r)
            try:
                metadata, cur_tag = util.from_json_string(data)
            except ValueError:
                raise IntegrityError()
            except TypeError:
                raise IntegrityError()

            tag = self.crypto.message_authentication_code(message=metadata, key=k_2, hash_name='SHA256')
            if tag != cur_tag:
                raise IntegrityError()

            decrypted_meta = self.crypto.symmetric_decrypt(ciphertext=metadata[32:], key=k_1, \
                                                                cipher_name='AES', mode_name='CBC', IV=metadata[:32])
            try:
                length, cur_leave_hashes = util.from_json_string(decrypted_meta)
            except ValueError:
                raise IntegrityError()

            # need to perform efficient updates for files of the same length
            if length == new_length:
                cur_tree = self.build_merkle_tree(cur_leave_hashes)
                new_tree = self.build_merkle_tree(new_leave_hashes)
                # if the root hashes are the same, i.e. file content hasn't been changed, no update is needed
                if cur_tree[0][0] == new_tree[0][0]:
                    return 
                self.replace_message_blocks(cur_tree, new_tree, r, k_1, k_2, message_blocks, 0, 0)
            else:
                self.store_message_on_server(message_blocks=message_blocks, r=r, k_1=k_1, k_2=k_2)

            # store the metadata of the updated file
            metadata = util.to_json_string((new_length, new_leave_hashes))
            IV = self.crypto.get_random_bytes(16)
            encrypted_meta = IV + self.crypto.symmetric_encrypt(message=metadata, key=k_1, \
                                                                    cipher_name='AES', mode_name='CBC', IV=IV)
            tag = self.crypto.message_authentication_code(message=encrypted_meta, key=k_2, hash_name='SHA256')
            self.storage_server.put(r, util.to_json_string((encrypted_meta, tag)))

    def replace_message_blocks(self, cur_tree, new_tree, r, k_1, k_2, message_blocks, outer, inner):
        # at the leaves
        if len(cur_tree) == 1 and len(new_tree) == 1:
            # if the hashes differ, need to update old message block with new message block
            if cur_tree[outer][inner] != new_tree[outer][inner]:
                self.store_message_on_server(r=r, k_1=k_1, k_2=k_2, index=inner, \
                                                change=message_blocks[inner], update_all=False)
                cur_tree[outer][inner] = new_tree[outer][inner]
            # if a node has siblings, i.e. not at the root node, propagate changes in hash up to root
            if len(cur_tree[outer]) > 1:
                # left
                if inner % 2 == 0:
                    sib_hash = cur_tree[outer][inner + 1]
                    return self.crypto.cryptographic_hash(cur_tree[outer][inner] + sib_hash, 'SHA256')
                # right
                elif inner % 2 == 1:
                    sib_hash = cur_tree[outer][inner - 1]
                    return self.crypto.cryptographic_hash(sib_hash + cur_tree[outer][inner], 'SHA256')
            else:
                return cur_tree[outer][inner]

        # at inner nodes; have to continue traversing until we get to the leaves
        cur_left, new_left = cur_tree[outer+1][2*inner], new_tree[outer+1][2*inner]
        if cur_left != new_left:
            cur_tree[outer][inner] = self.replace_message_blocks(cur_tree[outer+1:], new_tree[outer+1:], r, k_1, k_2, message_blocks, outer, 2*inner)

        cur_right, new_right = cur_tree[outer+1][2*inner + 1], new_tree[outer+1][2*inner + 1]
        if cur_right != new_right:
            cur_tree[outer][inner] = self.replace_message_blocks(cur_tree[outer+1:], new_tree[outer+1:], r, k_1, k_2, message_blocks, outer, 2*inner + 1)

        if len(cur_tree[outer]) > 1:
            if inner % 2 == 0:
                sib_hash = cur_tree[outer][inner + 1]
                return self.crypto.cryptographic_hash(cur_tree[outer][inner] + sib_hash, 'SHA256')
            # right
            elif inner % 2 == 1:
                sib_hash = cur_tree[outer][inner - 1]
                return self.crypto.cryptographic_hash(sib_hash + cur_tree[outer][inner], 'SHA256')
        else:
            return cur_tree[outer][inner]

    # Builds a merkle tree as a list of list, with each inner list representing nodes on a layer
    def build_merkle_tree(self, nodes):
        tree = []
        layer = []
        for leaf in nodes:
            layer.append(leaf)
        i = 0
        length = len(layer)
        # check if length of leaves is a power of 2;
        # if not, add appropriate number of dummy nodes
        if (length - 1) & length != 0:
            while (2**i < length):
                i += 1
        layer.extend(['']*(2**i - length))
        tree.append(layer)

        while len(layer) != 1:
            new_layer = []
            for i in range(0, len(layer), 2):
                h = self.crypto.cryptographic_hash(layer[i] + layer[i+1], 'SHA256')
                new_layer.append(h)
            tree.append(new_layer)
            layer = new_layer

        tree = tree[::-1]
        return tree

    # Stores either a block or all blocks of message on server, depending on whether or not UPDATE_ALL is set
    # This function encrypts each block of the message and stores every block with ID's specified by r + index
    def store_message_on_server(self, message_blocks=None, r=None, k_1=None, k_2=None, \
                                    index=None, change=None, update_all=True):
        if update_all:
            for i in range(len(message_blocks)):
                IV = self.crypto.get_random_bytes(16)
                encrypted_block = IV + self.crypto.symmetric_encrypt(message=message_blocks[i], key=k_1, \
                                                                        cipher_name='AES', mode_name='CBC', IV=IV)
                tag = self.crypto.message_authentication_code(message=encrypted_block, key=k_2, hash_name='SHA256')
                self.storage_server.put(r + str(i), util.to_json_string((encrypted_block, tag)))
        else:
            IV = self.crypto.get_random_bytes(16)
            encrypted_block = IV + self.crypto.symmetric_encrypt(message=change, key=k_1, \
                                                                    cipher_name='AES', mode_name='CBC', IV=IV)
            tag = self.crypto.message_authentication_code(message=encrypted_block, key=k_2, hash_name='SHA256')
            self.storage_server.put(r + str(index), util.to_json_string((encrypted_block, tag)))

    def download(self, name):
        # Replace with your implementation
        dir_lst = self.verify_server_data(path_join(self.username, "directory"), self.k_e, self.k_a)
        try:
            r, k_1, k_2, is_owner = dir_lst[name]
            # Non-owners have different r, k_1, k_2 than owners do
            if not is_owner:
            	data = self.verify_server_data(r, k_1, k_2)
            	r, k_1, k_2, io = data

            data = self.storage_server.get(r)
            try:
                metadata, cur_tag = util.from_json_string(data)
            except ValueError:
                raise IntegrityError()
            except TypeError:
            	raise IntegrityError()
            tag = self.crypto.message_authentication_code(message=metadata, key=k_2, hash_name='SHA256')
            if tag != cur_tag:
                raise IntegrityError()

            metadata = self.crypto.symmetric_decrypt(ciphertext=metadata[32:], key=k_1, \
                                                        cipher_name='AES', mode_name='CBC', IV=metadata[:32])
            try:
                metadata = util.from_json_string(metadata)
            except ValueError:
                raise IntegrityError()
        except KeyError:
            return None

        length = metadata[0]
        message_blocks = []
        for i in range(length):
            data = self.storage_server.get(r + str(i))
            try:
                message_block, cur_tag = util.from_json_string(data)
            except ValueError:
                raise IntegrityError()
            except TypeError:
                raise IntegrityError()
            tag = self.crypto.message_authentication_code(message=message_block, key=k_2, hash_name='SHA256')
            if tag != cur_tag:
                raise IntegrityError()

            message_block = self.crypto.symmetric_decrypt(ciphertext=message_block[32:], key=k_1, \
                                                            cipher_name='AES', mode_name='CBC', IV=message_block[:32])
            message_blocks.append(message_block)

        return ''.join(message_blocks)

    def share(self, user, name):
        # Replace with your implementation (not needed for Part 1)
        # collect info for name file
        dir_lst = self.verify_server_data(path_join(self.username, "directory"), self.k_e, self.k_a)
        if name not in dir_lst:
        	return None
        r, k_1, k_2, is_owner = dir_lst[name]

        # check if current user is owner, to allow for revocation
        if is_owner:
        	# create new r and save rkk to shared dir lst at name, user
	        shared_dir = self.verify_server_data(path_join(self.username, "shared"), self.k_e, self.k_a)
	        r = self.crypto.get_random_bytes(16)
	        k_1 = self.crypto.get_random_bytes(16)
	        k_2 = self.crypto.get_random_bytes(16)
	        if name not in shared_dir:
	        	shared_dir[name] = dict()
	        shared_dir[name][user] = (r, k_1, k_2)
	        self.update_shared_dir(util.to_json_string(shared_dir), self.k_e, self.k_a)

	        # encrypt and tag dir_lst[name] and put on server at r
	        contents = util.to_json_string(dir_lst[name])
	        IV = self.crypto.get_random_bytes(16)
	        encrypted_contents = IV + self.crypto.symmetric_encrypt(message=contents, key=k_1, \
                                                                        cipher_name='AES', mode_name='CBC', IV=IV)
	        tag = self.crypto.message_authentication_code(message=encrypted_contents, key=k_2, hash_name='SHA256')
	        self.storage_server.put(r, util.to_json_string((encrypted_contents, tag)))

        # form message (rkk group) and encrypt with user's public key
        msg = util.to_json_string((r, k_1, k_2))
        user_key = self.pks.get_public_key(user)
        encrypted_msg = self.crypto.asymmetric_encrypt(message=msg, public_key=user_key)
        
        # sign message with own private key and return (M, S) as string
        signature = self.crypto.asymmetric_sign(message=encrypted_msg, private_key=self.private_key)
        return util.to_json_string((encrypted_msg, signature))

    def receive_share(self, from_username, newname, message):
        # Replace with your implementation (not needed for Part 1)
        # verify message came from from_username
        try:
            encrypted_msg, signature = util.from_json_string(message)
        except ValueError:
            raise IntegrityError

        from_public_key = self.pks.get_public_key(from_username)
        verified = self.crypto.asymmetric_verify(message=encrypted_msg, signature=signature, public_key=from_public_key)
        if not verified:
        	raise IntegrityError

        # decrypt message with private key
        msg = self.crypto.asymmetric_decrypt(ciphertext=encrypted_msg, private_key=self.private_key)
        try:
        	r, k_1, k_2 = util.from_json_string(msg)
        except ValueError:
        	raise IntegrityError

        # save to directory, marking is_owner as False
        dir_lst = self.verify_server_data(path_join(self.username, "directory"), self.k_e, self.k_a)
        is_owner = False
        dir_lst[newname] = (r, k_1, k_2, is_owner)
        self.update_dir_lst(util.to_json_string(dir_lst), self.k_e, self.k_a)

    def revoke(self, user, name):
        # check if the current user is the owner since only the owner has the right to revoke access
        dir_lst = self.verify_server_data(path_join(self.username, "directory"), self.k_e, self.k_a)
        if name not in dir_lst:
            return
        r, k_1, k_2, is_owner = dir_lst[name]
        if not is_owner:
            raise IntegrityError

        # remove user,name from shared_dir_lst
        shared_dir = self.verify_server_data(path_join(self.username, "shared"), self.k_e, self.k_a)
        if name not in shared_dir or user not in shared_dir[name].keys():
        	return
        user_dir = shared_dir[name]
        del user_dir[user]
        self.update_shared_dir(util.to_json_string(shared_dir), self.k_e, self.k_a)

        # get file contents, delete old file, and re-upload
        file_contents = self.download(name)
        self.storage_server.delete(r)
        del dir_lst[name]
        self.update_dir_lst(util.to_json_string(dir_lst), self.k_e, self.k_a)
        self.upload(name, file_contents)

        # encrypt and tag new rkk group for each user with access to the file
        dir_lst = self.verify_server_data(path_join(self.username, "directory"), self.k_e, self.k_a)
        contents = util.to_json_string(dir_lst[name])
        for u in user_dir.keys():
        	r, k_1, k_2 = user_dir[u]
        	old_data = self.verify_server_data(r, k_1, k_2)
	        IV = self.crypto.get_random_bytes(16)
	        encrypted_contents = IV + self.crypto.symmetric_encrypt(message=contents, key=k_1, cipher_name='AES', mode_name='CBC', IV=IV)
	        tag = self.crypto.message_authentication_code(message=encrypted_contents, key=k_2, hash_name='SHA256')
	        self.storage_server.put(r, util.to_json_string((encrypted_contents, tag)))

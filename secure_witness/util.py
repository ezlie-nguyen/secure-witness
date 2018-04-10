from base64 import urlsafe_b64encode, urlsafe_b64decode
from wsgiref.util import FileWrapper

from Crypto import Random
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Protocol.KDF import PBKDF2
from Crypto.PublicKey import RSA

from models import File, Folder, Bulletin, UserKeys, FileAccess


# modified from Python source code
class EncryptedFileWrapper(FileWrapper):
    def __init__(self, filelike, key=None, iv=None, blksize=8192):
        self.filelike = filelike
        self.blksize = blksize
        if key is not None and iv is not None:
            self.cipher = AES.new(key, AES.MODE_CFB, iv)
        else:
            self.cipher = None
        if hasattr(filelike, 'close'):
            self.close = filelike.close

    def __getitem__(self, key):
        data = self.filelike.read(self.blksize)
        if data:
            if self.cipher is not None:
                data = self.cipher.decrypt(data)
            return data
        raise IndexError

    def __iter__(self):
        return self

    def next(self):
        data = self.filelike.read(self.blksize)
        if data:
            if self.cipher is not None:
                data = self.cipher.decrypt(data)
            return data
        raise StopIteration


def create_encryption_params(password, rand=Random.new()):
    r, c, ep, iv, encryption_key = '', '', '', None, None
    if password is not None:
        salt = rand.read(AES.block_size)
        iterations = 15000
        iv = rand.read(AES.block_size)
        encryption_key = PBKDF2(password, salt, count=iterations)
        ep = '%s$%d$%s' % (urlsafe_b64encode(salt), iterations, urlsafe_b64encode(iv))
        r = rand.read(AES.block_size)
        c = AES.new(encryption_key, AES.MODE_CFB, iv).encrypt(r)
        r = urlsafe_b64encode(r)
        c = urlsafe_b64encode(c)
    return r, c, ep, iv, encryption_key


def get_encryption_params(password, r, c, ep):
    args = ep.split('$')
    salt = urlsafe_b64decode(str(args[0]))
    iterations = int(args[1])
    iv = urlsafe_b64decode(str(args[2]))
    encryption_key = PBKDF2(password, salt, count=iterations)
    r = urlsafe_b64decode(r)
    c = urlsafe_b64decode(c)
    c = AES.new(encryption_key, AES.MODE_CFB, iv).decrypt(c)
    return r, c, iv, encryption_key


def generate_keys_for_user(user, password, rand=Random.new()):
    key = RSA.generate(2048)
    r, c, ep, iv, encryption_key = create_encryption_params(password, rand)
    e_private_key = urlsafe_b64encode(AES.new(encryption_key, AES.MODE_CFB, iv).encrypt(key.exportKey('DER')))

    uk = UserKeys(
        user = user,
        public_key = urlsafe_b64encode(key.publickey().exportKey('DER')),
        private_key = e_private_key,
        rand = r,
        check = c,
        encryption_params = ep,
    )

    return uk


def give_file_access(author, reader, file, aes_key):
    rsa_key = RSA.importKey(urlsafe_b64decode(str(reader.userkeys.public_key)))
    rsa_cipher = PKCS1_OAEP.new(rsa_key)
    encrypted_aes_key = rsa_cipher.encrypt(aes_key)

    fa = FileAccess(
        reader = reader,
        file = file,
        key = urlsafe_b64encode(encrypted_aes_key),
    )
    fa.save()

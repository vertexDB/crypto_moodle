class Args:
    def __init__(self, input, output):
        self._input = input
        self._output = output

    def get_args(self):
        return self._input, self._output


# SHA algorithm
class Sha_args(Args):
    # 100%
    pass


# Blowfish algorithm
class Blow_args(Args):
    def __init__(self, input, output, key):
        super().__init__(input, output)
        self._key = key

    def get_args(self):
        return super().get_args(), self._key


# RSA algorithm
class Rsa_args(Args):
    pass


# DES algorithm
class Des_args(Args):
    def __init__(self, input, output, key):
        super().__init__(input, output)
        self._key = key

    def get_args(self):
        return super().get_args(), self._key


# Pass and hash algorithm
class Psh_args(Args):
    pass


# Diffie Hellman algorithm
class Dif_args(Args):
    pass


# MD5 algorithm
class Md5_args(Args):
    pass


# RC5 algorithm
class Rc5_args(Args):
    pass


# Kuznechik algorithm
class Kuz_args(Args):
    def __init__(self, input, output, key):
        super().__init__(input, output)
        self._key = key

    def get_args(self):
        return super().get_args(), self._key


# Feistel algorithm
class Fei_args(Args):
    pass


# Kerberos algorithm
class Ker_args(Args):
    pass


# GOST 28147-89 algorithm
class Gost_args(Args):
    def __init__(self, input, output, key):
        super().__init__(input, output)
        self._key = key

    def get_args(self):
        return super().get_args(), self._key


# Idea algorithm
class Ideal_args(Args):
    def __init__(self, input, output, key):
        super().__init__(input, output)
        self._key = key

    def get_args(self):
        return super().get_args(), self._key

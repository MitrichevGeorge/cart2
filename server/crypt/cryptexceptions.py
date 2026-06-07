class CryptException(Exception):
    pass

class MitmAttack(CryptException):
    pass

class InternalError(CryptException):
    pass

class NetworkError(CryptException):
    pass
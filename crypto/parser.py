import openpyxl
from utils.e_algorithm import EAlgorithm
from crypto.external.blowfish import blowfish
import crypto.external.des
from crypto.external.kuznechik import kuznechik
from crypto.external.gost import gost
from crypto.external.md5 import md5
from crypto.external.feistel import cipher
from crypto.external.rc import rc
from crypto.external.rsa import rsa
# enum(type of algorithm) bytes
# bytes -> openpyxl -> parse by enum type -> hash with args


def parser(e_alg, e_bytes): # e_alg - алгоритм, e_bytes - excel file
    wb = openpyxl.load_workbook(e_bytes)
    sheet = wb.active()
    b1, c1 = sheet['B1'], sheet['C1']
    data = []
    for i in sheet.iter_rows(min_row=3, max_row=3, values_only=True):
        data.append(i.value)
    match e_alg:
        case EAlgorithm.BLOWFISH:
            return True
        case EAlgorithm.MD5:
            return True
            return True
        case EAlgorithm.KERBEROS:
            return True
        case EAlgorithm.GOST:
            return True
        case EAlgorithm.IDEA:
            return True
        case EAlgorithm.FEISTELL:
            return True
        case EAlgorithm.RC5:
            return True
        case EAlgorithm.PASSNHASH:
            return True
        case EAlgorithm.DES:
            return True
        case EAlgorithm.RSA:
            return True
        case EAlgorithm.SHA:
            return True
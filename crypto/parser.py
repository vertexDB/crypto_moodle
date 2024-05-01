import openpyxl
from utils.e_algorithm import EAlgorithm
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
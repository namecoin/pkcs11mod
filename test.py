#!/usr/bin/env python3.6
import ctypes
lib = ctypes.CDLL("./libnamecoin.so")
x=21
print("C_Initialize:", lib.C_Initialize())
print("C_GetInfo:", lib.C_GetInfo())
print("C_Initialize:", lib.C_Initialize())
print("C_GetSlotList:", lib.C_GetSlotList())
print("C_GetTokeninfo:", lib.C_GetTokenInfo())
print("C_OpenSession:", lib.C_OpenSession())
print("C_GetMechanismList:", lib.C_GetMechanismList())
print("C_GetFunctionList:", lib.C_GetFunctionList())


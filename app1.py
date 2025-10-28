import ctypes
dll = ctypes.WinDLL(r"C:\Windows\System32\CryptoIDA_pkcs11.dll")
print("Has C_OpenSession:", hasattr(dll, "C_OpenSession"))
print("Has C_GetFunctionList:", hasattr(dll, "C_GetFunctionList"))

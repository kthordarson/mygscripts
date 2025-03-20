import ghidra.app.script.GhidraScript
import ghidra.program.model.symbol.SourceType

class FixMsiFunctionSignatures(GhidraScript):
    def run(self):
        # List of MSI function signatures to fix
        msi_functions = [
            ("MsiCloseHandle", "int MsiCloseHandle(MSIHANDLE hAny)"),
            ("MsiOpenPackage", "UINT MsiOpenPackage(LPCSTR szPackagePath, MSIHANDLE *phProduct)"),
            ("MsiGetProductCode", "UINT MsiGetProductCode(LPCSTR szComponent, LPSTR lpBuf)"),
            ("MsiInstallProduct", "UINT MsiInstallProduct(LPCSTR szPackagePath, LPCSTR szCommandLine)"),
            ("MsiConfigureProduct", "UINT MsiConfigureProduct(LPCSTR szProduct, INSTALLSTATE eInstallState, INSTALLLEVEL iInstallLevel)"),
            ("MsiReinstallProduct", "UINT MsiReinstallProduct(LPCSTR szProduct, DWORD dwReinstallMode)"),
            ("MsiApplyPatch", "UINT MsiApplyPatch(LPCSTR szPatchPackage, LPCSTR szInstallPackage, INSTALLTYPE eInstallType, LPCSTR szCommandLine)"),
            ("MsiQueryFeatureState", "INSTALLSTATE MsiQueryFeatureState(LPCSTR szProduct, LPCSTR szFeature)"),
            ("MsiGetFeatureUsage", "UINT MsiGetFeatureUsage(LPCSTR szProduct, LPCSTR szFeature, LPDWORD pdwUseCount, WORD *pwDateUsed)")
        ]

        # Iterate over each function and fix the signature
        for func_name, func_signature in msi_functions:
            func = getGlobalFunctions(func_name)
            if func:
                func.setSignature(func_signature, SourceType.USER_DEFINED)
                print(f"Fixed signature for {func_name}")

# Execute the script
FixMsiFunctionSignatures().run()
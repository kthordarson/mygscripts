# Ghidra Python script to apply D3DX9_43.dll function and data type signatures
from ghidra.program.model.data import StructureDataType, FloatDataType, PointerDataType, ArrayDataType
from ghidra.program.model.data import FunctionDefinitionDataType, ParameterDefinitionImpl
from ghidra.program.model.data import IntegerDataType, UnsignedIntegerDataType, CharDataType
from ghidra.program.model.symbol import SourceType
from ghidra.util.task import TaskMonitor

def define_d3dx_types():
    """Define D3DX9 data structures in Ghidra."""
    dtm = currentProgram.getDataTypeManager()
    
    # D3DXVECTOR3 (12 bytes: float x, y, z)
    vec3 = StructureDataType("D3DXVECTOR3", 12)
    vec3.add(FloatDataType(), 4, "x", "X coordinate")
    vec3.add(FloatDataType(), 4, "y", "Y coordinate")
    vec3.add(FloatDataType(), 4, "z", "Z coordinate")
    dtm.addDataType(vec3, None)
    
    # D3DXMATRIX (64 bytes: 4x4 float matrix)
    matrix = StructureDataType("D3DXMATRIX", 64)
    for i in range(4):
        for j in range(4):
            matrix.add(FloatDataType(), 4, "m{0}{1}".format(i, j), "Matrix element [{0}][{1}]".format(i, j))
    dtm.addDataType(matrix, None)
    
    # Pointer types
    vec3_ptr = PointerDataType(vec3)
    matrix_ptr = PointerDataType(matrix)
    dtm.addDataType(vec3_ptr, None)
    dtm.addDataType(matrix_ptr, None)
    
    return {
        "D3DXVECTOR3": vec3,
        "D3DXMATRIX": matrix,
        "D3DXVECTOR3*": vec3_ptr,
        "D3DXMATRIX*": matrix_ptr
    }

def create_function_signature(name, return_type, params):
    """Create a function signature for Ghidra."""
    func_def = FunctionDefinitionDataType(name)
    func_def.setReturnType(return_type)
    param_list = []
    for i, (param_type, param_name) in enumerate(params):
        param = ParameterDefinitionImpl(param_name, param_type, "Parameter {0}".format(i + 1))
        param_list.append(param)
    func_def.setArguments(param_list)
    return func_def

def apply_d3dx_signatures(types):
    """Apply function signatures to D3DX9 imports, searching globally."""
    symbol_table = currentProgram.getSymbolTable()
    
    # Common D3DX9 functions from your code
    signatures = [
        ("D3DXMatrixRotationX", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (FloatDataType(), "Angle")
        ]),
        ("D3DXMatrixRotationY", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (FloatDataType(), "Angle")
        ]),
        ("D3DXMatrixRotationZ", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (FloatDataType(), "Angle")
        ]),
        ("D3DXMatrixMultiply", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (types["D3DXMATRIX*"], "pM1"), 
            (types["D3DXMATRIX*"], "pM2")
        ]),
        ("D3DXMatrixTranslation", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (FloatDataType(), "x"), 
            (FloatDataType(), "y"), 
            (FloatDataType(), "z")
        ]),
        ("D3DXMatrixLookAtLH", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (types["D3DXVECTOR3*"], "pEye"), 
            (types["D3DXVECTOR3*"], "pAt"), 
            (types["D3DXVECTOR3*"], "pUp")
        ]),
        ("D3DXMatrixInverse", types["D3DXMATRIX*"], [
            (types["D3DXMATRIX*"], "pOut"), 
            (PointerDataType(FloatDataType()), "pDeterminant"), 
            (types["D3DXMATRIX*"], "pM")
        ]),
        ("D3DXVec3Normalize", types["D3DXVECTOR3*"], [
            (types["D3DXVECTOR3*"], "pOut"), 
            (types["D3DXVECTOR3*"], "pV")
        ]),
        ("D3DXLoadMeshFromXA", IntegerDataType(), [
            (PointerDataType(CharDataType()), "pFilename"), 
            (UnsignedIntegerDataType(), "Options"), 
            (PointerDataType(), "pD3DDevice"), 
            (PointerDataType(), "pAdjacency"), 
            (PointerDataType(), "pMaterials"), 
            (PointerDataType(), "pEffectInstances"), 
            (PointerDataType(UnsignedIntegerDataType()), "pNumMaterials"), 
            (PointerDataType(), "ppMesh")
        ]),
        ("D3DXGetDeclVertexSize", UnsignedIntegerDataType(), [
            (PointerDataType(), "pDecl"), 
            (UnsignedIntegerDataType(), "Stream")
        ]),
        ("D3DXComputeBoundingBox", IntegerDataType(), [
            (PointerDataType(), "pFirstPosition"), 
            (UnsignedIntegerDataType(), "NumVertices"), 
            (PointerDataType(), "pVertexData"), 
            (types["D3DXVECTOR3*"], "pMin"), 
            (types["D3DXVECTOR3*"], "pMax")
        ]),
        ("D3DXComputeBoundingSphere", IntegerDataType(), [
            (PointerDataType(), "pFirstPosition"), 
            (UnsignedIntegerDataType(), "NumVertices"), 
            (PointerDataType(), "pVertexData"), 
            (types["D3DXVECTOR3*"], "pCenter"), 
            (PointerDataType(FloatDataType()), "pRadius")
        ]),
        ("D3DXCreateTextureFromFileA", IntegerDataType(), [
            (PointerDataType(), "pDevice"), 
            (PointerDataType(CharDataType()), "pSrcFile"), 
            (PointerDataType(), "ppTexture")
        ])
    ]

    # Search globally and filter by D3DX-like namespaces
    found_any = False
    for name, ret_type, params in signatures:
        symbols = symbol_table.getSymbols(name)  # Global search
        symbol_iter = iter(symbols)
        try:
            symbol = symbol_iter.next()  # First match
            ns_name = symbol.getParentNamespace().getName()
            if "D3DX9" in ns_name:  # Check if it's a D3DX9 DLL
                if symbol.getSymbolType().toString()=='Function':  # symbol.getSymbolType().isFunction():
                    func = getFunctionAt(symbol.getAddress())
                    if func:
                        func_def = create_function_signature(name, ret_type, params)
                        func.setCustomVariableStorage(False)
                        func.setReturnType(ret_type, SourceType.USER_DEFINED)
                        func.replaceParameters(func_def.getArguments(), True, SourceType.USER_DEFINED)
                        print("Applied signature for {0} at {1} in namespace {2}".format(
                            name, symbol.getAddress(), ns_name))
                        found_any = True
                    else:
                        print("Symbol {0} at {1} is not a function".format(name, symbol.getAddress()))
                else:
                    print("Symbol {0} found but not a function in {1}".format(name, ns_name))
            else:
                print("Symbol {0} found in {1} but not a D3DX9 namespace".format(name, ns_name))
        except StopIteration:
            print("Symbol {0} not found in any namespace".format(name))
    
    if not found_any:
        print("No D3DX9 functions found. Check Symbol Tree under Imports for D3DX9_* DLLs.")

def main():
    """Main script entry point."""
    types = define_d3dx_types()
    apply_d3dx_signatures(types)
    print("Finished applying D3DX9 signatures.")

if __name__ == "__main__":
    main()
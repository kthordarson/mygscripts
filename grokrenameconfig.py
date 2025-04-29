RENAME_CONFIG = [
    {
        'function_address': 0x1000dbcc,
        'new_function_name': 'InitializeSystemConfig',
        'return_type': 'SystemConfig*',
        'parameters': [],  # No parameters for this function
        'variables': [
            {'old_name': 'uVar1', 'new_name': 'tempFlag', 'type': 'uint8_t'},
            {'old_name': 'puVar2', 'new_name': 'tempPtr', 'type': 'void*'},
            {'old_name': 'pvVar3', 'new_name': 'allocatedMemory', 'type': 'void*'},
            {'old_name': 'puVar4', 'new_name': 'fieldPtr', 'type': 'void*'},
            {'old_name': 'sVar5', 'new_name': 'stringLength', 'type': 'size_t'},
            {'old_name': 'puVar6', 'new_name': 'bufferPtr', 'type': 'uint8_t*'},
            {'old_name': 'iVar7', 'new_name': 'loopCounter', 'type': 'int'},
            {'old_name': 'extraout_ECX', 'new_name': 'this', 'type': 'SystemConfig*'},
        ]
    },
    {
        'function_address': 0x10008d7c,
        'new_function_name': 'CleanupStringArray',
        'return_type': 'void',
        'parameters': [
            {'name': 'this', 'type': 'StringContainer*', 'index': 0}
        ],
        'variables': [
            {'old_name': 'pbVar1', 'new_name': 'endPtr', 'type': 'std::string*'},
            {'old_name': 'this', 'new_name': 'currentStr', 'type': 'std::string*'}
        ]
    },
    {
        'function_address': 0x1000601c,
        'new_function_name': 'ReleaseBufferElement',
        'return_type': 'void',
        'parameters': [
            {'name': 'this', 'type': 'BufferManager*', 'index': 0}
        ],
        'variables': [
            {'old_name': 'puVar1', 'new_name': 'currentPtr', 'type': 'void**'},
            {'old_name': 'piVar2', 'new_name': 'nextPtr', 'type': 'int*'},
            {'old_name': 'iVar3', 'new_name': 'baseAddress', 'type': 'int'},
            {'old_name': 'iVar4', 'new_name': 'tempValue', 'type': 'int'}
        ]
    },
    {
        'function_address': 0x10006005,
        'new_function_name': 'AdvanceBuffer',
        'return_type': 'void',
        'parameters': [
            {'name': 'this', 'type': 'BufferManager*', 'index': 0}
        ],
        'variables': [
            {'old_name': 'piVar1', 'new_name': 'counterPtr', 'type': 'int*'}
        ]
    },
    {
        'function_address': 0x1000b8b0,  # Placeholder, adjust if different
        'new_function_name': 'ClientLoginExtended',
        'return_type': 'int',
        'parameters': [
            {'name': 'this', 'type': 'ClientContext*', 'index': 0},
            {'name': 'username', 'type': 'char*', 'index': 1},
            {'name': 'sessionFlags', 'type': 'uint32_t', 'index': 2},
            {'name': 'password', 'type': 'char*', 'index': 3},
            {'name': 'serverAddress', 'type': 'char*', 'index': 4},
            {'name': 'timeout', 'type': 'uint32_t', 'index': 5}
        ],
        'variables': [
            {'old_name': 'sVar1', 'new_name': 'stringLength', 'type': 'size_t'},
            {'old_name': 'iVar2', 'new_name': 'loginResult', 'type': 'int'},
            {'old_name': 'puVar3', 'new_name': 'bufferPtr', 'type': 'uint32_t*'},
            {'old_name': 'local_134', 'new_name': 'usernameBuffer', 'type': 'char'},
            {'old_name': 'local_133', 'new_name': 'usernameMetadata', 'type': 'uint32_t'},
            {'old_name': 'local_d0', 'new_name': 'passwordBuffer', 'type': 'char'},
            {'old_name': 'local_cf', 'new_name': 'passwordMetadata', 'type': 'uint32_t'},
            {'old_name': 'local_6c', 'new_name': 'serverAddressBuffer', 'type': 'char'},
            {'old_name': 'local_6b', 'new_name': 'serverAddressMetadata', 'type': 'uint32_t'},
            {'old_name': 'local_8', 'new_name': 'reservedField', 'type': 'uint32_t'}
        ]
    },
    {
        'function_address': 0x1000365a,
        'new_function_name': 'ProcessCommand',
        'return_type': 'int',
        'parameters': [
            {'name': 'this', 'type': 'CommandProcessor*', 'index': 0}
        ],
        'variables': [
            {'old_name': 'puVar1', 'new_name': 'bufferPtr', 'type': 'uint32_t*'},
            {'old_name': 'iVar2', 'new_name': 'tempValue', 'type': 'int'},
            {'old_name': 'iVar3', 'new_name': 'commandId', 'type': 'int'},
            {'old_name': 'iVar4', 'new_name': 'statusCode', 'type': 'int'},
            {'old_name': 'DVar5', 'new_name': 'waitResult', 'type': 'DWORD'},
            {'old_name': 'extraout_ECX', 'new_name': 'this', 'type': 'CommandProcessor*'},
            {'old_name': 'unaff_EBP', 'new_name': 'context', 'type': 'CommandContext*'},
            {'old_name': 'bVar6', 'new_name': 'isEqual', 'type': 'bool'},
            {'old_name': 'bVar7', 'new_name': 'isLess', 'type': 'bool'},
            {'old_name': 'bVar8', 'new_name': 'isBorrow', 'type': 'bool'}
        ]
    }
]
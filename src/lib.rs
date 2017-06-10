#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

#[link(name = "Secur32")]
pub mod node_sspi {
    use std::ptr;
    use std::ffi::CString;
    use std::os::raw::c_void;

    //include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
    include!("../bindings.rs");

    const max_message_size: usize = 12000;

    pub struct SecurityContext {
        pub context_handle: _SecHandle,
        pub credentials_handle: _SecHandle,
        pub token: Vec<u8>
    }

    fn create_expiry() -> LARGE_INTEGER {
        LARGE_INTEGER { 
            __bindgen_anon_1: Default::default(),
            u: Default::default(),
            QuadPart: Default::default(),
            bindgen_union_field: 0
        }
    }

    fn acquire_credentials_handle(auth_type: String) -> _SecHandle {
        let principal: LPSTR = ptr::null_mut();
        let cred_type: u32 = 2; // Outbound
        let logonId: *mut c_void = ptr::null_mut();
        let authData: *mut c_void = ptr::null_mut();
        let getKeyFunction: SEC_GET_KEY_FN = None;
        let getKeyArgument: *mut c_void = ptr::null_mut();

        let auth_type_cstr = CString::new(auth_type.into_bytes()).unwrap();

        let mut cred_handle = _SecHandle {
            dwLower: 0,
            dwUpper: 0
        };

        unsafe {
            let auth_type_ptr = auth_type_cstr.into_raw();
            let security_status = AcquireCredentialsHandleA(principal, auth_type_ptr, cred_type, logonId, authData, getKeyFunction, getKeyArgument, &mut cred_handle, &mut create_expiry());
            match security_status {
                0 => println!("Success!"),
                val => println!("Unknown result: {}", val)
            }
        }
        cred_handle
    }

    pub fn initialize_security_context(auth_type: String, auth_spn: String) -> SecurityContext {
        let mut output_buffer_vec: Vec<u8>  = Vec::with_capacity(max_message_size);

        let mut context_handle = _SecHandle {
            dwLower: 0,
            dwUpper: 0
        };

        let cred_handle = acquire_credentials_handle(auth_type);

        let auth_spn_cstr = CString::new(auth_spn.into_bytes()).unwrap();
        unsafe {
            let null_context_handle: PCtxtHandle = ptr::null_mut();

            let auth_spn_ptr = auth_spn_cstr.into_raw();
            let message_attribute: u32 = 2048; // ISC_REQ_CONNECTION -- default value; security context will not format messages
            let data_representation: u32 = 0x00000010; // SECURITY_NATIVE_DREP
            let mut context_attributes: u32 = 0;

            let mut mut_cred_handle = _SecHandle {
                dwLower: cred_handle.dwLower,
                dwUpper: cred_handle.dwUpper
            };

            let input_buffer_desc: *mut _SecBufferDesc = ptr::null_mut();

            let mut output_buffer = _SecBuffer {
                cbBuffer: max_message_size as u32,
                BufferType: 2, // SECBUFFER_TOKEN
                pvBuffer: output_buffer_vec.as_mut_ptr() as *mut c_void
            };
            let mut output_buffer_desc = _SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: &mut output_buffer
            };
            let init_result = InitializeSecurityContextA(&mut mut_cred_handle, null_context_handle, auth_spn_ptr, message_attribute, 0, data_representation, 
                input_buffer_desc, 0, &mut context_handle, &mut output_buffer_desc, &mut context_attributes, &mut create_expiry());
            check_result_code(init_result, context_handle, output_buffer_desc);

            output_buffer_vec.set_len(output_buffer.cbBuffer as usize);
        }
        SecurityContext {
            context_handle: context_handle,
            token: output_buffer_vec,
            credentials_handle: cred_handle
        }
    }

    pub fn initialize_security_context_with_input(auth_spn: String, mut context: SecurityContext) -> SecurityContext {
        let mut output_buffer_vec: Vec<u8>  = Vec::with_capacity(max_message_size);
        let auth_spn_cstr = CString::new(auth_spn.into_bytes()).unwrap();

        unsafe {
            let auth_spn_ptr = auth_spn_cstr.into_raw();
            let message_attribute: u32 = 2048; // ISC_REQ_CONNECTION -- default value; security context will not format messages
            let data_representation: u32 = 0x00000010; // SECURITY_NATIVE_DREP
            let mut context_attributes: u32 = 0;

            let mut input_buffer = _SecBuffer {
                cbBuffer: max_message_size as u32,
                BufferType: 2, // SECBUFFER_TOKEN
                pvBuffer: context.token.as_mut_ptr() as *mut c_void
            };
            let mut input_buffer_desc = _SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: &mut input_buffer
            };

            let mut output_buffer = _SecBuffer {
                cbBuffer: max_message_size as u32,
                BufferType: 2, // SECBUFFER_TOKEN
                pvBuffer: output_buffer_vec.as_mut_ptr() as *mut c_void
            };
            let mut output_buffer_desc = _SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: &mut output_buffer
            };

            let init_result = InitializeSecurityContextA(&mut context.credentials_handle, &mut context.context_handle, auth_spn_ptr, message_attribute, 0, data_representation, 
                &mut input_buffer_desc, 0, &mut context.context_handle, &mut output_buffer_desc, &mut context_attributes, &mut create_expiry());
            check_result_code(init_result, context.context_handle, output_buffer_desc);

            output_buffer_vec.set_len(output_buffer.cbBuffer as usize);
        }
        SecurityContext {
            context_handle: context.context_handle,
            token: output_buffer_vec,
            credentials_handle: context.credentials_handle
        }
    }

    unsafe fn check_result_code(result_code: i32, mut context_handle: _SecHandle, mut buffer_desc: _SecBufferDesc) {
        match result_code {
                590612 | 590611 => {
                    if CompleteAuthToken(&mut context_handle, &mut buffer_desc) > 0 {
                        println!("Success completing auth token!");
                    }
                    else {
                        println!("Failed to complete token!");
                    }
                },
                val if (val >= 0) => println!("Success initializing token!"),
                val => println!("Unknown result: {}", val)
            }
    }
}
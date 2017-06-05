#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]

// extern crate libc;

#[link(name = "Secur32")]
pub mod node_sspi {
    use std::ptr;
    use std::ffi::CString;
    use std::os::raw::c_void;

    //include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
    include!("../bindings.rs");

    //#[link(name = "Secur32")]
    pub fn acquire_credentials_handle(auth_type: String, auth_spn: String) -> PCredHandle {
        let cred_type: u32 = 2; // Outbound
        let null_ptr: LPSTR = ptr::null_mut();

        let logonId: *mut c_void = ptr::null_mut();
        let authData: *mut c_void = ptr::null_mut();
        let getKeyFunction: SEC_GET_KEY_FN = None;
        let getKeyArgument: *mut c_void = ptr::null_mut();

        let mut expiry = LARGE_INTEGER { 
            __bindgen_anon_1: Default::default(),
            u: Default::default(),
            QuadPart: Default::default(),
            bindgen_union_field: 0
         };

        let mut cred_handle = _SecHandle {
            dwLower: 0,
            dwUpper: 0
        };
        let auth_type_bytes = auth_type.into_bytes();
        let auth_type_cstr = CString::new(auth_type_bytes).unwrap();

        let auth_spn_cstr = CString::new(auth_spn.into_bytes()).unwrap();
        unsafe {
            let auth_type_ptr = auth_type_cstr.into_raw();
            let security_status = AcquireCredentialsHandleA(null_ptr, auth_type_ptr, cred_type, logonId, authData, getKeyFunction, getKeyArgument, &mut cred_handle, &mut expiry);

            match security_status {
                0 => println!("Success!"),
                val => println!("Unknown result: {}", val)
            }

            match CString::from_raw(auth_type_ptr).into_string() {
                Ok(auth_str) => println!("AuthType: {}", auth_str),
                Err(_) => println!("Error getting authtype back")
            };

            let mut null_text_handle: PCtxtHandle = ptr::null_mut();
            let mut text_handle = _SecHandle {
                dwLower: 0,
                dwUpper: 0
            };

            let auth_spn_ptr = auth_spn_cstr.into_raw();
            let message_attribute: u32 = 2048; // ISC_REQ_CONNECTION -- default value; security context will not format messages
            let data_representation: u32 = 0x00000010; // SECURITY_NATIVE_DREP
            let mut context_attributes: u32 = 0;

            let mut input_buffer = _SecBuffer {
                cbBuffer: 0,
                BufferType: 0,
                pvBuffer: ptr::null_mut()
            };
            let mut input_buffer_desc: *mut _SecBufferDesc = ptr::null_mut();
            //  = _SecBufferDesc {
            //     ulVersion: 0,
            //     cBuffers: 1,
            //     pBuffers: &mut input_buffer
            // };

            let max_message_size = 12000;
            let mut output_buffer_array: Vec<c_void>  = Vec::with_capacity(max_message_size);
            let mut output_buffer = _SecBuffer {
                cbBuffer: max_message_size as u32,
                BufferType: 2, // SECBUFFER_TOKEN
                pvBuffer: output_buffer_array.as_mut_ptr()
            };
            let mut output_buffer_desc = _SecBufferDesc {
                ulVersion: 0,
                cBuffers: 1,
                pBuffers: &mut output_buffer
            };
            let init_result = InitializeSecurityContextA(&mut cred_handle, null_text_handle, auth_spn_ptr, message_attribute, 0, data_representation, 
                input_buffer_desc, 0, &mut text_handle, &mut output_buffer_desc, &mut context_attributes, &mut expiry);
            match init_result {
                0 => println!("Success!"),
                val => println!("Unknown result: {}", val)
            }
        }
        &mut cred_handle
    }
}
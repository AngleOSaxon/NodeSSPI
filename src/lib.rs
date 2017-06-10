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

    pub fn acquire_credentials_handle(auth_type: String, auth_spn: String) -> Vec<u8> {
        let cred_type: u32 = 2; // Outbound
        let principal: LPSTR = ptr::null_mut();

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

        let max_message_size = 12000;
        let mut output_buffer_vec: Vec<u8>  = Vec::with_capacity(max_message_size);

        let mut cred_handle = _SecHandle {
            dwLower: 0,
            dwUpper: 0
        };

        let auth_type_cstr = CString::new(auth_type.into_bytes()).unwrap();
        let auth_spn_cstr = CString::new(auth_spn.into_bytes()).unwrap();
        unsafe {
            let auth_type_ptr = auth_type_cstr.into_raw();
            let security_status = AcquireCredentialsHandleA(principal, auth_type_ptr, cred_type, logonId, authData, getKeyFunction, getKeyArgument, &mut cred_handle, &mut expiry);

            match security_status {
                0 => println!("Success!"),
                val => println!("Unknown result: {}", val)
            }

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
            let init_result = InitializeSecurityContextA(&mut cred_handle, null_text_handle, auth_spn_ptr, message_attribute, 0, data_representation, 
                input_buffer_desc, 0, &mut text_handle, &mut output_buffer_desc, &mut context_attributes, &mut expiry);
            match init_result {
                590612 | 590611 => {
                    if CompleteAuthToken(&mut text_handle, &mut output_buffer_desc) > 0 {
                        println!("Success completing auth token!");
                    }
                    else {
                        println!("Failed to complete token!");
                    }
                },
                val if (val > 0) => println!("Success initializing token!"),
                val => println!("Unknown result: {}", val)
            }

            output_buffer_vec.set_len(output_buffer.cbBuffer as usize);
        }
        output_buffer_vec
    }
}
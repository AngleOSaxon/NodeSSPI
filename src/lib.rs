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
    pub fn acquire_credentials_handle(auth_type: String) -> PCredHandle {
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
        }
        &mut cred_handle
    }
}
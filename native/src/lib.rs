#![allow(non_upper_case_globals)]
#![allow(non_camel_case_types)]
#![allow(non_snake_case)]
#![allow(dead_code)]
#[macro_use]
extern crate neon;
extern crate base64;

#[link(name = "Secur32")]
pub mod node_sspi {
    use std::ptr;
    use std::ffi::CString;
    use std::os::raw::c_void;
    use std::ops::Deref;
    use std::result::Result;

    use neon::vm::{Call, JsResult, Throw};
    use neon::js::{JsString, JsObject, JsNumber, JsUndefined, Object};
    use neon::mem::Handle;
    use neon::scope::RootScope;

    use base64::{encode, decode};

    //include!(concat!(env!("OUT_DIR"), "/bindings.rs"));
    include!("../bindings.rs");

    const max_message_size: usize = 12000;

    const SEC_E_OK: i32 = 0;
    const SEC_E_CERT_EXPIRED: i32 = -2146893016;
    const SEC_E_INCOMPLETE_MESSAGE: i32 = -2146893032;
    const SEC_E_INSUFFICIENT_MEMORY: i32 = -2146893056;
    const SEC_E_INTERNAL_ERROR: i32 = -2146893052;
    const SEC_E_INVALID_HANDLE: i32 = -2146893055;
    const SEC_E_INVALID_TOKEN: i32 = -2146893048;
    const SEC_E_LOGON_DENIED: i32 = -2146893044;
    const SEC_E_NO_AUTHENTICATING_AUTHORITY: i32 = -2146893039;
    const SEC_E_NO_CREDENTIALS: i32 = -2146893042;
    const SEC_E_TARGET_UNKNOWN: i32 = -2146893053;
    const SEC_E_UNSUPPORTED_FUNCTION: i32 = -2146893054;
    const SEC_E_UNTRUSTED_ROOT: i32 = -2146893019;
    const SEC_E_WRONG_PRINCIPAL: i32 = -2146893022;
    const SEC_E_SECPKG_NOT_FOUND: i32 = -2146893051;
    const SEC_E_QOP_NOT_SUPPORTED: i32 = -2146893046;
    const SEC_E_UNKNOWN_CREDENTIALS: i32 = -2146893043;
    const SEC_E_NOT_OWNER: i32 = -2146893050;
    const SEC_I_RENEGOTIATE: i32 = 590625;
    const SEC_I_COMPLETE_AND_CONTINUE: i32 = 590612;
    const SEC_I_COMPLETE_NEEDED: i32 = 590611;
    const SEC_I_CONTINUE_NEEDED: i32 = 590610;
    const SEC_I_INCOMPLETE_CREDENTIALS: i32 = 590624;
    
    pub struct SecurityContext {
        pub context_handle: _SecHandle,
        pub credentials_handle: _SecHandle,
        pub token: Vec<u8>
    }

    pub trait JavascriptConvert {
        fn get_js_object<'a>(&self, scope: &'a mut RootScope) -> Handle<'a, JsObject>;
        fn get_rust_object<'a, 'b>(js_handle: Handle<'a, JsObject>, scope: &'a mut RootScope) -> Result<Self, Throw>
            where Self : ::std::marker::Sized;
    }

    impl JavascriptConvert for _SecHandle {
        fn get_js_object<'a>(&self, scope: &'a mut RootScope) -> Handle<'a, JsObject> {
            let cred_handle: Handle<JsObject> = JsObject::new(scope);
            let cred_obj = cred_handle.deref();

            cred_obj.set("dwUpper", JsNumber::new(scope, self.dwUpper as f64));
            cred_obj.set("dwLower", JsNumber::new(scope, self.dwLower as f64));

            cred_handle
        }

        fn get_rust_object<'a, 'b>(js_handle: Handle<'a, JsObject>, scope: &'a mut RootScope) -> Result<Self, Throw> {
            let js_obj = js_handle.deref();
            let dw_upper = js_obj.get(scope, "dwUpper")?.check::<JsNumber>()?.value() as u64;
            let dw_lower =  js_obj.get(scope, "dwLower")?.check::<JsNumber>()?.value() as u64;

            let sec_handle = _SecHandle {
                dwUpper: dw_upper,
                dwLower: dw_lower
            };

            Ok(sec_handle)
        }
    } 
    
    impl JavascriptConvert for SecurityContext {
        fn get_js_object<'a>(&self, scope: &'a mut RootScope) -> Handle<'a, JsObject> {
            let encoded_token = encode(&self.token);
            
            let context_handle = JsObject::new(scope);
            let context_obj = context_handle.deref();
            context_obj.set("token", JsString::new(scope, encoded_token.as_ref()).unwrap());
            context_obj.set("contextHandle", self.context_handle.get_js_object(scope));
            context_obj.set("credentialsHandle", self.credentials_handle.get_js_object(scope));
            
            context_handle
        }

        fn get_rust_object<'a, 'b>(js_handle: Handle<'a, JsObject>, scope: &'a mut RootScope) -> Result<Self, Throw> {
            let js_obj = js_handle.deref();
            let context_handle = _SecHandle::get_rust_object(js_obj.get(scope, "contextHandle")?.check::<JsObject>()?, scope)?;
            let credentials_handle = _SecHandle::get_rust_object(js_obj.get(scope, "credentialsHandle")?.check::<JsObject>()?, scope)?;
            let token = match decode(&js_obj.get(scope, "token")?.check::<JsString>()?.value()) {
                Err(e) => return Err(Throw),
                Ok(tok) => tok
            };

            let context = SecurityContext {
                context_handle: context_handle,
                credentials_handle: credentials_handle,
                token: token
            };

            Ok(context)
        }
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

    pub fn cleanup(context: &mut SecurityContext) {
        unsafe {
            FreeCredentialsHandle(&mut context.credentials_handle);
            DeleteSecurityContext(&mut context.context_handle);
        }
    }

    unsafe fn check_result_code(result_code: i32, mut context_handle: _SecHandle, mut buffer_desc: _SecBufferDesc) {
        match result_code {
                SEC_I_COMPLETE_NEEDED | SEC_I_COMPLETE_AND_CONTINUE => {
                    if CompleteAuthToken(&mut context_handle, &mut buffer_desc) > 0 {
                        println!("Success completing auth token!");
                    }
                    else {
                        println!("Failed to complete token!");
                    }
                },
                val if (val >= SEC_E_OK) => println!("Success initializing token!"),
                val => println!("Error code {}", val)
            }
    }

    pub fn initialize_security_context_javascript(call: Call) -> JsResult<JsObject> {
        let auth_type = try!(try!(call.arguments.require(call.scope, 0)).check::<JsString>()).value().to_string();
        let auth_spn = try!(try!(call.arguments.require(call.scope, 1)).check::<JsString>()).value().to_string();
        let context = initialize_security_context(auth_type, auth_spn);

        let context_obj = context.get_js_object(call.scope);

        Ok(context_obj)
    }

    pub fn cleanup_javascript(call: Call) -> JsResult<JsUndefined> {
        let context_obj = try!(try!(call.arguments.require(call.scope, 0)).check::<JsObject>());

        let mut context = match SecurityContext::get_rust_object(context_obj, call.scope) {
            Ok(expr) => expr,
            Err(expr) => return Err(expr)
        };

        cleanup(&mut context);

        Ok(JsUndefined::new())
    }

    register_module!(m, {
        m.export("initializeSecurityContext", initialize_security_context_javascript);
        m.export("cleanup", cleanup_javascript);

        Ok(())
    });
}
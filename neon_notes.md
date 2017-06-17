neon notes:

1. "neon build" command appears to try and run "npm run configure", which is *supposed* to run "node-gyp configure".  Unfortuately the initial setup doesn't appear to create that "configure" command and so neon fails.
1a. When neon fails it does not check or output the error message, instead complaining only that it was unable to find the value for node_root_dir in the output from node-gyp.

2. The "neon build" process does not appear to set the linker search paths and linker library information ("cargo:rustc-link-search" and "cargo:rustc-link-lib") properly for the node library during its build script.
This may be a local issue--I encountered similar difficulties while attempting to link to "Secur32".  The linker appears to ignore %LIB% values as well as those specified in the cargo.toml file.  I have not verified that neon's build.rs file does not contain the linker information--it may do so and a different issue in my environment is the root cause.

3. node-gyp was problematic, particularly in relation to its attempts at locating Python.  This initially appeared to be an issue with node-gyp itself, resolved by setting the %PYTHON% environment variable to the appropriate Python path (note: I think that's what did it--I was trying a lot of things).  However, once this was done, running `node-gyp configure` in my project directory would successfully locate Python (before terminating in a different error about missing `bindings.gyp`), running `neon build` would produce the same error about being unable to locate Python, despite its presence in the %PATH%, its presence in the %PYTHON% variable, and the `which` module's ability to locate it when run individually.
This was eventually resolved by running `npm config set python <path to python.exe>`.
TODO: spin up clean Windows VM and more carefully document steps to repro
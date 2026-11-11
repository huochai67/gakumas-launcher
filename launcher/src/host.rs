#[cfg(all(windows, not(target_arch = "x86_64")))]
compile_error!("gakumas host must be built for Windows x86_64");

#[cfg(windows)]
#[allow(dead_code)]
pub fn should_run_as_host() -> bool {
    let Ok(exe) = std::env::current_exe() else {
        return false;
    };
    let is_gakumas_exe = exe
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.eq_ignore_ascii_case("gakumas.exe"));
    let has_unity_player = exe
        .parent()
        .is_some_and(|p| p.join("UnityPlayer.dll").is_file());
    is_gakumas_exe && has_unity_player
}

#[cfg(not(windows))]
#[allow(dead_code)]
pub fn should_run_as_host() -> bool {
    false
}

#[cfg(windows)]
pub fn run_and_exit() -> ! {
    match windows::run() {
        Ok(code) => std::process::exit(code),
        Err(error) => {
            use std::io::Write;
            if let Ok(exe) = std::env::current_exe() {
                if let Some(dir) = exe.parent() {
                    if let Ok(mut file) = std::fs::File::create(dir.join("gakumas-host.log")) {
                        let _ = writeln!(file, "{error}");
                    }
                }
            }
            eprintln!("error: {error}");
            std::process::exit(1);
        }
    }
}

#[cfg(not(windows))]
pub fn run_and_exit() -> ! {
    eprintln!("gakumas host is a Windows x64 executable (gakumas.exe); run it on Windows or via Wine");
    std::process::exit(1);
}

#[cfg(windows)]
pub mod windows {
    use std::{
        ffi::{CString, OsStr},
        io,
        os::windows::ffi::OsStrExt,
        path::Path,
        ptr,
    };
    use windows_sys::Win32::{
        Foundation::{FreeLibrary, HINSTANCE, HMODULE},
        System::{
            Environment::GetCommandLineW,
            LibraryLoader::{
                GetModuleHandleW, GetProcAddress, LoadLibraryExW, SetDllDirectoryW,
                LOAD_WITH_ALTERED_SEARCH_PATH,
            },
        },
    };

    type Error = Box<dyn std::error::Error>;
    type UnityMain = unsafe extern "system" fn(HINSTANCE, HINSTANCE, *mut u16, i32) -> i32;
    type SetDataDir = unsafe extern "C" fn(*const i8);
    type CheckPlatform = unsafe extern "system" fn(u32) -> i32;

    struct Module(HMODULE);
    impl Drop for Module {
        fn drop(&mut self) {
            unsafe {
                FreeLibrary(self.0);
            }
        }
    }

    fn wide(value: &OsStr) -> Vec<u16> {
        value.encode_wide().chain(std::iter::once(0)).collect()
    }

    fn load(path: &Path) -> Result<Module, Error> {
        let name = wide(path.as_os_str());
        let module = unsafe {
            LoadLibraryExW(name.as_ptr(), ptr::null_mut(), LOAD_WITH_ALTERED_SEARCH_PATH)
        };
        if module.is_null() {
            return Err(format!(
                "LoadLibraryExW({}) failed: {}",
                path.file_name().unwrap_or_default().to_string_lossy(),
                io::Error::last_os_error()
            )
            .into());
        }
        Ok(Module(module))
    }

    fn symbol(
        module: HMODULE,
        name: &'static [u8],
    ) -> Result<unsafe extern "system" fn() -> isize, Error> {
        unsafe { GetProcAddress(module, name.as_ptr()) }.ok_or_else(|| {
            format!(
                "missing native export {}",
                String::from_utf8_lossy(&name[..name.len() - 1])
            )
            .into()
        })
    }

    pub fn run() -> Result<i32, Error> {
        let executable = std::env::current_exe()?;
        let root = executable.parent().ok_or("host has no runtime directory")?;
        std::env::set_current_dir(root)?;
        let root_wide = wide(root.as_os_str());
        if unsafe { SetDllDirectoryW(root_wide.as_ptr()) } == 0 {
            return Err(io::Error::last_os_error().into());
        }

        let assembly = load(&root.join("GameAssembly.dll"))?;
        let set_data_dir: SetDataDir =
            unsafe { std::mem::transmute(symbol(assembly.0, b"il2cpp_set_data_dir\0")?) };
        let data_dir = CString::new(
            root.join("gakumas_Data/il2cpp_data")
                .to_str()
                .ok_or("runtime path is not valid Unicode")?,
        )?;
        unsafe {
            set_data_dir(data_dir.as_ptr());
        }
        let unity = load(&root.join("UnityPlayer.dll"))?;

        let winhttp_name = wide(OsStr::new("winhttp.dll"));
        let mut winhttp = unsafe { GetModuleHandleW(winhttp_name.as_ptr()) };
        let proxy = if root.join("winhttp.dll").is_file() && winhttp.is_null() {
            Some(load(&root.join("winhttp.dll"))?)
        } else {
            None
        };
        if let Some(proxy) = &proxy {
            winhttp = proxy.0;
        }
        if !winhttp.is_null() {
            if let Ok(export) = symbol(winhttp, b"WinHttpCheckPlatform\0") {
                let check: CheckPlatform = unsafe { std::mem::transmute(export) };
                unsafe {
                    check(0);
                }
            }
        }

        let unity_main: UnityMain =
            unsafe { std::mem::transmute(symbol(unity.0, b"UnityMain\0")?) };
        let instance = unsafe { GetModuleHandleW(ptr::null()) };
        if instance.is_null() {
            return Err(io::Error::last_os_error().into());
        }
        let original = unsafe { GetCommandLineW() };
        if original.is_null() {
            return Err("GetCommandLineW returned null".into());
        }
        let mut length = 0;
        while unsafe { *original.add(length) } != 0 {
            length += 1;
        }
        let mut command = unsafe { std::slice::from_raw_parts(original, length) }.to_vec();
        if !std::env::args_os().any(|arg| arg.eq_ignore_ascii_case(OsStr::new("-projectPath"))) {
            command.extend(" -projectPath \"".encode_utf16());
            command.extend(root.as_os_str().encode_wide());
            command.push('"' as u16);
        }
        command.push(0);
        let result = unsafe { unity_main(instance, ptr::null_mut(), command.as_mut_ptr(), 1) };
        drop(proxy);
        drop(unity);
        drop(assembly);
        Ok(result)
    }
}

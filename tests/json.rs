#![cfg(feature = "json")]

use seccompiler::{apply_filter, compile_from_json, BpfProgram};
use std::convert::TryInto;
use std::env::consts::ARCH;
use std::io::Read;
use std::thread;

const FAILURE_CODE: i32 = 1000;

fn validate_json_filter<R: Read>(reader: R, validation_fn: fn(), should_fail: Option<bool>) {
    let mut filters = compile_from_json(reader, ARCH.try_into().unwrap()).unwrap();
    let filter: BpfProgram = filters.remove("main_thread").unwrap();

    // We need to run the validation inside another thread in order to avoid setting
    // the seccomp filter for the entire unit tests process.
    let errno = thread::spawn(move || {
        // Install the filter.
        apply_filter(&filter).unwrap();

        // Call the validation fn.
        validation_fn();

        // Return errno.
        std::io::Error::last_os_error().raw_os_error().unwrap()
    })
    .join()
    .unwrap();

    // In case of a seccomp denial `errno` should be `FAILURE_CODE`
    if let Some(should_fail) = should_fail {
        if should_fail {
            assert_eq!(errno, FAILURE_CODE);
        } else {
            assert_ne!(errno, FAILURE_CODE);
        }
    }
}

#[test]
fn test_empty_filter() {
    // An empty filter should always return the default action.
    // For example, for an empty allowlist, it should always trap/kill,
    // for an empty denylist, it should allow allow all system calls.

    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "allow",
            "match_action": "trap",
            "filter": []
        }
    }"#;

    let mut filters = compile_from_json(json_input.as_bytes(), ARCH.try_into().unwrap()).unwrap();
    let filter = filters.remove("main_thread").unwrap();

    // This should allow any system calls.
    let pid = thread::spawn(move || {
        let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
        assert_eq!(seccomp_level, 0);
        // Install the filter.
        apply_filter(&filter).unwrap();

        let seccomp_level = unsafe { libc::prctl(libc::PR_GET_SECCOMP) };
        assert_eq!(seccomp_level, 2);

        unsafe { libc::getpid() }
    })
    .join()
    .unwrap();

    // Check that the getpid syscall returned successfully.
    assert!(pid > 0);
}

#[test]
fn test_invalid_architecture() {
    // A filter compiled for another architecture should kill the process upon evaluation.
    // The process will appear as if it received a SIGSYS.
    let mut arch = "aarch64";

    if ARCH == "aarch64" {
        arch = "x86_64";
    }

    let json_input = r#"{
        "main_thread": {
            "mismatch_action": "allow",
            "match_action": "trap",
            "filter": []
        }
    }"#;

    let mut filters = compile_from_json(json_input.as_bytes(), arch.try_into().unwrap()).unwrap();
    let filter = filters.remove("main_thread").unwrap();

    let pid = unsafe { libc::fork() };
    match pid {
        0 => {
            apply_filter(&filter).unwrap();

            unsafe {
                libc::getpid();
            }
        }
        child_pid => {
            let mut child_status: i32 = -1;
            let pid_done = unsafe { libc::waitpid(child_pid, &mut child_status, 0) };
            assert_eq!(pid_done, child_pid);

            assert!(libc::WIFSIGNALED(child_status));
            assert_eq!(libc::WTERMSIG(child_status), libc::SIGSYS);
        }
    };
}

#[test]
fn test_complex_filter() {
    let json_input = r#"{
            "main_thread": {
                "mismatch_action": {"errno" : 1000},
                "match_action": "allow",
                "filter": [
                    {
                        "syscall": "rt_sigprocmask",
                        "comment": "extra syscalls needed by the test runtime"
                    },
                    {
                        "syscall": "sigaltstack"
                    },
                    {
                        "syscall": "munmap"
                    },
                    {
                        "syscall": "exit"
                    },
                    {
                        "syscall": "rt_sigreturn"
                    },
                    {
                        "syscall": "futex"
                    },
                    {
                        "syscall": "getpid",
                        "comment": "start of the actual filter we want to test."
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "le",
                                "val": 14
                            },
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "ne",
                                "val": 13
                            }
                        ]
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "gt",
                                "val": 20
                            },
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "lt",
                                "val": 40
                            }
                        ]
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 0,
                                "type": "dword",
                                "op": "eq",
                                "val": 1
                            },
                            {
                                "index": 2,
                                "type": "dword",
                                "op": "eq",
                                "val": 15
                            }
                        ]
                    },
                    {
                        "syscall": "ioctl",
                        "args": [
                            {
                                "index": 2,
                                "type": "qword",
                                "op": "eq",
                                "val": 4294967336,
                                "comment": "u32::MAX as u64 + 41"
                            }
                        ]
                    },
                    {
                        "syscall": "madvise",
                        "args": [
                            {
                                "index": 0,
                                "type": "dword",
                                "op": "eq",
                                "val": 0
                            },
                            {
                                "index": 1,
                                "type": "dword",
                                "op": "eq",
                                "val": 0
                            }
                        ]
                    }
                ]
            }
        }"#;

    // check syscalls that are supposed to work
    {
        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 12);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 14);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 21);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 39);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(1, 0, 15);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, u32::MAX as u64 + 41);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::madvise(std::ptr::null_mut(), 0, 0);
            },
            Some(false),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                assert!(libc::getpid() > 0);
            },
            None,
        );
    }

    // check syscalls that are not supposed to work
    {
        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 13);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 16);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 17);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 18);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 19);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, 20);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::ioctl(0, 0, u32::MAX as u64 + 42);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                libc::madvise(std::ptr::null_mut(), 1, 0);
            },
            Some(true),
        );

        validate_json_filter(
            json_input.as_bytes(),
            || unsafe {
                assert_eq!(libc::getuid() as i32, -FAILURE_CODE);
            },
            None,
        );
    }
}

#![allow(non_upper_case_globals)]
use libc::c_void;
use mshv_bindings::*;
use mshv_ioctls::{Mshv,VcpuFd};
use std::io::Write;
fn main() {
    let mshv = Mshv::new().unwrap();
    let vm = mshv.create_vm().unwrap();
    let vcpu = vm.create_vcpu(0).unwrap();
    // This example is based on https://lwn.net/Articles/658511/
    #[rustfmt::skip]
       let code:[u8;12] = [
           0xba, 0xf8, 0x03,  /* mov $0x3f8, %dx */
           0x00, 0xd8,         /* add %bl, %al */
           0x04, b'0',         /* add $'0', %al */
           0xee,               /* out %al, (%dx) */
           /* send a 0 to indicate we're done */
           0xb0, b'\0',        /* mov $'\0', %al */
           0xee,               /* out %al, (%dx) */
           /* HLT seems to cause a hang rather than return hv_message_type_HVMSG_X64_HALT */
           0xf4, /* HLT */
       ];

    let mem_size = 0x1000;
    // SAFETY: FFI call.
    let load_addr = unsafe {
        libc::mmap(
            std::ptr::null_mut(),
            mem_size,
            libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_ANONYMOUS | libc::MAP_SHARED | libc::MAP_NORESERVE,
            -1,
            0,
        )
    } as *mut u8;
    let mem_region = mshv_user_mem_region {
        flags: HV_MAP_GPA_READABLE | HV_MAP_GPA_WRITABLE | HV_MAP_GPA_EXECUTABLE,
        guest_pfn: 0x1,
        size: 0x1000,
        userspace_addr: load_addr as u64,
    };

    vm.map_user_memory(mem_region).unwrap();

    // SAFETY: load_addr is a valid pointer from mmap. Its length is mem_size.
    unsafe {
        // Get a mutable slice of `mem_size` from `load_addr`.
        let mut mslice = ::std::slice::from_raw_parts_mut(load_addr, mem_size);
        mslice.write_all(&code).unwrap();
    }

    //Get CS Register
    let mut cs_reg = hv_register_assoc {
        name: hv_register_name::HV_X64_REGISTER_CS as u32,
        ..Default::default()
    };
    vcpu.get_reg(::std::slice::from_mut(&mut cs_reg)).unwrap();

    // SAFETY: access union fields
    unsafe {
        assert_ne!({ cs_reg.value.segment.base }, 0);
        assert_ne!({ cs_reg.value.segment.selector }, 0);
    };

    cs_reg.value.segment.base = 0;
    cs_reg.value.segment.selector = 0;

    vcpu.set_reg(&[
        cs_reg,
        hv_register_assoc {
            name: hv_register_name::HV_X64_REGISTER_RAX as u32,
            value: hv_register_value { reg64: 6 },
            ..Default::default()
        },
        hv_register_assoc {
            name: hv_register_name::HV_X64_REGISTER_RBX as u32,
            value: hv_register_value { reg64: 2 },
            ..Default::default()
        },
        hv_register_assoc {
            name: hv_register_name::HV_X64_REGISTER_RIP as u32,
            value: hv_register_value { reg64: 0x1000 },
            ..Default::default()
        },
        hv_register_assoc {
            name: hv_register_name::HV_X64_REGISTER_RFLAGS as u32,
            value: hv_register_value { reg64: 0x2 },
            ..Default::default()
        },
    ])
    .unwrap();

    let hv_message: hv_message = Default::default();
    let mut done = false;
    let halted;
    loop {
        let ret_hv_message: hv_message = vcpu.run(hv_message).unwrap();
        match ret_hv_message.header.message_type {
            hv_message_type_HVMSG_X64_HALT => {
                // Never get here ...
                println!("VM Halted!");
                halted = true;
                break;
            }
            hv_message_type_HVMSG_X64_IO_PORT_INTERCEPT => {
                let io_message = ret_hv_message.to_ioport_info().unwrap();

                if !done {
                    assert!(io_message.rax == b'8' as u64);
                    assert!(io_message.port_number == 0x3f8);
                    // SAFETY: access union fields.
                    unsafe {
                        assert!(io_message.access_info.__bindgen_anon_1.string_op() == 0);
                        assert!(io_message.access_info.__bindgen_anon_1.access_size() == 1);
                    }
                    assert!(
                        io_message.header.intercept_access_type == /*HV_INTERCEPT_ACCESS_WRITE*/ 1_u8
                    );
                    println!("First out call!");
                    
                    update_rip(&vcpu,io_message.header.rip
                        + io_message.header.instruction_length() as u64);
                    
                    done = true;
                    
                } else {
                    assert!(io_message.rax == b'\0' as u64);
                    assert!(io_message.port_number == 0x3f8);
                    // SAFETY: access union fields.
                    unsafe {
                        assert!(io_message.access_info.__bindgen_anon_1.string_op() == 0);
                        assert!(io_message.access_info.__bindgen_anon_1.access_size() == 1);
                    }
                    assert!(
                        io_message.header.intercept_access_type == /*HV_INTERCEPT_ACCESS_WRITE*/ 1_u8
                    );
                    println!("Second out call!");

                    update_rip(&vcpu,io_message.header.rip
                        + io_message.header.instruction_length() as u64);
                }
            }
            _ => {
                println!("Message type: 0x{:x?}", {
                    ret_hv_message.header.message_type
                });
                panic!("Unexpected Exit Type");
            }
        };
    }
    assert!(done);
    assert!(halted);
    vm.unmap_user_memory(mem_region).unwrap();
    // SAFETY: FFI call. We're sure load_addr and mem_size are correct.
    unsafe { libc::munmap(load_addr as *mut c_void, mem_size) };
    //    }
}

fn update_rip(vcpu: &VcpuFd, ip: u64) {
    /* Advance rip */
    vcpu.set_reg(&[hv_register_assoc {
        name: hv_register_name::HV_X64_REGISTER_RIP as u32,
        value: hv_register_value {
            reg64: ip,
        },
        ..Default::default()
    }])
    .unwrap();
}
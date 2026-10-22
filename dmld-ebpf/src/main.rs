#![no_std]
#![no_main]

use aya_ebpf::{macros::uprobe, programs::ProbeContext};
use aya_log_ebpf::info;

#[uprobe(path = "libc", function = "malloc")]
pub fn dmld(ctx: ProbeContext) -> u32 {
    match try_dmld(ctx) {
        Ok(ret) => ret,
        Err(ret) => ret,
    }
}

fn try_dmld(ctx: ProbeContext) -> Result<u32, u32> {
    info!(&ctx, "function malloc called by libc");
    Ok(0)
}

#[cfg(not(test))]
#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

#[unsafe(link_section = "license")]
#[unsafe(no_mangle)]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

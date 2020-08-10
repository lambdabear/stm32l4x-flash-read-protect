use clap::{App, Arg};
use probe_rs::{Error, MemoryInterface, Session};

const FLASH_REG_BASE_ADDR: u32 = 0x4002_2000;
const FLASH_SR_OFFSET: u32 = 0x10;
const FLASH_CR_OFFSET: u32 = 0x14;
const FLASH_OPTR_OFFSET: u32 = 0x20;
const FLASH_KEYR_OFFSET: u32 = 0x08;
const FLASH_OPTKEYR_OFFSET: u32 = 0x0C;
const KEY1: u32 = 0x45670123;
const KEY2: u32 = 0xCDEF89AB;
const OPTKEY1: u32 = 0x08192A3B;
const OPTKEY2: u32 = 0x4C5D6E7F;
fn main() -> Result<(), Error> {
    let matches = App::new("set-stm32l4x-flash-read-protection")
        .version("0.1")
        .author("Zhang Yi")
        .about("Setting stm32lx mcu flash read protection")
        .arg(
            Arg::new("level")
                .short('l')
                .long("level")
                .about("Setting a protection level: 0, 1, or 2")
                .default_value("0")
                .takes_value(true)
                .required(true),
        )
        .get_matches();

    let mut session = Session::auto_attach("STM32L4")?;
    let mut core = session.core(0)?;
    let mut buf = [0_u32; 2];
    core.read_32(0x1FFF_7800, &mut buf)?;
    println!("flash option register: {:X?}", buf);

    // check that no Flash memory operation is on going
    loop {
        core.read_32(FLASH_REG_BASE_ADDR + FLASH_SR_OFFSET, &mut buf)?;
        let bsy = buf[0] & 0x0001_0000_u32;
        if bsy == 0 {
            break;
        }
    }

    // unlocking the FLASH_CR
    let buf = [KEY1];
    core.write_32(FLASH_REG_BASE_ADDR + FLASH_KEYR_OFFSET, &buf)?;
    let buf = [KEY2];
    core.write_32(FLASH_REG_BASE_ADDR + FLASH_KEYR_OFFSET, &buf)?;

    // clear OPTLOCK option lock bit
    let buf = [OPTKEY1];
    core.write_32(FLASH_REG_BASE_ADDR + FLASH_OPTKEYR_OFFSET, &buf)?;
    let buf = [OPTKEY2];
    core.write_32(FLASH_REG_BASE_ADDR + FLASH_OPTKEYR_OFFSET, &buf)?;

    // write options value in the options registers
    // set read protection level to Level n
    let buf = match matches.value_of("level") {
        Some("0") => [0xAA],
        Some("1") => [0x00],
        Some("2") => [0xCC],
        Some(_) | None => [0x00],
    };
    core.write_8(FLASH_REG_BASE_ADDR + FLASH_OPTR_OFFSET, &buf)?;

    // start options modification
    let mut buf = [0_u32, 1];
    core.read_32(FLASH_REG_BASE_ADDR + FLASH_CR_OFFSET, &mut buf)?;
    buf[0] = buf[0] | 0x0002_0000;
    core.write_32(FLASH_REG_BASE_ADDR + FLASH_CR_OFFSET, &buf)?;

    // check that no Flash memory operation is on going
    let mut buf = [0_u32, 1];
    loop {
        core.read_32(FLASH_REG_BASE_ADDR + FLASH_SR_OFFSET, &mut buf)?;
        let bsy = buf[0] & 0x0001_0000_u32;
        if bsy == 0 {
            break;
        }
    }

    let mut buf = [0_u32, 2];
    core.read_32(FLASH_REG_BASE_ADDR + FLASH_OPTR_OFFSET, &mut buf)?;
    println!("flash option register: {:X?}", buf);

    core.reset_and_halt(std::time::Duration::from_secs(1))?;
    println!("mcu reset");
    Ok(())
}

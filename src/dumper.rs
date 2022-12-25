use nix::sys::signal::{kill, Signal};
use nix::unistd::Pid;
use proc_maps::MapRange;

use std::cell::RefCell;
use std::io::{Read, Write};
use std::io::{SeekFrom, Seek};
use std::io::Cursor;
use byteorder::{ReadBytesExt, LittleEndian, WriteBytesExt};

use regex::bytes::Regex;

pub struct Dumper {
    pid: Pid,
    mem_fd : RefCell<std::fs::File>,
    maps: Vec<MapRange>,
}

impl Dumper {
    pub fn new(pid: i32) -> Dumper {
        let mem_fd = match std::fs::File::open(format!("/proc/{}/mem", pid)) {
            Ok(fd) => fd,
            Err(_) => {
                panic!("no such process: {}", pid);     
            }
        };
        Dumper {
            pid: Pid::from_raw(pid),
            maps: Vec::new(),
            mem_fd: RefCell::new(mem_fd),
        }
    }

    pub fn attach_process(&mut self) {
        kill(self.pid, Signal::SIGSTOP)
            .expect("Failed to send SIGSTOP to process");

        self.maps =
            proc_maps::get_process_maps(self.pid.as_raw()).expect("Failed to get process maps");
    }

    pub fn detach_process(&self) {

        kill(self.pid, Signal::SIGCONT)
            .expect("Failed to send SIGCONT to process");
    }

    fn guess_dex_size(&self, dex_header_addr : usize) -> Option<(usize, usize)> {
        
        let mut cursor = self.mem_fd.borrow_mut();

        cursor.seek(SeekFrom::Start(dex_header_addr as u64)).ok()?;

        cursor.seek(SeekFrom::Current(0x20)).ok()?;
        let file_size = cursor.read_u32::<LittleEndian>().ok()?;

        // verify string_ids_off
        cursor.seek(SeekFrom::Start(dex_header_addr as u64)).ok()?;
        cursor.seek(SeekFrom::Current(0x3c)).ok()?;
        let string_ids_off = cursor.read_u32::<LittleEndian>().ok()?;
        if string_ids_off != 0x70 {
            return None;
        }        

        // guess size by map_off + map_size * 0xC + 4
        cursor.seek(SeekFrom::Start(dex_header_addr as u64)).ok()?;
        cursor.seek(SeekFrom::Current(0x34)).ok()?;
        let map_off = cursor.read_u32::<LittleEndian>().ok()?;

        cursor.seek(SeekFrom::Start(dex_header_addr as u64)).ok()?;
        cursor.seek(SeekFrom::Current(map_off as i64)).ok()?;
        let map_size = cursor.read_u32::<LittleEndian>().ok()?;

        let real_size = map_off.checked_add(map_size.checked_mul(0xC)?)?.checked_add(4)?;
        return Some((file_size as usize, real_size as usize))
    }

    fn fix_dex(dex: &[u8]) -> Option<Vec<u8>> {
        let mut fix = dex.to_vec();
        let mut cursor = Cursor::new(&mut fix);

        cursor.write("dex\n035\0".as_bytes()).ok()?;

        // file size
        cursor.seek(SeekFrom::Start(0x20)).ok()?;
        cursor.write_u32::<LittleEndian>(dex.len() as u32).ok()?;

        // header size
        cursor.seek(SeekFrom::Start(0x24)).ok()?;
        cursor.write_u32::<LittleEndian>(112).ok()?;

        cursor.seek(SeekFrom::Start(0x28)).ok()?;
        let endian_tag = cursor.read_u32::<LittleEndian>().ok()?;
        if endian_tag != 0x12345678 && endian_tag != 0x78563412 {
            cursor.seek(SeekFrom::Start(0x28)).ok()?;
            cursor.write_u32::<LittleEndian>(0x12345678).ok()?;
        }

        Some(fix)
    }
    
    pub fn search_dex(&mut self, out_path: &str) {
        self.maps
            .iter()
            .filter(|m| m.is_read() && m.size() > 0x60)
            .filter(|m| match m.filename() {
                Some(f) => !(f.starts_with("/data/dalvik-cache/") || f.starts_with("/system/")),
                None => true,
            })
            .for_each(|m| {
                if let Some(mem) = self.read_memory_proc(m.start(), m.size()) {
                    // println!("searching dex in {:#08x} - {:#08x}", m.start(), m.start() + m.size());

                    let re = Regex::new(r"\x64\x65\x78\x0a\x30..\x00").unwrap();
                    re.find_iter(&mem).for_each(|s| {
                        println!("find dex off: {:#08x}", m.start() + s.start());
                        let real_addr = m.start() + s.start();
                        if let Some((file_size, guess_size)) = self.guess_dex_size(real_addr) {
                            if let Some(data) = self.read_memory_proc(real_addr, guess_size) {
                                println!("file_size: {:#08x}, guess_size: {:#08x}", file_size, guess_size);
                                let mut file = std::fs::File::create(format!("{}/dex_{:#08x}.dex", out_path, real_addr))
                                    .expect("Failed to create dex file");
                                file.write(&data).expect("Failed to write dex file");
                            } else {
                                println!("read memory failed {:#08x} - {:#08x}", real_addr, real_addr + guess_size);
                            }
                        }
                    });

                    if (&mem[0..3]).to_vec() != "dex".as_bytes().to_vec() {
                        if let Some((file_size, guess_size)) = self.guess_dex_size(m.start()) {
                            println!("no header, file_size: {:#08x}, guess_size: {:#08x}", file_size, guess_size);
                            if let Some(data) = self.read_memory_proc(m.start(), guess_size) {
                                if let Some(new_dex) = Dumper::fix_dex(&data) {
                                    let mut file = std::fs::File::create(format!("{}/dex_{:#08x}.dex", out_path, m.start()))
                                    .expect("Failed to create dex file");
                                    file.write(&new_dex).expect("Failed to write dex file");
                                }   
                            } else {
                                println!("read memory failed {:#08x} - {:#08x}", m.start(), m.start() + guess_size);
                            }
                        }
                    }
                }
            });
    }

    fn read_memory_proc(&self, address: usize, size: usize) -> Option<Vec<u8>> {
        let mut buffer = vec![0u8; size];

        self.mem_fd.borrow_mut().seek(std::io::SeekFrom::Start(address as u64)).ok()?;
        self.mem_fd.borrow_mut().read_exact(&mut buffer).ok()?;

        Some(buffer)
    }
}

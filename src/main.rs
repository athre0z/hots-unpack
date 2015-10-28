/*
 * Tool statically unpacking HotS binaries.
 * 
 * The MIT License (MIT)
 * 
 * Copyright (c) 2015 athre0z
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in all
 * copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

extern crate crypto;
mod pe;

use std::fs::File;
use std::path::Path;
use std::io::prelude::*;
use std::error::Error;
use std::mem;
use std::slice;
use std::env;

use crypto::{buffer, aes, blockmodes};

#[allow(unused_imports)]
use crypto::symmetriccipher::Encryptor;

type Rva = u32;
type Va = u64;

/// Entry-point.
fn main() {
    println!("HotS-unpack v1.2.0 (c) 2015 athre0z\n");

    // Parse arguments.
    let args: Vec<_> = env::args().collect();
    let (in_path, out_path) = match args.len() {
        2 => (&args[1], "out.exe".to_string()),
        3 => (&args[1], args[2].clone()),
        _ => {
            println!("[*] Usage: {} <input binary> [output binary]", args[0]);
            return;
        }
    };

    // Read file.
    let mut f = match File::open(&Path::new(&in_path)) {
        Err(why) => panic!("[-] Couldn't open input file: {}", Error::description(&why)),
        Ok(file) => file,
    };
	
    let mut data = Vec::new();
    let data_size = match f.read_to_end(&mut data) {
        Err(why) => panic!("[-] Couldn't read input file: {}", Error::description(&why)),
        Ok(x) => x
    };

    println!("[+] Read file: {} bytes", data_size);

    // Parse DOS-header.
    let mz = get_data::<pe::ImageDosHeader>(&mut data, 0);
    if unsafe { (*mz).magic } != pe::DOS_MAGIC {
        panic!("[-] Invalid input file: invalid DOS header");
    }

    // Parse NT-header.
    let nt_header_offs = unsafe { (*mz).lfanew } as u32;
    let nt = get_data::<pe::ImageNtHeaders32>(&mut data, nt_header_offs);
    if unsafe { (*nt).signature } != pe::PE_MAGIC {
        panic!("[-] Invalid input file: invalid NT header");
    }

    // Obtain useful information.
    let sec_table_offs;
    let num_secs;
    let data_offs;
    let image_base;

    let is_amd64 = unsafe { (*nt).file_header.machine } == pe::IMAGE_FILE_MACHINE_AMD64;
    if is_amd64 {
        let nt64 = get_data::<pe::ImageNtHeaders64>(&mut data, nt_header_offs);
        sec_table_offs = nt_header_offs + mem::size_of::<pe::ImageNtHeaders64>() as u32;
        num_secs = unsafe { (*nt64).file_header.number_of_sections } as u32;
        data_offs = sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() as u32 * num_secs;
        image_base = unsafe { (*nt64).opt_header.image_base } as Va;
    }
    else {
        sec_table_offs = nt_header_offs + mem::size_of::<pe::ImageNtHeaders32>() as u32;
        num_secs = unsafe { (*nt).file_header.number_of_sections } as u32;
        data_offs = sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() as u32 * num_secs;
        image_base = unsafe { (*nt).opt_header.image_base } as Va;
    }

    let mut chunk_table_opt: Option<Vec<ChunkEntry>> = None;

    // Scan for chunk table in new format. 
    // Yep, there's certainly room for optimization here.
    println!("[*] Heuristically locating chunk table (new format) ...");
    {
        let mut chunk_table_candidate = Vec::<ChunkEntry>::with_capacity(500000);
        'new_format_scan: for i in data_offs..data.len() as u32 {
            let mut offs = 0u32;
            let mut abs_offs = 0u32;

            //if i % 100000 == 0 { println!("{}", i); }

            while i + offs + mem::size_of::<u8>() as u32 <= data.len() as u32 {
                let chunk_entry_offs = match read_compressed_u32(&mut data, i + offs) {
                    Some((val, size)) => { offs += size; val },
                    None => break,
                };

                if abs_offs as u32 + chunk_entry_offs as u32 > u32::max_value() as u32 {
                    break;
                }
                abs_offs += chunk_entry_offs;

                if offs >= 200000 && abs_offs == 0xFFFFFFFF {
                    chunk_table_opt = Some(chunk_table_candidate);
                    break 'new_format_scan;
                }

                if chunk_entry_offs == 0 || chunk_entry_offs >= 0x5000000 {
                    break;
                }

                let chunk_entry_size = match read_compressed_u32(&mut data, i + offs) {
                    Some((val, size)) => { offs += size; val },
                    None => break,
                };

                chunk_table_candidate.push(ChunkEntry{
                    offset: abs_offs,
                    size: chunk_entry_size
                });
                if abs_offs as u32 + chunk_entry_size as u32 > u32::max_value() as u32 {
                    break;
                }
                abs_offs += chunk_entry_size;
            }
            chunk_table_candidate.clear();
        }
    }

    // If we didn't find it yet, scan for chunk table in old format.
    if chunk_table_opt.is_none() {
        println!("[*] Heuristically locating chunk table (old format) ...");
        'old_format_scan: for i in data_offs..data.len() as u32 {
            let mut offs = 0u32;
            let mut last_addr = 0u32;

            // Check if candidate looks like a chunk table.
            while i + offs + mem::size_of::<ChunkEntry>() as u32 <= data.len() as u32 { 
                unsafe {
                    let cur = get_data::<ChunkEntry>(&mut data, i + offs);

                    // The chunk table's end is indicated with an 0xFFFFFFFF.
                    if offs >= 1000 * mem::size_of::<ChunkEntry>() as u32 
                        && (*cur).offset == 0xFFFFFFFF {

                        chunk_table_opt = Some(
                            slice::from_raw_parts(
                                get_data::<ChunkEntry>(&mut data, i), 
                                (offs as usize / mem::size_of::<ChunkEntry>()) - 1
                            ).to_vec()
                        );
                        break 'old_format_scan;
                    }

                    // The chunk table entries are stored ascending.
                    if (*cur).offset <= last_addr {
                        break;
                    }
     
                    last_addr = (*cur).offset;
                    offs += mem::size_of::<ChunkEntry>() as u32;
                }
            }
        }
    }

    let chunk_table = match chunk_table_opt {
        None => panic!("[-] Unable to locate chunk table."),
        Some(x) => x,
    };

    println!("[+] Found chunk table ({} entries).", chunk_table.len());

    // Scan for AES key.
    println!("[*] Locating AES key ...");

    // 0xFF -> wildcard
    let pattern: Vec<u8>;
    if is_amd64 {
        pattern = vec![
            0x48, 0x8D, 0x05, 0xFF, 0xFF, 0xFF, 0xFF, // lea  rax, g_aesKey
            0x48, 0x8D, 0x15, 0xFF, 0xFF, 0xFF, 0xFF, // lea  rdx, g_aesInputKey
            0x48, 0x89, 0xC1,                         // mov  rcx, rax
            0x41, 0xB8, 0x80, 0x00, 0x00, 0x00,       // mov  r8d, 80h
            0xE8,                                     // call AesSetDecryptKey
        ];
    }
    else {
        pattern = vec![
            0x68, 0x80, 0x00, 0x00, 0x00,             // push 80h
            0x68, 0xFF, 0xFF, 0xFF, 0xFF,             // push offset g_aesInputKey
            0x68, 0xFF, 0xFF, 0xFF, 0xFF,             // push offset g_aesKey
            0xE8, 0xFF, 0xFF, 0xFF, 0xFF,             // call AesSetDecryptKey
            0xE9,                                     // jmp  XXX
        ];
    }

    let mut match_ = None;
    for offs in sec_table_offs..(data.len() - pattern.len()) as u32 {
        let mut exhausted = true;
        for (i, cur_pat_byte) in pattern.iter().enumerate() {
            if *cur_pat_byte == 0xFF { continue; }
            if data[offs as usize + i] != *cur_pat_byte { 
                exhausted = false;
                break; 
            }
        }

        if exhausted {
            match_ = Some(offs);
            break;
        }
    }

    let aes_key_rva = match match_ {
        Some(x) => unsafe { 
            if is_amd64 {
                // RIP-relative addressing
                (fo_to_rva(&mut data, sec_table_offs, num_secs, x + 7).unwrap() as i32
                    + *get_data::<i32>(&mut data, x + 7 + 3) 
                    + 7) as Rva
            }
            else {
                (*get_data::<u32>(&mut data, x + 6) as u64 - image_base) as Rva
            }
        },
        None => panic!("[-] Unable to locate AES key.")
    };

    print!("[+] Found AES key @ RVA 0x{:x}: ", aes_key_rva);

    // Dump AES key.
    let aes_key = unsafe { *get_data_rva::<[u8; 16]>(
        &mut data, sec_table_offs, num_secs, aes_key_rva) };
    
    for i in aes_key.iter() {
        print!("{:02x} ", i);
    }
    print!("\n");

    // Collect all encrypted chunks into one buffer (we got plenty of memory, don't we? :p)
    println!("[*] Merging encrypted chunks ...", );
    let mut encrypted_blob = Vec::<u8>::new();
    for cur_chunk in &chunk_table {
        encrypted_blob.extend(get_slice_rva::<u8>(
            &mut data, sec_table_offs, num_secs, cur_chunk.offset as Rva, 
            cur_chunk.size as u32).to_vec());
    }

    let padding_length = 16 - encrypted_blob.len() % 16;
    if padding_length > 0 {
        encrypted_blob.extend(vec![0; padding_length]);
    }

    // Decrypt blob.
    println!("[*] Decrypting ...");
    let mut decryptor = aes::ecb_decryptor(
        aes::KeySize::KeySize128,
        &aes_key,
        blockmodes::NoPadding);
    let mut decrypted_blob = vec![0u8; encrypted_blob.len()];

    {
        let mut read_buf = buffer::RefReadBuffer::new(&encrypted_blob);
        let mut write_buf = buffer::RefWriteBuffer::new(&mut decrypted_blob);
        match decryptor.decrypt(&mut read_buf, &mut write_buf, true) {
            Err(why) => panic!("[-] Unable to decrypt data: {:?}", why),
            Ok(result) => match result {
                buffer::BufferResult::BufferUnderflow => {},
                buffer::BufferResult::BufferOverflow => unreachable!(),
            }
        }
    }

    // Write data from blob back into our file buffer.
    println!("[*] Putting decrypted data where it belongs ...");
    let mut read_offset = 0u32;
    for cur_chunk in &chunk_table {
        let chunk_size = cur_chunk.size as u32;
        let mut dst = get_slice_rva::<u8>(&mut data, sec_table_offs, num_secs, 
            cur_chunk.offset as Rva, chunk_size);
        let src = &decrypted_blob[read_offset as usize..(read_offset + chunk_size) as usize];

        for (cur_src_byte, cur_dst_byte) in src.iter().zip(dst.iter_mut()) {
            *cur_dst_byte = *cur_src_byte;
        }

        read_offset += chunk_size;
    }

    // Blizz moved the IAT to the .reloc section, which isn't loaded by IDA
    // when loading a file without the "manual load" option, which results in
    // unresolved API calls. Rename it to make IDA map it into the IDB by default.
    println!("[*] Fixing section table ...");
    for i in 0..num_secs {
        let cur_sec = get_data::<pe::ImageSectionHeader>(
            &mut data, 
            sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() as u32 * i
        );

        unsafe {
            if (*cur_sec).name.iter().zip(".reloc".as_bytes().iter()).all(|(a, b)| a == b) {
                for (src, dst) in ".reloc_".as_bytes().iter().zip((*cur_sec).name.iter_mut()) {
                    *dst = *src;
                }
            }
        }
    }

    // Write output file.
    println!("[*] Writing output file ...");
    let mut out_f = match File::create(&Path::new(&out_path)) {
        Err(why) => panic!("[-] Couldn't open output file: {}", Error::description(&why)),
        Ok(file) => file,
    };
    
    match out_f.write_all(&data) {
        Err(why) => panic!("[-] Couldn't write to output file: {}", Error::description(&why)),
        Ok(..) => println!("[+] Wrote {:?} bytes ({}).", data.len(), &out_path),
    }
}

#[repr(C, packed)]
#[derive(Clone)]
struct ChunkEntry {
    pub offset: u32,
    pub size: u32,
}

/// Obtains a ptr to a struct inside the input file by it's file offset.
fn get_data<T>(data: &mut Vec<u8>, file_offset: u32) -> *mut T {
    if mem::size_of::<T>() > data.len() - file_offset as usize {
        panic!("[-] Invalid input file: file address exceeds file boundaries.");
    }
    unsafe { mem::transmute(data.as_ptr() as usize + file_offset as usize) }
}

/// Obtains a ptr to a struct inside the input file by it's RVA.
fn get_data_rva<T>(data: &mut Vec<u8>, sec_table_offs: u32, 
    num_secs: u32, rva: Rva) -> *mut T {

    match rva_to_fo(data, sec_table_offs, num_secs, rva) {
        Some(rva) => get_data::<T>(data, rva),
        None => panic!("[-] Invalid input file: Pointer to an invalid RVA encountered.")
    }
}

/// Obtains a mutable slice from the input file by it's RVA.
fn get_slice_rva<'a, T>(data: &'a mut Vec<u8>, sec_table_offs: u32, 
    num_secs: u32, rva: Rva, len: u32) -> &'a mut [T] {

    let file_offset = match rva_to_fo(data, sec_table_offs, num_secs, rva) {
        Some(fo) => fo,
        None => panic!("[-] Invalid input file: Pointer to an invalid RVA encountered.")
    };

    if mem::size_of::<T>() * len as usize > data.len() - file_offset as usize {
        panic!("[-] Invalid input file: file address exceeds file boundaries.");
    }

    unsafe { 
        slice::from_raw_parts_mut(mem::transmute(
            data.as_ptr() as usize + file_offset as usize), len as usize) 
    }
}

/// Translates an RVA to a file offset.
fn rva_to_fo(data: &mut Vec<u8>, sec_table_offs: u32, 
    num_secs: u32, rva: Rva) -> Option<u32> {
    
    for i in 0..num_secs {
        let cur_sec = get_data::<pe::ImageSectionHeader>(
            data, 
            sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() as u32 * i
        );

        unsafe {
            let sec_va = (*cur_sec).virtual_address;
            if rva >= sec_va && rva <= sec_va + (*cur_sec).virtual_size {
                return Some((rva - sec_va + (*cur_sec).pointer_to_raw_data) as u32);
            }
        }
    }
    None
}

/// Translates an FO to an RVA.
fn fo_to_rva(data: &mut Vec<u8>, sec_table_offs: u32, 
    num_secs: u32, fo: u32) -> Option<u32> {
    
    for i in 0..num_secs {
        let cur_sec = get_data::<pe::ImageSectionHeader>(
            data, 
            sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() as u32 * i
        );

        unsafe {
            let sec_fo = (*cur_sec).pointer_to_raw_data as u32;
            if fo >= sec_fo && fo <= sec_fo + (*cur_sec).size_of_raw_data {
                return Some((fo - sec_fo + (*cur_sec).virtual_address));
            }
        }
    }
    None
}

/// Reads a compressed u32 from the input file.
fn read_compressed_u32(data: &mut Vec<u8>, file_offset: u32) 
        -> Option<(u32 /*val*/, u32 /*size*/)> {

    let mut out_int = 0u32;
    let mut shift_offs = 0u32;
    for i in 0..5 {
        let cur_byte = unsafe { *get_data::<u8>(data, file_offset + i) };
        out_int += ((cur_byte as u32) & 0x7F) << shift_offs;
        shift_offs += 7;
        if cur_byte & 0x80 == 0 {
            return Some((out_int, i + 1));
        }
    }
    None
}

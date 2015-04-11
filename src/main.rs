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

/// Entry-point.
fn main() {
    println!("HotS-unpack unpacker by athre0z (c) 2015 zyantific.com\n");

    // Parse arguments.
    let args: Vec<_> = env::args().collect();
    if args.len() != 2 {
        println!("[*] Usage: {} <input binary>", args[0]);
        return;
    }

    // Read file.
    let mut f = match File::open(&Path::new(&args[1])) {
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
    let nt_header_offs = unsafe { (*mz).lfanew } as usize;
    let nt = get_data::<pe::ImageNtHeaders32>(&mut data, nt_header_offs);
    if unsafe { (*nt).signature } != pe::PE_MAGIC {
        panic!("[-] Invalid input file: invalid NT header");
    }

    // Obtain useful information.
    let sec_table_offs = nt_header_offs + mem::size_of::<pe::ImageNtHeaders32>();
    let num_secs = unsafe { (*nt).file_header.number_of_sections } as usize;
    let data_offs = sec_table_offs 
        + mem::size_of::<pe::ImageSectionHeader>() * num_secs;
    let image_base = unsafe { (*nt).opt_header.image_base } as usize;

    // Scan for chunk table.
    println!("[*] Heuristically locating chunk table ...");
    let mut chunk_table_offs = 0;
    let mut chunk_table_len = 0;

    'scan: for i in data_offs..data.len() {
        let mut offs = 0usize;
        let mut last_addr = 0u32;

        // Check if candidate looks like a chunk table.
        while i + offs + mem::size_of::<ChunkEntry>() <= data.len() { 
            unsafe {
                let cur = get_data::<ChunkEntry>(&mut data, i + offs);

                // The chunk table's end is indicated with an 0xFFFFFFFF.
                if offs >= 1000 * mem::size_of::<ChunkEntry>() && (*cur).offset == 0xFFFFFFFF {
                    chunk_table_offs = i;
                    chunk_table_len = (offs / mem::size_of::<ChunkEntry>()) - 1;
                    break 'scan;
                }

                // The chunk table entries are stored ascending.
                if (*cur).offset <= last_addr {
                    break;
                }
 
                last_addr = (*cur).offset;
                offs += mem::size_of::<ChunkEntry>();
            }
        }
    }

    if chunk_table_offs == 0 || chunk_table_len == 0 {
        panic!("[-] Unable to locate chunk table.");
    }

    println!("[+] Found chunk table @ FO 0x{:x} ({} entries).", 
        chunk_table_offs, chunk_table_len);

    // Scan for AES key.
    println!("[*] Locating AES key ...");

    // 0xFF -> wildcard
    let pattern = [
        0x68, 0x80, 0x00, 0x00, 0x00, // push 80h
        0x68, 0xFF, 0xFF, 0xFF, 0xFF, // push offset g_aesInputKey
        0x68, 0xFF, 0xFF, 0xFF, 0xFF, // push offset g_aesKey
        0xE8, 0xFF, 0xFF, 0xFF, 0xFF, // call AesSetDecryptKey
        0xE9,                         // jmp  XXX
    ];

    let mut match_ = None;
    for offs in sec_table_offs..(data.len() - pattern.len()) {
        let mut exhausted = true;
        for (i, cur_pat_byte) in pattern.iter().enumerate() {
            if *cur_pat_byte == 0xFF { continue; }
            if data[offs + i] != *cur_pat_byte { 
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
        Some(x) => unsafe { *get_data::<u32>(&mut data, x + 6) as usize - image_base },
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
    for i in 0..chunk_table_len {
        let chunk_info = get_data::<ChunkEntry>(
            &mut data, chunk_table_offs + mem::size_of::<ChunkEntry>() * i);
        unsafe {
            encrypted_blob.extend(get_slice_rva::<u8>(
                &mut data, sec_table_offs, num_secs, (*chunk_info).offset as usize, 
                (*chunk_info).size as usize).to_vec());
        }
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
    let mut read_offset = 0usize;
    for i in 0..chunk_table_len {
        let chunk_info = get_data::<ChunkEntry>(
            &mut data, chunk_table_offs + mem::size_of::<ChunkEntry>() * i);
        unsafe {
            let chunk_size = (*chunk_info).size as usize;
            let mut dst = get_slice_rva::<u8>(&mut data, sec_table_offs, num_secs, 
                (*chunk_info).offset as usize, chunk_size);
            let src = &decrypted_blob[read_offset..read_offset + chunk_size];

            for (cur_src_byte, cur_dst_byte) in src.iter().zip(dst.iter_mut()) {
                *cur_dst_byte = *cur_src_byte;
            }

            read_offset += chunk_size;
        }
    }

    // Blizz moved the IAT to the .reloc section, which isn't loaded by IDA
    // when loading a file without the "manual load" option, which results in
    // unresolved API calls. Rename it to make IDA map it into the IDB by default.
    println!("[*] Fixing section table ...");
    for i in 0..num_secs {
        let cur_sec = get_data::<pe::ImageSectionHeader>(
            &mut data, sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() * i);

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
    let mut out_f = match File::create(&Path::new("out.exe")) {
        Err(why) => panic!("[-] Couldn't open output file: {}", Error::description(&why)),
        Ok(file) => file,
    };
    
    match out_f.write_all(&data) {
        Err(why) => panic!("[-] Couldn't write to output file: {}", Error::description(&why)),
        Ok(..) => println!("[+] Wrote {:?} bytes (out.exe).", data.len()),
    }
}

#[repr(C)]
#[packed]
struct ChunkEntry {
    pub offset: u32,
    pub size: u32,
}

/// Obtains a ptr to a struct inside the input file by it's file offset.
fn get_data<T>(data: &mut Vec<u8>, file_offset: usize) -> *mut T {
    if mem::size_of::<T>() > data.len() - file_offset {
        panic!("[-] Invalid input file: file address exceeds file boundaries.");
    }
    unsafe { mem::transmute(data.as_ptr() as usize + file_offset) }
}

/// Obtains a ptr to a struct inside the input file by it's RVA.
fn get_data_rva<T>(data: &mut Vec<u8>, sec_table_offs: usize, 
    num_secs: usize, rva: usize) -> *mut T {

    match rva_to_fo(data, sec_table_offs, num_secs, rva) {
        Some(rva) => get_data::<T>(data, rva),
        None => panic!("[-] Invalid input file: Pointer to an invalid RVA encountered.")
    }
}

/// Obtains a mutable slice from the input file by it's RVA.
fn get_slice_rva<'a, T>(data: &'a mut Vec<u8>, sec_table_offs: usize, 
    num_secs: usize, rva: usize, len: usize) -> &'a mut [T] {

    let file_offset = match rva_to_fo(data, sec_table_offs, num_secs, rva) {
        Some(fo) => fo,
        None => panic!("[-] Invalid input file: Pointer to an invalid RVA encountered.")
    };

    if mem::size_of::<T>() * len > data.len() - file_offset {
        panic!("[-] Invalid input file: file address exceeds file boundaries.");
    }

    unsafe { slice::from_raw_parts_mut(mem::transmute(
        data.as_ptr() as usize + file_offset), len) }
}

/// Translates an RVA to a file offset.
fn rva_to_fo(data: &mut Vec<u8>, sec_table_offs: usize, 
    num_secs: usize, rva: usize) -> Option<usize> {
    
    for i in 0..num_secs {
        let cur_sec = get_data::<pe::ImageSectionHeader>(
            data, sec_table_offs + mem::size_of::<pe::ImageSectionHeader>() * i);

        unsafe {
            let sec_va = (*cur_sec).virtual_address as usize;
            if rva >= sec_va && rva <= sec_va + (*cur_sec).virtual_size as usize {
                return Some(rva - sec_va + (*cur_sec).pointer_to_raw_data as usize);
            }
        }
    }
    
    None
}
use std::env;
use std::fs;
use std::process::Command;
use std::collections::HashMap;

// Hardcoded secret
const API_KEY: &str = "sk-proj-abcdefghijklmnopqrstuvwxyz1234567890ABCDEFGHIJKLMNOP";
const AWS_SECRET: &str = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
const DB_PASSWORD: &str = "hunter2";

// Panic on None — unwrap without check
fn get_first(v: &Vec<String>) -> String {
    v.first().unwrap().clone()
}

// Panic on parse error
fn parse_port(s: &str) -> u16 {
    s.parse::<u16>().unwrap()
}

// Command injection — user input interpolated into shell command
fn run_user_command(user_input: &str) {
    Command::new("sh")
        .arg("-c")
        .arg(format!("ls {}", user_input))
        .output()
        .unwrap();
}

// Path traversal — no sanitisation
fn read_user_file(filename: &str) -> String {
    let path = format!("/app/data/{}", filename);
    fs::read_to_string(path).unwrap()
}

// Integer overflow — no checked arithmetic
fn multiply(a: u8, b: u8) -> u8 {
    a * b
}

// String literal in env::var (DeepSource RS-W1015)
fn get_home() -> String {
    env::var("HOME").unwrap_or_default()
}

fn get_secret() -> String {
    env::var("SECRET_KEY").unwrap_or("default_secret".to_string())
}

// Hardcoded /tmp path (DeepSource RS-S1003)
fn write_temp(data: &str) {
    fs::write("/tmp/output.txt", data).unwrap();
    fs::write("/tmp/cache.bin", data.as_bytes()).unwrap();
}

// Infinite loop with no break condition
fn spin_wait(flag: &mut bool) {
    loop {
        if *flag {
            *flag = false;
        }
        // missing break — will loop forever if flag never set externally
    }
}

// Use-after-free pattern via raw pointer
unsafe fn raw_ptr_misuse() {
    let x = Box::new(42i32);
    let ptr = Box::into_raw(x);
    drop(Box::from_raw(ptr));
    // use after free
    println!("{}", *ptr);
}

// Regex compiled inside loop (performance)
fn find_matches(inputs: &[&str]) -> Vec<bool> {
    inputs.iter().map(|s| {
        let re = regex::Regex::new(r"^\d+$").unwrap();
        re.is_match(s)
    }).collect()
}

// Unnecessary clone
fn process(items: Vec<String>) -> usize {
    items.clone().len()
}

fn main() {
    println!("API_KEY={}", API_KEY);
}

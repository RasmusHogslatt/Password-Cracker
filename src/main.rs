use crypto::digest::Digest;
use crypto::md5::Md5;
use std::io::{self, Write};
use std::sync::{
    atomic::{AtomicBool, AtomicUsize, Ordering},
    Arc, Mutex,
};
use std::thread;
use std::time::Instant;

struct PasswordGenerator {
    charset: Vec<char>,
    current_password: Vec<usize>,
    length: usize,
    done: bool,    // Indicate if all passwords of length have been generated
    offset: usize, // Starting point in password space. Makes sure each thread doesn't redo previous work
    stride: usize, // Steps to take in password space. Usually 1 unless you want to skip passwords
}

impl PasswordGenerator {
    fn new(charset: &[char], length: usize) -> Self {
        Self {
            charset: charset.to_vec(),
            current_password: vec![0; length],
            length,
            done: false,
            offset: 0,
            stride: 1,
        }
    }

    fn with_offset_and_stride(
        charset: &[char],
        length: usize,
        offset: usize,
        stride: usize,
    ) -> Self {
        let mut generator = Self::new(charset, length);
        generator.stride = stride;
        generator.offset = offset;
        generator.current_password[0] = offset;
        generator
    }

    fn increment(&mut self) {
        for _ in 0..self.stride {
            let mut i = self.length - 1;
            loop {
                self.current_password[i] += 1;
                if self.current_password[i] < self.charset.len() {
                    break;
                }

                if i == 0 {
                    self.done = true;
                    break;
                }

                self.current_password[i] = 0;
                i -= 1;
            }
        }
    }
}

// Using iterator for password generation makes sure only the memory of current password needs to be stored, 
// as opposed to filling a list with all possible permutations.
impl Iterator for PasswordGenerator {
    type Item = String;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        let password: String = self
            .current_password
            .iter()
            .map(|&index| self.charset[index])
            .collect();
        self.increment();
        Some(password)
    }
}

// Hash password using prebuilt MD5 algorithm
fn hash(password: &str) -> String {
    let mut hasher = Md5::new();
    hasher.input_str(password);
    hasher.result_str()
}

// Ask user to enter a password and returns its MD5 hash
fn get_target_from_user() -> String {
    print!("Please enter a password to crack: ");
    io::stdout().flush().unwrap();

    let mut password = String::new();
    io::stdin().read_line(&mut password).unwrap();

    password = password.trim().to_string(); // Trimming newline

    let password_hash = hash(&password);
    println!(
        "Solving for password {} with hash {}",
        password, password_hash
    );
    password_hash
}

fn main() {
    let target = get_target_from_user();
    let charset: Vec<char> = (32..127).map(|x| x as u8 as char).collect(); // All ASCII characters from space to ~

    let target = Arc::new(target.to_string());
    let charset = Arc::new(charset);

    let num_threads = 4;

    for password_length in 1.. {
        let password_found = Arc::new(Mutex::new(None));
        let found_flag = Arc::new(AtomicBool::new(false));
        let solving_thread = Arc::new(AtomicUsize::new(0));
        let mut handles = vec![];

        let start = Instant::now();

        for i in 0..num_threads {
            let target = Arc::clone(&target);
            let charset = Arc::clone(&charset);
            let password_found = Arc::clone(&password_found);
            let found_flag = Arc::clone(&found_flag);
            let solving_thread = Arc::clone(&solving_thread);

            let handle = thread::spawn(move || {
                let mut generator = PasswordGenerator::with_offset_and_stride(
                    &charset,
                    password_length,
                    i,
                    num_threads,
                );
                while let Some(password) = generator.next() {
                    if found_flag.load(Ordering::Relaxed) {
                        break;
                    }
                    if hash(&password) == *target {
                        let mut password_found = password_found.lock().unwrap();
                        *password_found = Some(password);
                        solving_thread.store(i, Ordering::Relaxed);
                        found_flag.store(true, Ordering::Relaxed);
                        break;
                    }
                }
            });

            handles.push(handle);
        }

        for handle in handles {
            handle.join().unwrap();
        }

        let duration = start.elapsed();

        if found_flag.load(Ordering::Relaxed) {
            let password_found = password_found.lock().unwrap();
            match &*password_found {
                Some(password) => {
                    println!(
                        "Found password: {} in {:.2?} by thread {}",
                        password,
                        duration,
                        solving_thread.load(Ordering::Relaxed)
                    );
                    return;
                }
                None => (),
            }
        } else {
            println!(
                "No password found of length {} in {:.2?}",
                password_length, duration
            );
        }
    }
}

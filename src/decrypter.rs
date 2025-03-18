pub struct Decrypter {
    key: Option<String>,
    key_array: Vec<u8>,
    header_length: usize,
}

impl Decrypter {
    /// Creates a new Decrypter instance.
    ///
    /// # Arguments
    ///
    /// - `key` - Optional encryption key, that can be fetched from `System.json`'s `encryptionKey` field.
    ///           Leave it `None` to auto-determine the key from input files. You can set it after
    ///           constructing `Decrypter` using `set_key_from_image()` or `set_key_string()`.
    pub fn new(key: Option<String>) -> Self {
        let mut decrypter: Decrypter = Decrypter {
            key,
            key_array: Vec::new(),
            header_length: 16,
        };

        if decrypter.key.is_some() {
            decrypter.key_array = decrypter.split_encryption_code();
        }

        decrypter
    }

    fn split_encryption_code(&self) -> Vec<u8> {
        match &self.key {
            None => Vec::new(),
            Some(key) => {
                let mut code_arr: Vec<u8> = Vec::new();
                let chars: Vec<char> = key.chars().collect();

                for i in (0..chars.len()).step_by(2) {
                    if i + 1 < chars.len() {
                        let hex_str: String = format!("{}{}", chars[i], chars[i + 1]);
                        if let Ok(value) = u8::from_str_radix(&hex_str, 16) {
                            code_arr.push(value);
                        }
                    }
                }

                code_arr
            }
        }
    }

    fn process_buffer(&self, buffer: &mut [u8]) {
        let limit: usize = self.header_length.min(self.key_array.len());

        for (i, item) in buffer.iter_mut().enumerate().take(limit) {
            *item ^= self.key_array[i];
        }
    }

    /// Returns the decrypter's key.
    ///
    /// Falls back to empty string if key is not set.
    pub fn key(&self) -> String {
        if let Some(ref key) = self.key {
            key.to_owned()
        } else {
            String::new()
        }
    }

    /// Sets the key of decrypter to provided string.
    ///
    /// # Arguments
    ///
    /// - `key` - The encryption key string.
    pub fn set_key_string(&mut self, key: String) {
        self.key = Some(key);
        self.key_array = self.split_encryption_code();
    }

    /// Sets the key of decrypter from encrypted `file_content` image data.
    ///
    /// # Arguments
    ///
    /// - `file_content` - The data of RPG Maker file
    pub fn set_key_from_image(&mut self, file_content: &[u8]) {
        let header: &[u8] = &file_content[self.header_length..self.header_length * 2];
        const PNG_HEADER: [u8; 16] = [
            0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a, 0x00, 0x00, 0x00, 0x0d, 0x49, 0x48,
            0x44, 0x52,
        ];

        let mut key: String = String::new();
        for i in 0..self.header_length {
            key.push_str(&format!("{:02x}", PNG_HEADER[i] ^ header[i]));
        }

        self.key = Some(key);
        self.key_array = self.split_encryption_code();
    }

    /// Decrypts RPG Maker file content.
    ///
    /// # Arguments
    ///
    /// - `file_content` - The data of RPG Maker file.
    ///
    /// # Returns
    ///
    /// - Vector containing decrypted data.
    pub fn decrypt(&mut self, file_content: &[u8]) -> Vec<u8> {
        if self.key.is_none() {
            self.set_key_from_image(file_content);
        }

        let mut result: Vec<u8> = file_content[self.header_length..].to_vec();
        self.process_buffer(&mut result);
        result
    }

    /// Encrypts file content.
    ///
    /// This function needs decrypter to have a key, which you can fetch from `System.json` file
    /// or by calling `set_key_from_image()` with the data from encrypted file.
    ///
    /// # Arguments
    ///
    /// - `file_content` - The data of `.png`, `.ogg` or `.m4a` file.
    ///
    /// # Returns
    ///
    /// - Vector containing encrypted data.
    ///
    /// # Panics
    ///
    /// - Panics if encryption key is not set.
    pub fn encrypt(&self, file_content: &[u8]) -> Vec<u8> {
        if self.key.is_none() {
            panic!("Encryption key is not set.");
        }

        let mut data: Vec<u8> = file_content.to_vec();
        self.process_buffer(&mut data);

        const HEADER: [u8; 16] = [
            0x52, 0x50, 0x47, 0x4d, 0x56, 0x00, 0x00, 0x00, 0x00, 0x03, 0x01, 0x00, 0x00, 0x00,
            0x00, 0x00,
        ];

        let mut output_data = Vec::from(HEADER);
        output_data.extend(data);
        output_data
    }
}

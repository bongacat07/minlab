use std::fmt;
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct MacAddr([u8; 6]);

impl MacAddr {
    pub const BROADCAST: Self = Self([0xff; 6]);

    pub fn new(bytes: [u8; 6]) -> Self {
        Self(bytes)
    }

    pub fn octets(self) -> [u8; 6] {
        self.0
    }

    pub fn parse(s: &str) -> Result<Self, MacParseError> {
        let parts: Vec<&str> = s.split([':', '-']).collect();

        if parts.len() != 6 {
            return Err(MacParseError(s.to_string()));
        }

        let mut mac = [0u8; 6];

        for (i, part) in parts.iter().enumerate() {
            if part.len() != 2 {
                return Err(MacParseError(s.to_string()));
            }

            mac[i] = u8::from_str_radix(part, 16).map_err(|_| MacParseError(s.to_string()))?;
        }

        Ok(Self(mac))
    }
}

impl fmt::Display for MacAddr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            self.0[0], self.0[1], self.0[2], self.0[3], self.0[4], self.0[5],
        )
    }
}

#[derive(Debug)]
pub struct MacParseError(String);

impl fmt::Display for MacParseError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid MAC address: {}", self.0)
    }
}

impl std::error::Error for MacParseError {}

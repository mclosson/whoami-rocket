use crypto::{buffer, aes, blockmodes};
use crypto::buffer::{ReadBuffer, WriteBuffer};
use crypto::pbkdf2::pbkdf2;
use crypto::hmac::Hmac;
use crypto::sha1::Sha1;
use data_encoding::base64;
use std::iter;
use std::str;

pub fn decrypt(session_cookie: &str, secret_key_base: &str) -> String {
    let salt = "encrypted cookie"; // String literal used in Rails 4.x, 5.x as the salt
    let cookie = base64::decode(session_cookie.split("--").nth(0).unwrap().as_bytes()).unwrap();
    let cookie = String::from_utf8(cookie).unwrap();

    let v: Vec<_> = cookie.split("--").map(|s| s.as_bytes()).collect();
    let encrypted_data = base64::decode(v[0]).unwrap();
    let iv = base64::decode(v[1]).unwrap();

    let mut mac = Hmac::new(Sha1::new(), secret_key_base.as_bytes());
    let mut key: Vec<u8> = iter::repeat(0).take(64).collect();
    pbkdf2(&mut mac, salt.as_bytes(), 1000, &mut key);

    let mut decryptor = aes::cbc_decryptor(
        aes::KeySize::KeySize256,
        &key[..],
        &iv[..],
        blockmodes::PkcsPadding);

    let mut final_result = Vec::<u8>::new();
    let mut read_buffer = buffer::RefReadBuffer::new(&encrypted_data[..]);
    let mut buffer = [0; 4096];

    {
        let mut write_buffer = buffer::RefWriteBuffer::new(&mut buffer);
        decryptor.decrypt(&mut read_buffer, &mut write_buffer, true).unwrap();
        final_result.extend(write_buffer.take_read_buffer().take_remaining());
    }

    let mut plain_text = buffer.to_vec();
    let terminator = plain_text.iter().position(|&n| n == 0).unwrap();
    plain_text.truncate(terminator);
    String::from_utf8(plain_text).unwrap()
}

#[cfg(test)]
mod tests {

    #[test]
    fn it_works() {
        let session_cookie = "KzlOUi9lK01vL0Z1Sk1vUUw2QksxM0JpT2xTdm1xMkxoaExMWFZUQWJBUUl0UEgvN1NYUGNtdVVadGZ1REM3YkNCQW56WDhEUDN5WG1KWjdRSjE4d3hoTEJvcHlLSzgwQTdWT1lFMmF3WkpvY0RJV1kveHF1eURSTlgrUkE3N3Q4S2JlY1gwcXdycTArdno3empleS93bC9XODRWMUJCZm1MOUh5dlZVMjJNSjZKc3cwNGFLaXRsVHlCaUpwUW4rN3pZYWlVQ2l3UmVqR2g4aVZLcFl6NUczMkluV0t1cE9CODJKL2RSYVhOZnJsZGhOanEyQ1JGVjNPVlkvQW5MQ3BKTjFjbGNHLzdoaDdPaFRySnFEa1E9PS0teVlEL0lZQ3Y1a1dnZnBnREd1S1lrdz09--ef5736349befb8afcab96954144e9188521326f1";
        let secret_key_base = "9b068b0ffb899625a4e11fd75180907439961e3cba7da709d060826de1ab6ae674dde93d2cf62106e5d22a667f9173ace8331f22b1539503ef8d79fc1fe3c5ef";
        let expected = "{\"session_id\":\"278407bb306a0f61b7490afae89da92f\",\"_csrf_token\":\"XantipYbR5itu1Gw5mLvo/Q2QVL3pXlLBbI6vnI33I0=\",\"user_id\":3,\"flash\":{\"discard\":[\"notice\"],\"flashes\":{\"notice\":\"Sign in successful\"}}}";

        let plain_text = ::decrypt(&session_cookie, &secret_key_base);
        assert_eq!(expected, plain_text);
    }

}
